package matching

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"go.temporal.io/api/serviceerror"
	clockspb "go.temporal.io/server/api/clock/v1"
	"go.temporal.io/server/api/matchingservice/v1"
	persistencespb "go.temporal.io/server/api/persistence/v1"
	"go.temporal.io/server/common/backoff"
	"go.temporal.io/server/common/clock"
	hlc "go.temporal.io/server/common/clock/hybrid_logical_clock"
	"go.temporal.io/server/common/dynamicconfig"
	"go.temporal.io/server/common/goro"
	"go.temporal.io/server/common/headers"
	p "go.temporal.io/server/common/persistence"
	"go.temporal.io/server/common/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// loadEndpointsPageSize is the page size to use when initially loading endpoints from persistence
	loadEndpointsPageSize = 100

	// maxDeletedEndpointTombstones caps the in-memory tombstone map to prevent unbounded growth.
	// Nexus endpoints are cluster-global resources; the practical number of endpoints is small,
	// so this cap is a safety guard only.
	maxDeletedEndpointTombstones = 10000
)

type (
	internalUpdateNexusEndpointRequest struct {
		endpointID string
		version    int64
		spec       *persistencespb.NexusEndpointSpec
		clusterID  int64
		timeSource clock.TimeSource
	}

	internalCreateNexusEndpointRequest struct {
		spec       *persistencespb.NexusEndpointSpec
		clusterID  int64
		timeSource clock.TimeSource
	}

	// nexusEndpointClient manages cache and persistence access for Nexus endpoints.
	// nexusEndpointClient contains a RWLock to enforce serial updates to prevent
	// nexus_endpoints table version conflicts.
	//
	// nexusEndpointClient should only be used within matching service because it assumes
	// that it is running on the matching node that owns the nexus_endpoints table.
	// There is no explicit listener for membership changes because table ownership changes
	// will be detected by version conflicts and eventually settle through retries.
	nexusEndpointClient struct {
		hasLoadedEndpoints atomic.Bool

		sync.RWMutex        // protects tableVersion, endpoints, endpointsByID, endpointsByName, and tableVersionChanged
		tableVersion        int64
		endpointEntries     []*persistencespb.NexusEndpointEntry // sorted by ID to support pagination during ListNexusEndpoints
		endpointsByID       map[string]*persistencespb.NexusEndpointEntry
		endpointsByName     map[string]*persistencespb.NexusEndpointEntry
		tableVersionChanged chan struct{}

		// deletedClocks tracks the HLC clock of endpoints at the time they were deleted via replication.
		// This tombstone map prevents a stale UPDATE replication event that arrives after a DELETE
		// from resurrecting the endpoint via applyUpsertLocked.
		// Capped at maxDeletedEndpointTombstones; cleared entirely on overflow (safety guard only).
		deletedClocks map[string]*clockspb.HybridLogicalClock

		refreshLock              sync.Mutex // protects refreshHandle which is updated whenever node gains/loses ownership
		refreshHandle            *goro.Handle
		endpointsRefreshInterval dynamicconfig.DurationPropertyFn

		persistence p.NexusEndpointManager
	}
)

func newEndpointClient(
	endpointsRefreshInterval dynamicconfig.DurationPropertyFn,
	persistence p.NexusEndpointManager,
) *nexusEndpointClient {
	return &nexusEndpointClient{
		endpointsRefreshInterval: endpointsRefreshInterval,
		persistence:              persistence,
		tableVersionChanged:      make(chan struct{}),
		deletedClocks:            make(map[string]*clockspb.HybridLogicalClock),
	}
}

func (m *nexusEndpointClient) CreateNexusEndpoint(
	ctx context.Context,
	request *internalCreateNexusEndpointRequest,
) (*matchingservice.CreateNexusEndpointResponse, error) {
	if !m.hasLoadedEndpoints.Load() {
		// Endpoints must be loaded into memory before Create so we know whether this endpoint name is in use and that we
		// have the last known table version to update persistence.
		if err := m.loadEndpoints(ctx); err != nil {
			return nil, fmt.Errorf("error loading nexus endpoints cache: %w", err)
		}
	}

	m.Lock()
	defer m.Unlock()

	if _, exists := m.endpointsByName[request.spec.GetName()]; exists {
		return nil, serviceerror.NewAlreadyExistsf("error creating Nexus endpoint. Endpoint with name %v already registered", request.spec.GetName())
	}

	entry := &persistencespb.NexusEndpointEntry{
		Version: 0,
		Id:      uuid.NewString(),
		Endpoint: &persistencespb.NexusEndpoint{
			Clock:       hlc.Zero(request.clusterID),
			Spec:        request.spec,
			CreatedTime: timestamppb.New(request.timeSource.Now().UTC()),
		},
	}

	resp, err := m.persistence.CreateOrUpdateNexusEndpoint(ctx, &p.CreateOrUpdateNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		Entry:                 entry,
	})
	if err != nil {
		return nil, err
	}

	entry.Version = resp.Version
	m.tableVersion++
	m.endpointsByID[entry.Id] = entry
	m.endpointsByName[entry.Endpoint.Spec.Name] = entry
	m.insertEndpointLocked(entry)
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return &matchingservice.CreateNexusEndpointResponse{
		Entry: entry,
	}, nil
}

func (m *nexusEndpointClient) UpdateNexusEndpoint(
	ctx context.Context,
	request *internalUpdateNexusEndpointRequest,
) (*matchingservice.UpdateNexusEndpointResponse, error) {
	if !m.hasLoadedEndpoints.Load() {
		// Endpoints must be loaded into memory before Update, since we need to check the previous entry and we need the
		// last known table version to update persistence.
		if err := m.loadEndpoints(ctx); err != nil {
			return nil, fmt.Errorf("error loading nexus endpoint cache: %w", err)
		}
	}

	m.Lock()
	defer m.Unlock()

	previous, exists := m.endpointsByID[request.endpointID]
	if !exists {
		return nil, serviceerror.NewNotFoundf("error updating Nexus endpoint. endpoint ID %v not found", request.endpointID)
	}

	if request.version != previous.Version {
		return nil, serviceerror.NewFailedPreconditionf("nexus endpoint version mismatch. received: %v expected %v", request.version, previous.Version)
	}

	entry := &persistencespb.NexusEndpointEntry{
		Version: previous.Version,
		Id:      previous.Id,
		Endpoint: &persistencespb.NexusEndpoint{
			Clock: hlc.Next(previous.Endpoint.Clock, request.timeSource),
			Spec:  request.spec,
		},
	}

	resp, err := m.persistence.CreateOrUpdateNexusEndpoint(ctx, &p.CreateOrUpdateNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		Entry:                 entry,
	})
	if err != nil {
		return nil, err
	}

	entry.Version = resp.Version
	m.tableVersion++
	m.endpointsByID[entry.Id] = entry
	m.endpointsByName[entry.Endpoint.Spec.Name] = entry
	m.insertEndpointLocked(entry)
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return &matchingservice.UpdateNexusEndpointResponse{
		Entry: entry,
	}, nil
}

func (m *nexusEndpointClient) insertEndpointLocked(entry *persistencespb.NexusEndpointEntry) {
	idx, found := slices.BinarySearchFunc(m.endpointEntries, entry, func(a *persistencespb.NexusEndpointEntry, b *persistencespb.NexusEndpointEntry) int {
		return bytes.Compare([]byte(a.Id), []byte(b.Id))
	})

	if found {
		m.endpointEntries[idx] = entry
	} else {
		m.endpointEntries = slices.Insert(m.endpointEntries, idx, entry)
	}
}

func (m *nexusEndpointClient) DeleteNexusEndpoint(
	ctx context.Context,
	request *matchingservice.DeleteNexusEndpointRequest,
) (*matchingservice.DeleteNexusEndpointResponse, error) {
	resp, _, err := m.deleteNexusEndpointInternal(ctx, request)
	return resp, err
}

// deleteNexusEndpointInternal deletes the endpoint and returns the response alongside the deleted
// entry. The deleted entry is used by the matching engine to build the DELETE replication task with
// the entry's HLC clock, so that standby clusters can record a tombstone even when the DELETE
// replication event arrives before the CREATE.
func (m *nexusEndpointClient) deleteNexusEndpointInternal(
	ctx context.Context,
	request *matchingservice.DeleteNexusEndpointRequest,
) (*matchingservice.DeleteNexusEndpointResponse, *persistencespb.NexusEndpointEntry, error) {
	if !m.hasLoadedEndpoints.Load() {
		// Endpoints must be loaded into memory before deletion so that the endpoint UUID can be looked up
		if err := m.loadEndpoints(ctx); err != nil {
			return nil, nil, fmt.Errorf("error loading nexus endpoints cache: %w", err)
		}
	}

	m.Lock()
	defer m.Unlock()

	entry, ok := m.endpointsByID[request.Id]
	if !ok {
		return nil, nil, serviceerror.NewNotFoundf("error deleting nexus endpoint with ID: %v", request.Id)
	}

	err := m.persistence.DeleteNexusEndpoint(ctx, &p.DeleteNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		ID:                    entry.Id,
	})
	if err != nil {
		return nil, nil, err
	}

	m.tableVersion++
	delete(m.endpointsByID, request.Id)
	delete(m.endpointsByName, entry.Endpoint.Spec.Name)
	m.endpointEntries = slices.DeleteFunc(m.endpointEntries, func(entry *persistencespb.NexusEndpointEntry) bool {
		return entry.Id == request.Id
	})
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return &matchingservice.DeleteNexusEndpointResponse{}, entry, nil
}

// ApplyCreateReplicationEvent applies a replicated endpoint creation from a remote cluster.
// The endpoint entry retains the original UUID from the source cluster.
// If a local endpoint with the same UUID exists, this is a duplicate and is skipped.
// If a local endpoint with the same name but different UUID exists, HLC clock comparison
// determines which one wins (last-writer-wins).
func (m *nexusEndpointClient) ApplyCreateReplicationEvent(
	ctx context.Context,
	entry *persistencespb.NexusEndpointEntry,
) error {
	if !m.hasLoadedEndpoints.Load() {
		if err := m.loadEndpoints(ctx); err != nil {
			return fmt.Errorf("error loading nexus endpoints cache: %w", err)
		}
	}

	m.Lock()
	defer m.Unlock()

	// Duplicate check: if endpoint with same UUID already exists, skip (idempotent).
	if _, exists := m.endpointsByID[entry.GetId()]; exists {
		return nil
	}

	// Tombstone check: if this endpoint ID was previously deleted via replication, a stale CREATE
	// replay must not resurrect it. Only proceed if the incoming CREATE is strictly newer than
	// the deletion clock (intentional recreation), otherwise discard.
	if tombstoneClock, deleted := m.deletedClocks[entry.GetId()]; deleted {
		if !hlc.Greater(entry.GetEndpoint().GetClock(), tombstoneClock) {
			return nil
		}
		// CREATE is newer than the deletion — intentional recreation.
		// Don't remove tombstone yet; wait until we confirm the CREATE will proceed
		// (name conflict resolution might reject it, and we need the tombstone preserved).
	}

	// Name conflict check: if a local endpoint has the same name but different UUID,
	// use HLC clock comparison to determine the winner.
	proceed, err := m.resolveNameConflictLocked(ctx, entry)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	// CREATE will proceed — now safe to remove the tombstone.
	delete(m.deletedClocks, entry.GetId())

	// Persist the replicated endpoint with Version: 0 (insert) and the source UUID.
	replicatedEntry := &persistencespb.NexusEndpointEntry{
		Version:  0,
		Id:       entry.GetId(),
		Endpoint: entry.GetEndpoint(),
	}

	resp, err := m.persistence.CreateOrUpdateNexusEndpoint(ctx, &p.CreateOrUpdateNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		Entry:                 replicatedEntry,
	})
	if err != nil {
		return fmt.Errorf("error persisting replicated nexus endpoint: %w", err)
	}

	replicatedEntry.Version = resp.Version
	m.tableVersion++
	m.endpointsByID[replicatedEntry.Id] = replicatedEntry
	m.endpointsByName[replicatedEntry.Endpoint.Spec.Name] = replicatedEntry
	m.insertEndpointLocked(replicatedEntry)
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return nil
}

// ApplyUpdateReplicationEvent applies a replicated endpoint update from a remote cluster.
// Looks up the endpoint by UUID. If not found, falls through to create (handles out-of-order delivery).
// Uses HLC clock comparison to detect stale updates.
func (m *nexusEndpointClient) ApplyUpdateReplicationEvent(
	ctx context.Context,
	entry *persistencespb.NexusEndpointEntry,
) error {
	if !m.hasLoadedEndpoints.Load() {
		if err := m.loadEndpoints(ctx); err != nil {
			return fmt.Errorf("error loading nexus endpoints cache: %w", err)
		}
	}

	m.Lock()
	defer m.Unlock()

	existing, exists := m.endpointsByID[entry.GetId()]
	if !exists {
		// Endpoint not found locally. Two possible explanations:
		// (a) Out-of-order delivery: CREATE has not arrived yet — safe to upsert.
		// (b) Stale UPDATE after DELETE: a DELETE was already applied and this UPDATE arrived late.
		//     In this case we must NOT resurrect the deleted endpoint.
		if tombstoneClock, deleted := m.deletedClocks[entry.GetId()]; deleted {
			if !hlc.Greater(entry.GetEndpoint().GetClock(), tombstoneClock) {
				// Update is not newer than the deletion — discard to avoid resurrection.
				return nil
			}
			// Update is newer than the deletion — intentional recreation.
			// Don't remove tombstone yet; applyUpsertLocked may reject due to name conflict.
		}
		err := m.applyUpsertLocked(ctx, entry)
		if err != nil {
			return err
		}
		// Upsert succeeded — now safe to remove the tombstone.
		delete(m.deletedClocks, entry.GetId())
		return nil
	}

	// Stale update check: if the replicated clock is not newer than the local clock, skip.
	if !hlc.Greater(entry.GetEndpoint().GetClock(), existing.GetEndpoint().GetClock()) {
		return nil
	}

	// If the update renames the endpoint, check for name conflicts with other local endpoints.
	if existing.GetEndpoint().GetSpec().GetName() != entry.GetEndpoint().GetSpec().GetName() {
		proceed, err := m.resolveNameConflictLocked(ctx, entry)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}

	// Apply the update using the LOCAL version (not the source version) for optimistic concurrency.
	updatedEntry := &persistencespb.NexusEndpointEntry{
		Version:  existing.Version,
		Id:       existing.Id,
		Endpoint: entry.GetEndpoint(),
	}

	resp, err := m.persistence.CreateOrUpdateNexusEndpoint(ctx, &p.CreateOrUpdateNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		Entry:                 updatedEntry,
	})
	if err != nil {
		return fmt.Errorf("error persisting replicated nexus endpoint update: %w", err)
	}

	updatedEntry.Version = resp.Version
	m.tableVersion++
	m.endpointsByID[updatedEntry.Id] = updatedEntry
	// If the name changed, clean up the old name mapping.
	if existing.GetEndpoint().GetSpec().GetName() != updatedEntry.GetEndpoint().GetSpec().GetName() {
		delete(m.endpointsByName, existing.GetEndpoint().GetSpec().GetName())
	}
	m.endpointsByName[updatedEntry.Endpoint.Spec.Name] = updatedEntry
	m.insertEndpointLocked(updatedEntry)
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return nil
}

// ApplyDeleteReplicationEvent applies a replicated endpoint deletion from a remote cluster.
// Always records a tombstone using the clock from the replication task entry, regardless of
// whether the endpoint exists locally. This handles the DELETE-before-CREATE delivery scenario:
// if a CREATE replication event arrives later with a clock ≤ the tombstone clock, it is discarded.
// The entry in the replication task must carry the deleted endpoint's HLC clock.
func (m *nexusEndpointClient) ApplyDeleteReplicationEvent(
	ctx context.Context,
	entry *persistencespb.NexusEndpointEntry,
) error {
	if entry.GetEndpoint() == nil || entry.GetEndpoint().GetClock() == nil {
		return serviceerror.NewInvalidArgument("nexus endpoint replication DELETE task missing clock")
	}

	if !m.hasLoadedEndpoints.Load() {
		if err := m.loadEndpoints(ctx); err != nil {
			return fmt.Errorf("error loading nexus endpoints cache: %w", err)
		}
	}

	m.Lock()
	defer m.Unlock()

	// Always record a tombstone from the replication task's clock.
	// This is necessary even when the endpoint is not present locally (DELETE arrived before CREATE).
	// Note: nil clock is already rejected by the early return above.
	if len(m.deletedClocks) >= maxDeletedEndpointTombstones {
		// Safety guard: clear the map rather than grow without bound.
		// In practice this limit is never reached; endpoints are cluster-global and few.
		m.deletedClocks = make(map[string]*clockspb.HybridLogicalClock)
	}
	m.deletedClocks[entry.GetId()] = entry.GetEndpoint().GetClock()

	existing, ok := m.endpointsByID[entry.GetId()]
	if !ok {
		// Not present locally — tombstone recorded above; nothing else to do.
		return nil
	}

	// Don't delete if the local endpoint is strictly newer than the DELETE's clock.
	// This handles multi-source replication where the endpoint was updated from
	// a different cluster after this deletion occurred at the source.
	if hlc.Greater(existing.GetEndpoint().GetClock(), entry.GetEndpoint().GetClock()) {
		return nil
	}

	if err := m.persistence.DeleteNexusEndpoint(ctx, &p.DeleteNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		ID:                    existing.GetId(),
	}); err != nil {
		return fmt.Errorf("error deleting replicated nexus endpoint: %w", err)
	}

	m.tableVersion++
	delete(m.endpointsByID, existing.GetId())
	delete(m.endpointsByName, existing.GetEndpoint().GetSpec().GetName())
	m.endpointEntries = slices.DeleteFunc(m.endpointEntries, func(e *persistencespb.NexusEndpointEntry) bool {
		return e.GetId() == existing.GetId()
	})
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return nil
}

// resolveNameConflictLocked checks if a replicated endpoint's name conflicts with a different
// local endpoint. If so, HLC clock comparison determines the winner: if the replicated endpoint
// wins, the conflicting local endpoint is deleted; if the local endpoint wins, returns false
// to signal the caller to skip the replicated entry. Must be called with write lock held.
// Returns (proceed bool, error).
func (m *nexusEndpointClient) resolveNameConflictLocked(
	ctx context.Context,
	entry *persistencespb.NexusEndpointEntry,
) (bool, error) {
	existing, nameConflict := m.endpointsByName[entry.GetEndpoint().GetSpec().GetName()]
	if !nameConflict || existing.GetId() == entry.GetId() {
		// No conflict, or same endpoint (not a conflict).
		return true, nil
	}

	if hlc.Greater(entry.GetEndpoint().GetClock(), existing.GetEndpoint().GetClock()) {
		// Replicated endpoint wins — delete the local one first.
		if err := m.persistence.DeleteNexusEndpoint(ctx, &p.DeleteNexusEndpointRequest{
			LastKnownTableVersion: m.tableVersion,
			ID:                    existing.GetId(),
		}); err != nil {
			return false, fmt.Errorf("error deleting conflicting local endpoint during replication: %w", err)
		}
		m.tableVersion++
		delete(m.endpointsByID, existing.GetId())
		delete(m.endpointsByName, existing.GetEndpoint().GetSpec().GetName())
		m.endpointEntries = slices.DeleteFunc(m.endpointEntries, func(e *persistencespb.NexusEndpointEntry) bool {
			return e.GetId() == existing.GetId()
		})
		// Signal long-poll waiters about the table version change.
		ch := m.tableVersionChanged
		m.tableVersionChanged = make(chan struct{})
		close(ch)
		return true, nil
	}

	// Local endpoint wins — caller should skip the replicated endpoint.
	return false, nil
}

// applyUpsertLocked inserts a replicated endpoint entry. Must be called with write lock held.
func (m *nexusEndpointClient) applyUpsertLocked(
	ctx context.Context,
	entry *persistencespb.NexusEndpointEntry,
) error {
	// Check for name conflicts before inserting.
	proceed, err := m.resolveNameConflictLocked(ctx, entry)
	if err != nil {
		return err
	}
	if !proceed {
		return nil
	}

	replicatedEntry := &persistencespb.NexusEndpointEntry{
		Version:  0, // insert semantics
		Id:       entry.GetId(),
		Endpoint: entry.GetEndpoint(),
	}

	resp, err := m.persistence.CreateOrUpdateNexusEndpoint(ctx, &p.CreateOrUpdateNexusEndpointRequest{
		LastKnownTableVersion: m.tableVersion,
		Entry:                 replicatedEntry,
	})
	if err != nil {
		return fmt.Errorf("error persisting replicated nexus endpoint: %w", err)
	}

	replicatedEntry.Version = resp.Version
	m.tableVersion++
	m.endpointsByID[replicatedEntry.Id] = replicatedEntry
	m.endpointsByName[replicatedEntry.Endpoint.Spec.Name] = replicatedEntry
	m.insertEndpointLocked(replicatedEntry)
	ch := m.tableVersionChanged
	m.tableVersionChanged = make(chan struct{})
	close(ch)

	return nil
}

func (m *nexusEndpointClient) ListNexusEndpoints(
	ctx context.Context,
	request *matchingservice.ListNexusEndpointsRequest,
) (*matchingservice.ListNexusEndpointsResponse, chan struct{}, error) {
	m.RLock()
	if request.LastKnownTableVersion > m.tableVersion {
		// indicates we may have lost table ownership, so need to reload from persistence
		m.hasLoadedEndpoints.Store(false)
	}
	m.RUnlock()

	if !m.hasLoadedEndpoints.Load() {
		if err := m.loadEndpoints(ctx); err != nil {
			return nil, nil, fmt.Errorf("error loading nexus endpoints cache: %w", err)
		}
	}

	m.RLock()
	defer m.RUnlock()

	if request.LastKnownTableVersion != 0 && request.LastKnownTableVersion != m.tableVersion {
		return nil, nil, serviceerror.NewFailedPreconditionf("nexus endpoints table version mismatch. received: %v expected %v", request.LastKnownTableVersion, m.tableVersion)
	}

	startIdx := 0
	if request.NextPageToken != nil {
		nextEndpointID := string(request.NextPageToken)

		startFound := false
		startIdx, startFound = slices.BinarySearchFunc(
			m.endpointEntries,
			&persistencespb.NexusEndpointEntry{Id: nextEndpointID},
			func(a *persistencespb.NexusEndpointEntry, b *persistencespb.NexusEndpointEntry) int {
				return bytes.Compare([]byte(a.Id), []byte(b.Id))
			})

		if !startFound {
			return nil, nil, serviceerror.NewFailedPrecondition("could not find endpoint indicated by nexus list endpoints next page token")
		}
	}

	endIdx := min(startIdx+int(request.PageSize), len(m.endpointEntries))

	var nextPageToken []byte
	if endIdx < len(m.endpointEntries) {
		nextPageToken = []byte(m.endpointEntries[endIdx].Id)
	}

	resp := &matchingservice.ListNexusEndpointsResponse{
		TableVersion:  m.tableVersion,
		NextPageToken: nextPageToken,
		Entries:       slices.Clone(m.endpointEntries[startIdx:endIdx]),
	}

	return resp, m.tableVersionChanged, nil
}

func (m *nexusEndpointClient) loadEndpoints(ctx context.Context) error {
	m.Lock()
	defer m.Unlock()

	if m.hasLoadedEndpoints.Load() {
		// check whether endpoints were loaded while waiting for write lock
		return nil
	}

	// reset cached view since we will be paging from the start
	m.resetCacheStateLocked()

	var pageToken []byte

	for ctx.Err() == nil {
		resp, err := m.persistence.ListNexusEndpoints(ctx, &p.ListNexusEndpointsRequest{
			LastKnownTableVersion: m.tableVersion,
			NextPageToken:         pageToken,
			PageSize:              loadEndpointsPageSize,
		})
		if err != nil {
			if errors.Is(err, p.ErrNexusTableVersionConflict) {
				// indicates table was updated during paging, so reset and start from the beginning
				m.resetCacheStateLocked()
				pageToken = nil
				continue
			}
			return err
		}

		pageToken = resp.NextPageToken
		m.tableVersion = resp.TableVersion
		for _, entry := range resp.Entries {
			m.endpointEntries = append(m.endpointEntries, entry)
			m.endpointsByID[entry.Id] = entry
			m.endpointsByName[entry.Endpoint.Spec.Name] = entry
		}

		if len(pageToken) == 0 {
			break
		}
	}

	m.hasLoadedEndpoints.Store(ctx.Err() == nil)
	return ctx.Err()
}

func (m *nexusEndpointClient) resetCacheStateLocked() {
	m.tableVersion = 0
	m.endpointEntries = []*persistencespb.NexusEndpointEntry{}
	m.endpointsByID = make(map[string]*persistencespb.NexusEndpointEntry)
	m.endpointsByName = make(map[string]*persistencespb.NexusEndpointEntry)
}

// notifyOwnershipChanged starts or stops a background routine which watches the Nexus endpoints table version for
// changes. This is only expected to be called from matchingEngineImpl.notifyNexusEndpointsOwnershipChange()
func (m *nexusEndpointClient) notifyOwnershipChanged(isOwner bool) {
	var oldHandle *goro.Handle

	m.refreshLock.Lock()
	if isOwner && m.refreshHandle == nil {
		// Just acquired ownership. Start refresh loop on table version to catch any updates from previous owner.
		backgroundCtx := headers.SetCallerInfo(
			context.Background(),
			headers.SystemBackgroundCallerInfo,
		)
		m.refreshHandle = goro.NewHandle(backgroundCtx)
		m.refreshHandle.Go(m.refreshTableVersion)
	} else if !isOwner && m.refreshHandle != nil {
		// Just lost ownership. Stop table version refresh loop.
		oldHandle = m.refreshHandle
		m.refreshHandle = nil
	}
	m.refreshLock.Unlock()

	if oldHandle != nil {
		oldHandle.Cancel()
		<-oldHandle.Done()
	}
}

func (m *nexusEndpointClient) refreshTableVersion(ctx context.Context) error {
	for ctx.Err() == nil {
		m.checkTableVersion(ctx)
		util.InterruptibleSleep(ctx, backoff.Jitter(m.endpointsRefreshInterval(), 0.2))
	}
	return ctx.Err()
}

func (m *nexusEndpointClient) checkTableVersion(ctx context.Context) {
	// Acquire lock to make sure we are not in the middle of an update.
	m.Lock()
	defer m.Unlock()

	resp, err := m.persistence.ListNexusEndpoints(ctx, &p.ListNexusEndpointsRequest{
		LastKnownTableVersion: 0,
		PageSize:              0,
	})
	if err != nil || resp.TableVersion != m.tableVersion {
		m.hasLoadedEndpoints.Store(false)
		ch := m.tableVersionChanged
		m.tableVersionChanged = make(chan struct{})
		close(ch)
	}
}
