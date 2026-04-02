package matching

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	clockspb "go.temporal.io/server/api/clock/v1"
	persistencespb "go.temporal.io/server/api/persistence/v1"
	"go.temporal.io/server/common/dynamicconfig"
	p "go.temporal.io/server/common/persistence"
	"go.uber.org/mock/gomock"
)

// newTestEndpointClient creates a nexusEndpointClient backed by a mock persistence manager that
// returns an empty endpoint list on initial load.
func newTestEndpointClient(t *testing.T) (*nexusEndpointClient, *p.MockNexusEndpointManager) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mock := p.NewMockNexusEndpointManager(ctrl)
	mock.EXPECT().
		ListNexusEndpoints(gomock.Any(), gomock.Any()).
		Return(&p.ListNexusEndpointsResponse{TableVersion: 0, Entries: nil}, nil).
		AnyTimes()
	client := newEndpointClient(
		dynamicconfig.GetDurationPropertyFn(0),
		mock,
	)
	return client, mock
}

// newTestEntry constructs a minimal NexusEndpointEntry for test use.
func newTestEntry(id, name string, wallClock int64) *persistencespb.NexusEndpointEntry {
	return &persistencespb.NexusEndpointEntry{
		Id: id,
		Endpoint: &persistencespb.NexusEndpoint{
			Clock: &clockspb.HybridLogicalClock{WallClock: wallClock, Version: 0, ClusterId: 1},
			Spec:  &persistencespb.NexusEndpointSpec{Name: name},
		},
	}
}

// TestApplyDeleteReplicationEvent_BeforeCreate verifies the DELETE-before-CREATE ordering fix:
// a DELETE replication task that arrives before the corresponding CREATE must cause the later
// CREATE to be discarded when its clock is not newer than the DELETE tombstone clock.
func TestApplyDeleteReplicationEvent_BeforeCreate(t *testing.T) {
	ctx := context.Background()
	client, mock := newTestEndpointClient(t)

	const endpointID = "endpoint-abc"
	const endpointName = "my-endpoint"

	// Clock C2 (wall=200) is the deletion clock.
	deleteEntry := newTestEntry(endpointID, endpointName, 200)

	// Apply the DELETE first — endpoint does not exist locally yet.
	err := client.ApplyDeleteReplicationEvent(ctx, deleteEntry)
	require.NoError(t, err)

	// Tombstone should be recorded for the endpoint ID.
	require.Contains(t, client.deletedClocks, endpointID, "tombstone should be recorded even when endpoint was not present locally")

	// Now apply a CREATE with clock C1 (wall=100) — older than the DELETE tombstone.
	createEntry := newTestEntry(endpointID, endpointName, 100)

	// persistence.CreateOrUpdateNexusEndpoint must NOT be called — the CREATE should be discarded.
	mock.EXPECT().CreateOrUpdateNexusEndpoint(gomock.Any(), gomock.Any()).Times(0)

	err = client.ApplyCreateReplicationEvent(ctx, createEntry)
	require.NoError(t, err)

	// Endpoint must not appear in the registry.
	require.NotContains(t, client.endpointsByID, endpointID, "stale CREATE must not resurrect a deleted endpoint")
}

// TestApplyDeleteReplicationEvent_RecreationAllowed verifies that a CREATE with a clock strictly
// newer than the DELETE tombstone is accepted (intentional recreation).
func TestApplyDeleteReplicationEvent_RecreationAllowed(t *testing.T) {
	ctx := context.Background()
	client, mock := newTestEndpointClient(t)

	const endpointID = "endpoint-xyz"
	const endpointName = "my-endpoint-2"

	// DELETE with clock C1 (wall=100).
	deleteEntry := newTestEntry(endpointID, endpointName, 100)

	err := client.ApplyDeleteReplicationEvent(ctx, deleteEntry)
	require.NoError(t, err)

	// CREATE with clock C2 (wall=200) — newer than the tombstone; should be accepted.
	createEntry := newTestEntry(endpointID, endpointName, 200)

	mock.EXPECT().
		CreateOrUpdateNexusEndpoint(gomock.Any(), gomock.Any()).
		Return(&p.CreateOrUpdateNexusEndpointResponse{Version: 1}, nil).
		Times(1)

	err = client.ApplyCreateReplicationEvent(ctx, createEntry)
	require.NoError(t, err)

	// Endpoint must be present and tombstone must be cleared (intentional recreation removes it).
	require.Contains(t, client.endpointsByID, endpointID, "recreation with newer clock must be accepted")
	require.NotContains(t, client.deletedClocks, endpointID, "tombstone should be removed after accepted recreation")
}

// TestApplyUpdateReplicationEvent_AfterDelete verifies that a stale UPDATE arriving after a DELETE
// does not resurrect the endpoint.
func TestApplyUpdateReplicationEvent_AfterDelete(t *testing.T) {
	ctx := context.Background()
	client, mock := newTestEndpointClient(t)

	const endpointID = "endpoint-upd"
	const endpointName = "my-endpoint-upd"

	// DELETE with clock C2 (wall=200).
	deleteEntry := newTestEntry(endpointID, endpointName, 200)

	err := client.ApplyDeleteReplicationEvent(ctx, deleteEntry)
	require.NoError(t, err)

	// UPDATE with clock C1 (wall=100) arrives after DELETE — must be discarded.
	updateEntry := newTestEntry(endpointID, endpointName, 100)

	mock.EXPECT().CreateOrUpdateNexusEndpoint(gomock.Any(), gomock.Any()).Times(0)

	err = client.ApplyUpdateReplicationEvent(ctx, updateEntry)
	require.NoError(t, err)

	require.NotContains(t, client.endpointsByID, endpointID, "stale UPDATE must not resurrect a deleted endpoint")
}
