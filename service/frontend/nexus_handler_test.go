package frontend

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nexus-rpc/sdk-go/nexus"
	"github.com/stretchr/testify/require"
	enumspb "go.temporal.io/api/enums/v1"
	nexuspb "go.temporal.io/api/nexus/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/server/api/matchingservice/v1"
	persistencespb "go.temporal.io/server/api/persistence/v1"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/clock"
	"go.temporal.io/server/common/cluster"
	"go.temporal.io/server/common/cluster/clustertest"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/dynamicconfig"
	"go.temporal.io/server/common/headers"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/metrics/metricstest"
	"go.temporal.io/server/common/namespace"
	"go.temporal.io/server/common/primitives/timestamp"
	"go.temporal.io/server/common/quotas"
	"go.temporal.io/server/common/rpc/interceptor"
	"go.temporal.io/server/common/util"
)

type mockAuthorizer struct{}

// Authorize implements authorization.Authorizer.
func (mockAuthorizer) Authorize(ctx context.Context, caller *authorization.Claims, target *authorization.CallTarget) (authorization.Result, error) {
	return authorization.Result{Decision: authorization.DecisionAllow}, nil
}

var _ authorization.Authorizer = mockAuthorizer{}

type mockRateLimiter struct {
	allow bool
}

// Allow implements quotas.RequestRateLimiter.
func (r mockRateLimiter) Allow(now time.Time, request quotas.Request) bool {
	return r.allow
}

// Reserve implements quotas.RequestRateLimiter.
func (mockRateLimiter) Reserve(now time.Time, request quotas.Request) quotas.Reservation {
	panic("unimplemented for test")
}

// Wait implements quotas.RequestRateLimiter.
func (mockRateLimiter) Wait(ctx context.Context, request quotas.Request) error {
	panic("unimplemented for test")
}

var _ quotas.RequestRateLimiter = mockRateLimiter{}

type mockNamespaceChecker namespace.Name

func (n mockNamespaceChecker) Exists(name namespace.Name) error {
	if name == namespace.Name(n) {
		return nil
	}
	return errors.New("doesn't exist")
}

type contextOptions struct {
	namespaceState          enumspb.NamespaceState
	namespacePassive        bool
	quota                   int
	namespaceRateLimitAllow bool
	rateLimitAllow          bool
	redirectAllow           bool
	headersBlacklist        []string
}

func newOperationContext(options contextOptions) *operationContext {
	oc := &operationContext{
		nexusContext: &nexusContext{},
	}
	oc.logger = log.NewTestLogger()
	mh := metricstest.NewCaptureHandler()
	oc.metricsHandlerForInterceptors = mh
	oc.metricsHandler = mh
	oc.clientVersionChecker = headers.NewDefaultVersionChecker()
	oc.apiName = "/temporal.api.nexusservice.v1.NexusService/DispatchNexusTask"
	oc.responseHeaders = make(map[string]string)

	oc.namespaceName = "test-namespace"
	activeClusterName := cluster.TestCurrentClusterName
	if options.namespacePassive {
		activeClusterName = cluster.TestAlternativeClusterName
	}
	oc.namespace = namespace.NewGlobalNamespaceForTest(
		&persistencespb.NamespaceInfo{
			Id:    uuid.NewString(),
			Name:  oc.namespaceName,
			State: options.namespaceState,
		},
		&persistencespb.NamespaceConfig{
			Retention:                    timestamp.DurationFromDays(1),
			CustomSearchAttributeAliases: make(map[string]string),
		},
		&persistencespb.NamespaceReplicationConfig{
			ActiveClusterName: activeClusterName,
			Clusters: []string{
				cluster.TestCurrentClusterName,
				cluster.TestAlternativeClusterName,
			},
		},
		1,
	)

	checker := mockNamespaceChecker(oc.namespace.Name())
	oc.auth = authorization.NewInterceptor(
		nil,
		mockAuthorizer{},
		oc.metricsHandler,
		oc.logger,
		checker,
		nil,
		"",
		"",
		dynamicconfig.GetBoolPropertyFn(false), // enableCrossNamespaceCommands
	)
	oc.namespaceConcurrencyLimitInterceptor = interceptor.NewConcurrentRequestLimitInterceptor(
		nil,
		nil,
		oc.logger,
		func(ns string) int { return options.quota },
		func(ns string) int { return options.quota },
		map[string]int{
			oc.apiName: 1,
		},
	)
	oc.namespaceRateLimitInterceptor = interceptor.NewNamespaceRateLimitInterceptor(
		nil,
		mockRateLimiter{options.namespaceRateLimitAllow},
		make(map[string]int),
		func() bool { return true },
	)
	oc.rateLimitInterceptor = interceptor.NewRateLimitInterceptor(
		mockRateLimiter{options.rateLimitAllow},
		make(map[string]int),
	)

	oc.clusterMetadata = clustertest.NewMetadataForTest(
		cluster.NewTestClusterMetadataConfig(true, !options.namespacePassive),
	)
	oc.forwardingEnabledForNamespace = dynamicconfig.GetBoolPropertyFnFilteredByNamespace(
		options.redirectAllow,
	)
	oc.headersBlacklist = dynamicconfig.NewGlobalCachedTypedValue(
		dynamicconfig.NewCollection(
			&dynamicconfig.StaticClient{
				dynamicconfig.FrontendNexusRequestHeadersBlacklist.Key(): options.headersBlacklist,
			},
			nil,
		),
		dynamicconfig.FrontendNexusRequestHeadersBlacklist,
		func(patterns []string) (*regexp.Regexp, error) {
			if len(patterns) == 0 {
				return matchNothing, nil
			}
			return util.WildCardStringsToRegexp(patterns)
		},
	)
	oc.redirectionInterceptor = interceptor.NewRedirection(
		nil,
		nil,
		config.DCRedirectionPolicy{Policy: interceptor.DCRedirectionPolicyAllAPIsForwarding},
		oc.logger,
		nil,
		oc.metricsHandlerForInterceptors,
		clock.NewRealTimeSource(),
		oc.clusterMetadata,
	)

	return oc
}

func TestNexusInterceptRequest_InvalidNamespaceState_ResultsInBadRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_DELETED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, nexus.Header{})
	var handlerError *nexus.HandlerError
	require.ErrorAs(t, err, &handlerError)
	require.Equal(t, nexus.HandlerErrorTypeBadRequest, handlerError.Type)
	require.Equal(t, "bad request", handlerError.Cause.Error())
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "invalid_namespace_state"}, snap["test"][0].Tags)
}

func TestNexusInterceptRequest_NamespaceConcurrencyLimited_ResultsInResourceExhausted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   0,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, nexus.Header{})
	var handlerError *nexus.HandlerError
	require.ErrorAs(t, err, &handlerError)
	require.Equal(t, nexus.HandlerErrorTypeResourceExhausted, handlerError.Type)
	require.Equal(t, "resource exhausted", handlerError.Cause.Error())
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "namespace_concurrency_limited"}, snap["test"][0].Tags)
}

func TestNexusInterceptRequest_NamespaceRateLimited_ResultsInResourceExhausted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: false,
		rateLimitAllow:          true,
	})
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, nexus.Header{})
	var handlerError *nexus.HandlerError
	require.ErrorAs(t, err, &handlerError)
	require.Equal(t, nexus.HandlerErrorTypeResourceExhausted, handlerError.Type)
	require.Equal(t, "namespace rate limit exceeded", handlerError.Cause.Error())
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "namespace_rate_limited"}, snap["test"][0].Tags)
}

func TestNexusInterceptRequest_GlobalRateLimited_ResultsInResourceExhausted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          false,
	})
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, nexus.Header{})
	var handlerError *nexus.HandlerError
	require.ErrorAs(t, err, &handlerError)
	require.Equal(t, nexus.HandlerErrorTypeResourceExhausted, handlerError.Type)
	require.Equal(t, "service rate limit exceeded", handlerError.Cause.Error())
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "global_rate_limited"}, snap["test"][0].Tags)
}

func TestNexusInterceptRequest_ForwardingDisabled_ResultsInUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		namespacePassive:        true,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
		redirectAllow:           false,
	})
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, nexus.Header{})
	var handlerError *nexus.HandlerError
	require.ErrorAs(t, err, &handlerError)
	require.Equal(t, nexus.HandlerErrorTypeUnavailable, handlerError.Type)
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "namespace_inactive_forwarding_disabled"}, snap["test"][0].Tags)
}

func TestNexusInterceptRequest_ForwardingEnabled_ResultsInNotActiveError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		namespacePassive:        true,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
		redirectAllow:           true,
	})
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, nexus.Header{})
	var notActiveErr *serviceerror.NamespaceNotActive
	require.ErrorAs(t, err, &notActiveErr)
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "request_forwarded"}, snap["test"][0].Tags)
}

func TestNexusInterceptRequest_InvalidSDKVersion_ResultsInBadRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		namespacePassive:        false,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
		redirectAllow:           true,
	})
	header := nexus.Header{headerUserAgent: "Nexus-go-sdk/v99.0.0"}
	ctx = oc.augmentContext(ctx, header)
	err = oc.interceptRequest(ctx, &matchingservice.DispatchNexusTaskRequest{}, header)
	var handlerError *nexus.HandlerError
	require.ErrorAs(t, err, &handlerError)
	require.Equal(t, nexus.HandlerErrorTypeBadRequest, handlerError.Type)
	mh := oc.metricsHandler.(*metricstest.CaptureHandler) //nolint:revive
	capture := mh.StartCapture()
	oc.metricsHandler.Counter("test").Record(1)
	mh.StopCapture(capture)
	snap := capture.Snapshot()
	require.Equal(t, 1, len(snap["test"]))
	require.Equal(t, map[string]string{"outcome": "unsupported_client"}, snap["test"][0].Tags)
}

// newDDSignerHolder builds a GlobalCachedTypedValue[*ddCallerSigner] backed by
// a static dynamicconfig key, mirroring how the real handler reads the signer.
// Passing "" yields a holder whose Get returns nil, modeling the
// injection-disabled configuration.
func newDDSignerHolder(t *testing.T, b64Key string) *dynamicconfig.GlobalCachedTypedValue[*ddCallerSigner] {
	t.Helper()
	holder := dynamicconfig.NewGlobalCachedTypedValue(
		dynamicconfig.NewCollection(
			&dynamicconfig.StaticClient{
				dynamicconfig.FrontendNexusDDCallerHmacKey.Key(): b64Key,
			},
			nil,
		),
		dynamicconfig.FrontendNexusDDCallerHmacKey,
		func(k string) (*ddCallerSigner, error) {
			return newDDCallerSigner(k)
		},
	)
	return holder
}

func testDDHMACKeyB64(t *testing.T) string {
	t.Helper()
	// Deterministic 32-byte key so tests can assert exact signature values.
	key := make([]byte, minHMACKeyBytes)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.RawStdEncoding.EncodeToString(key)
}

func TestNexusInterceptRequest_DDCallerInjection_DisabledWhenHolderNil(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	oc.claims = &authorization.Claims{Subject: "alice", System: authorization.RoleWriter}
	// ddSigner intentionally left nil.

	header := nexus.Header{"ok-header": "ok"}
	ctx = oc.augmentContext(ctx, header)
	req := &matchingservice.DispatchNexusTaskRequest{Request: &nexuspb.Request{Header: map[string]string{"ok-header": "ok"}}}
	require.NoError(t, oc.interceptRequest(ctx, req, header))

	for _, k := range ddCallerHeaders {
		_, present := req.Request.Header[k]
		require.Falsef(t, present, "header %q must be absent when signer holder is nil", k)
	}
}

func TestNexusInterceptRequest_DDCallerInjection_DisabledWhenKeyEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	oc.claims = &authorization.Claims{Subject: "alice"}
	oc.ddSigner = newDDSignerHolder(t, "") // empty key -> Get() returns nil signer.

	header := nexus.Header{"ok-header": "ok"}
	ctx = oc.augmentContext(ctx, header)
	req := &matchingservice.DispatchNexusTaskRequest{Request: &nexuspb.Request{Header: map[string]string{"ok-header": "ok"}}}
	require.NoError(t, oc.interceptRequest(ctx, req, header))

	for _, k := range ddCallerHeaders {
		_, present := req.Request.Header[k]
		require.Falsef(t, present, "header %q must be absent when HMAC key is empty", k)
	}
}

func TestNexusInterceptRequest_DDCallerInjection_StampsAllHeadersAndVerifiableSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	oc.endpointName = "orders-service"
	oc.claims = &authorization.Claims{
		Subject: "user:alice",
		System:  authorization.RoleWriter,
		Namespaces: map[string]authorization.Role{
			"billing": authorization.RoleReader,
			"orders":  authorization.RoleWorker | authorization.RoleAdmin,
		},
	}
	keyB64 := testDDHMACKeyB64(t)
	oc.ddSigner = newDDSignerHolder(t, keyB64)

	header := nexus.Header{"ok-header": "ok"}
	ctx = oc.augmentContext(ctx, header)
	req := &matchingservice.DispatchNexusTaskRequest{Request: &nexuspb.Request{Header: map[string]string{"ok-header": "ok"}}}
	require.NoError(t, oc.interceptRequest(ctx, req, header))

	got := req.Request.Header
	require.Equal(t, "user:alice", got[ddCallerSubjectHeader])
	require.Equal(t, "writer", got[ddCallerSystemRoleHeader])
	require.Equal(t, "billing=reader,orders=worker+admin", got[ddCallerNsRolesHeader])
	require.Equal(t, "test-namespace", got[ddCallerTargetNsHeader])
	require.Equal(t, "orders-service", got[ddCallerEndpointHeader])
	require.NotEmpty(t, got[ddCallerTSHeader])
	require.NotEmpty(t, got[ddCallerSigHeader])

	// A verifier reconstructs the payload from the emitted fields and confirms
	// the signature matches. Cross-field tampering would fail this check.
	verifier, err := newDDCallerSigner(keyB64)
	require.NoError(t, err)
	expected := verifier.Sign(signedPayload(
		got[ddCallerSubjectHeader],
		got[ddCallerSystemRoleHeader],
		got[ddCallerNsRolesHeader],
		got[ddCallerTargetNsHeader],
		got[ddCallerEndpointHeader],
		got[ddCallerTSHeader],
	))
	require.Equal(t, expected, got[ddCallerSigHeader])
}

func TestNexusInterceptRequest_DDCallerInjection_StripsAttackerSuppliedHeaders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	oc.claims = &authorization.Claims{Subject: "real-caller"}
	oc.ddSigner = newDDSignerHolder(t, testDDHMACKeyB64(t))

	// Hostile caller tries to forge a server-issued attestation by including
	// x-dd-caller-* headers on the inbound request. The server must strip
	// these before stamping its own values.
	hostile := map[string]string{
		ddCallerSubjectHeader:    "admin-impersonator",
		ddCallerSystemRoleHeader: "admin",
		ddCallerSigHeader:        "deadbeef",
		"ok-header":              "ok",
	}
	header := nexus.Header{"ok-header": "ok"}
	ctx = oc.augmentContext(ctx, header)
	req := &matchingservice.DispatchNexusTaskRequest{Request: &nexuspb.Request{Header: hostile}}
	require.NoError(t, oc.interceptRequest(ctx, req, header))

	require.Equal(t, "real-caller", req.Request.Header[ddCallerSubjectHeader],
		"subject header must reflect c.claims, not the forged value")
	require.NotEqual(t, "deadbeef", req.Request.Header[ddCallerSigHeader],
		"signature must be regenerated over server values, not carried over from inbound request")
	require.Equal(t, "ok", req.Request.Header["ok-header"])
}

func TestNexusInterceptRequest_DDCallerInjection_StripsHostileHeadersEvenWhenClaimsNil(t *testing.T) {
	// A request whose claim mapper produced nil claims (e.g. anonymous /
	// unauthenticated) must not be able to smuggle a forged x-dd-caller-*
	// attestation past the frontend. The signer is configured, so the strip
	// runs unconditionally; the stamp is skipped because c.claims is nil.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
	})
	// oc.claims intentionally left nil.
	oc.ddSigner = newDDSignerHolder(t, testDDHMACKeyB64(t))

	hostile := map[string]string{
		ddCallerSubjectHeader:    "admin-impersonator",
		ddCallerSystemRoleHeader: "admin",
		ddCallerSigHeader:        "deadbeef",
		"ok-header":              "ok",
	}
	header := nexus.Header{"ok-header": "ok"}
	ctx = oc.augmentContext(ctx, header)
	req := &matchingservice.DispatchNexusTaskRequest{Request: &nexuspb.Request{Header: hostile}}
	require.NoError(t, oc.interceptRequest(ctx, req, header))

	for _, k := range ddCallerHeaders {
		_, present := req.Request.Header[k]
		require.Falsef(t, present, "hostile header %q must be stripped even when claims are nil", k)
	}
	require.Equal(t, "ok", req.Request.Header["ok-header"])
}

func TestNexusInterceptRequest_DDCallerInjection_StrippedByBlacklist(t *testing.T) {
	// Documents the operator hazard: if an operator adds x-dd-caller-* to
	// FrontendNexusRequestHeadersBlacklist, injection runs but the sanitize
	// step strips the stamped headers before they leave the frontend, so the
	// bridge worker sees no attestation and denies every request. This test
	// locks the behavior so a future change that silently defeats the
	// blacklist can't ship unnoticed.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
		headersBlacklist:        []string{"x-dd-caller-*"},
	})
	oc.claims = &authorization.Claims{Subject: "alice"}
	oc.ddSigner = newDDSignerHolder(t, testDDHMACKeyB64(t))

	header := nexus.Header{"ok-header": "ok"}
	ctx = oc.augmentContext(ctx, header)
	req := &matchingservice.DispatchNexusTaskRequest{Request: &nexuspb.Request{Header: map[string]string{"ok-header": "ok"}}}
	require.NoError(t, oc.interceptRequest(ctx, req, header))

	for _, k := range ddCallerHeaders {
		_, present := req.Request.Header[k]
		require.Falsef(t, present, "blacklist must strip %q — operator hazard documented in constants.go", k)
	}
	require.Equal(t, "ok", req.Request.Header["ok-header"])
}

func TestNexusInterceptRequest_HeadersSanitization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var err error
	oc := newOperationContext(contextOptions{
		namespaceState:          enumspb.NAMESPACE_STATE_REGISTERED,
		namespacePassive:        false,
		quota:                   1,
		namespaceRateLimitAllow: true,
		rateLimitAllow:          true,
		headersBlacklist:        []string{"delete-*", "remove-*"},
	})
	initialHeader := nexus.Header{
		"ok-header":  "ok",
		"delete-foo": "foo",
		"delete-bar": "bar",
		"remove-zzz": "zzz",
	}
	header := util.CloneMapNonNil(initialHeader)
	ctx = oc.augmentContext(ctx, header)
	request := &matchingservice.DispatchNexusTaskRequest{
		Request: &nexuspb.Request{Header: header},
	}
	err = oc.interceptRequest(ctx, request, header)
	require.NoError(t, err)
	require.Equal(t, initialHeader, header)
	require.Equal(t, map[string]string{"ok-header": "ok"}, request.Request.Header)
}
