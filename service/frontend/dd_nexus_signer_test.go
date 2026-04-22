package frontend

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/authorization"
)

func randomKey(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestNewDDCallerSigner_EmptyKeyDisablesInjection(t *testing.T) {
	signer, err := newDDCallerSigner("")
	require.NoError(t, err)
	require.Nil(t, signer)
}

func TestNewDDCallerSigner_RejectsShortKey(t *testing.T) {
	short := base64.RawStdEncoding.EncodeToString(randomKey(t, minHMACKeyBytes-1))
	signer, err := newDDCallerSigner(short)
	require.Error(t, err)
	require.Nil(t, signer)
	require.Contains(t, err.Error(), "too short")
}

func TestNewDDCallerSigner_RejectsInvalidBase64(t *testing.T) {
	signer, err := newDDCallerSigner("!!!not-base64!!!")
	require.Error(t, err)
	require.Nil(t, signer)
}

func TestNewDDCallerSigner_AcceptsPaddedAndUnpadded(t *testing.T) {
	key := randomKey(t, minHMACKeyBytes)
	padded := base64.StdEncoding.EncodeToString(key)
	unpadded := base64.RawStdEncoding.EncodeToString(key)

	sPadded, err := newDDCallerSigner(padded)
	require.NoError(t, err)
	require.NotNil(t, sPadded)

	sUnpadded, err := newDDCallerSigner(unpadded)
	require.NoError(t, err)
	require.NotNil(t, sUnpadded)

	require.Equal(t, sPadded.Sign("payload"), sUnpadded.Sign("payload"),
		"padded and unpadded encodings of the same key must produce the same MAC")
}

func TestNewDDCallerSigner_AcceptsURLSafeAlphabet(t *testing.T) {
	// Pick a key whose standard base64 encoding includes characters that the
	// URL-safe alphabet remaps (+ -> -, / -> _), to force the two alphabets
	// to diverge textually while representing the same bytes.
	key := make([]byte, minHMACKeyBytes)
	for i := range key {
		key[i] = byte(i * 7)
	}
	std := base64.RawStdEncoding.EncodeToString(key)
	urlSafe := base64.RawURLEncoding.EncodeToString(key)
	require.NotEqual(t, std, urlSafe, "test precondition: chosen key must expose alphabet differences")

	sStd, err := newDDCallerSigner(std)
	require.NoError(t, err)
	sURL, err := newDDCallerSigner(urlSafe)
	require.NoError(t, err)

	require.Equal(t, sStd.Sign("payload"), sURL.Sign("payload"),
		"URL-safe and standard alphabet encodings of the same key must produce the same MAC")
}

func TestDDCallerSigner_SignIsDeterministic(t *testing.T) {
	key := base64.RawStdEncoding.EncodeToString(randomKey(t, minHMACKeyBytes))
	signer, err := newDDCallerSigner(key)
	require.NoError(t, err)

	require.Equal(t, signer.Sign("abc"), signer.Sign("abc"))
	require.NotEqual(t, signer.Sign("abc"), signer.Sign("abd"))
}

func TestDDCallerSigner_DifferentKeysProduceDifferentSignatures(t *testing.T) {
	k1 := base64.RawStdEncoding.EncodeToString(randomKey(t, minHMACKeyBytes))
	k2 := base64.RawStdEncoding.EncodeToString(randomKey(t, minHMACKeyBytes))
	require.NotEqual(t, k1, k2)

	s1, err := newDDCallerSigner(k1)
	require.NoError(t, err)
	s2, err := newDDCallerSigner(k2)
	require.NoError(t, err)

	require.NotEqual(t, s1.Sign("payload"), s2.Sign("payload"))
}

func TestSignedPayload_IsLengthPrefixed(t *testing.T) {
	p := signedPayload("sub", "worker", "ns=reader", "target", "endpoint", "100", "active", "n0", "jwt")
	// Expected: concat of "<len>:<value>" for each field, in order.
	require.Equal(t, "3:sub6:worker9:ns=reader6:target8:endpoint3:1006:active2:n03:jwt", p)
}

func TestSignedPayload_DisambiguatesFieldBoundaries(t *testing.T) {
	// A hostile subject that tries to forge the remaining fields by embedding
	// colons or other separators must not produce the same payload as a
	// legitimate multi-field input.
	a := signedPayload("sub:target", "", "", "real", "endpoint", "1", "c", "n", "jwt")
	b := signedPayload("sub", "", "", "target", "realendpoint", "1", "c", "n", "jwt")
	require.NotEqual(t, a, b,
		"length-prefixing must disambiguate field boundaries even when values contain separator-like bytes")
}

func TestSignedPayload_DisambiguatesTrailingFields(t *testing.T) {
	// Length-prefixing must also prevent collisions between trailing fields
	// (cluster/nonce/authType) — a hostile caller who can influence nonce
	// (e.g., via header injection defeated by strip) must not be able to
	// forge cluster or authType through concatenation.
	a := signedPayload("s", "", "", "t", "e", "1", "cluster-a", "nonce", "jwt")
	b := signedPayload("s", "", "", "t", "e", "1", "cluster", "a nonce", "jwt")
	require.NotEqual(t, a, b,
		"length-prefixing must disambiguate cluster/nonce boundaries")
}

func TestEncodeRole_Undefined(t *testing.T) {
	require.Equal(t, "", encodeRole(authorization.RoleUndefined))
}

func TestEncodeRole_SingleBits(t *testing.T) {
	require.Equal(t, "worker", encodeRole(authorization.RoleWorker))
	require.Equal(t, "reader", encodeRole(authorization.RoleReader))
	require.Equal(t, "writer", encodeRole(authorization.RoleWriter))
	require.Equal(t, "admin", encodeRole(authorization.RoleAdmin))
}

func TestEncodeRole_MultipleBitsAscending(t *testing.T) {
	combined := authorization.RoleAdmin | authorization.RoleWorker
	// Bits must render in ascending-bit order regardless of how they were OR'd.
	require.Equal(t, "worker+admin", encodeRole(combined))
}

func TestEncodeRole_UnknownBitsSurfaceInOutput(t *testing.T) {
	// A role with an unknown bit set must surface the raw value so the verifier
	// can refuse to honor it, rather than silently truncating.
	invalid := authorization.RoleWorker | authorization.Role(1<<10)
	encoded := encodeRole(invalid)
	require.Contains(t, encoded, "worker")
	require.Contains(t, encoded, "unknown(0x")
}

func TestEncodeNamespaceRoles_EmptyMapIsEmptyString(t *testing.T) {
	require.Equal(t, "", encodeNamespaceRoles(nil))
	require.Equal(t, "", encodeNamespaceRoles(map[string]authorization.Role{}))
}

func TestEncodeNamespaceRoles_Deterministic(t *testing.T) {
	m := map[string]authorization.Role{
		"zeta":  authorization.RoleReader,
		"alpha": authorization.RoleWorker | authorization.RoleAdmin,
		"mike":  authorization.RoleWriter,
	}
	// Keys sorted ascending; role bits ascending within each entry; "," joins.
	require.Equal(t, "alpha=worker+admin,mike=writer,zeta=reader", encodeNamespaceRoles(m))
}

func TestEncodeNamespaceRoles_StableAcrossIterationsOfSameMap(t *testing.T) {
	m := map[string]authorization.Role{
		"b": authorization.RoleReader,
		"a": authorization.RoleWorker,
		"c": authorization.RoleAdmin,
	}
	first := encodeNamespaceRoles(m)
	for i := 0; i < 32; i++ {
		require.Equal(t, first, encodeNamespaceRoles(m),
			"Go map iteration is unspecified; encode output must be sorted")
	}
}

func TestDDCallerHeaders_CanonicalHeaderListMatchesConstants(t *testing.T) {
	// Guardrail: if someone adds a header constant but forgets to extend
	// ddCallerHeaders, injection stops stripping forged copies of it.
	all := strings.Join(ddCallerHeaders, ",")
	for _, name := range []string{
		ddCallerSubjectHeader,
		ddCallerSystemRoleHeader,
		ddCallerNsRolesHeader,
		ddCallerTargetNsHeader,
		ddCallerEndpointHeader,
		ddCallerTSHeader,
		ddCallerClusterHeader,
		ddCallerNonceHeader,
		ddCallerAuthTypeHeader,
		ddCallerSigHeader,
	} {
		require.Contains(t, all, name, "ddCallerHeaders must include %q", name)
	}
}

func TestInferAuthType_NilClaimsIsEmpty(t *testing.T) {
	require.Equal(t, "", inferAuthType(nil))
}

func TestInferAuthType_AdminWithNoNamespacesIsMTLS(t *testing.T) {
	// DD claim mapper shape for internode / replication mTLS: Subject set to
	// the CN, System=RoleAdmin, Namespaces nil.
	claims := &authorization.Claims{
		Subject: "internode.example.com",
		System:  authorization.RoleAdmin,
	}
	require.Equal(t, ddAuthTypeMTLS, inferAuthType(claims))
}

func TestInferAuthType_AdminWithNamespacesIsJWT(t *testing.T) {
	// An admin JWT with explicit domain grants does NOT look like internode
	// mTLS — the Namespaces map is populated by the claim mapper.
	claims := &authorization.Claims{
		Subject: "alice@datadog",
		System:  authorization.RoleAdmin,
		Namespaces: map[string]authorization.Role{
			"billing": authorization.RoleReader,
		},
	}
	require.Equal(t, ddAuthTypeJWT, inferAuthType(claims))
}

func TestInferAuthType_NonAdminWithNoNamespacesIsJWT(t *testing.T) {
	// A JWT user with no domain grants (e.g., misconfigured token) is not
	// mTLS — mTLS specifically requires System=RoleAdmin.
	claims := &authorization.Claims{
		Subject: "alice@datadog",
		System:  authorization.RoleWriter,
	}
	require.Equal(t, ddAuthTypeJWT, inferAuthType(claims))
}

func TestInferAuthType_UndefinedRoleIsJWT(t *testing.T) {
	// Empty role + empty namespaces defaults to JWT, not MTLS — the bridge
	// worker's allowlist for mTLS should never admit a non-admin subject.
	claims := &authorization.Claims{Subject: "alice@datadog"}
	require.Equal(t, ddAuthTypeJWT, inferAuthType(claims))
}

type fakeAuthTypeExt struct{ tag string }

func (f *fakeAuthTypeExt) DDAuthType() string { return f.tag }

func TestInferAuthType_ExtensionOverridesHeuristic_MTLS(t *testing.T) {
	// An extension-provided "mtls" tag must win even when the heuristic would
	// have returned "jwt" (e.g. an mTLS identity that legitimately carries
	// domain grants — a scenario the heuristic can't represent).
	claims := &authorization.Claims{
		Subject:    "workflow-worker.example.com",
		System:     authorization.RoleWorker,
		Namespaces: map[string]authorization.Role{"billing": authorization.RoleWorker},
		Extensions: &fakeAuthTypeExt{tag: ddAuthTypeMTLS},
	}
	require.Equal(t, ddAuthTypeMTLS, inferAuthType(claims))
}

func TestInferAuthType_ExtensionOverridesHeuristic_JWT(t *testing.T) {
	// An extension-provided "jwt" tag must win even when the heuristic would
	// have returned "mtls" — this is the exact false-positive the extension
	// exists to eliminate (admin JWT with no domain grants).
	claims := &authorization.Claims{
		Subject:    "alice@datadog",
		System:     authorization.RoleAdmin,
		Extensions: &fakeAuthTypeExt{tag: ddAuthTypeJWT},
	}
	require.Equal(t, ddAuthTypeJWT, inferAuthType(claims))
}

func TestInferAuthType_EmptyExtensionFallsBackToHeuristic(t *testing.T) {
	// An extension that returns "" (unknown auth path) must not silently blank
	// out the attestation — the heuristic still runs so partial extensions
	// don't regress coverage for deployments that haven't fully rolled out.
	claims := &authorization.Claims{
		Subject:    "internode.example.com",
		System:     authorization.RoleAdmin,
		Extensions: &fakeAuthTypeExt{tag: ""},
	}
	require.Equal(t, ddAuthTypeMTLS, inferAuthType(claims))
}

func TestInferAuthType_NonMatchingExtensionTypeFallsBackToHeuristic(t *testing.T) {
	// An Extensions value that doesn't implement authTypeExtension at all
	// (e.g. a struct from an older claim mapper) must not break the flow —
	// the heuristic carries us.
	claims := &authorization.Claims{
		Subject:    "alice@datadog",
		System:     authorization.RoleWriter,
		Extensions: struct{ Other string }{Other: "ignored"},
	}
	require.Equal(t, ddAuthTypeJWT, inferAuthType(claims))
}

func TestInferAuthType_ExtensionPassesThroughUnknownTag(t *testing.T) {
	// A claim mapper that emits a new auth path the fork hasn't seen yet
	// (e.g. "spiffe") must pass through verbatim — the signed payload is
	// the bridge worker's source of truth, not the fork's knowledge of
	// which tokens exist.
	claims := &authorization.Claims{
		Subject:    "spiffe://example/service",
		Extensions: &fakeAuthTypeExt{tag: "spiffe"},
	}
	require.Equal(t, "spiffe", inferAuthType(claims))
}
