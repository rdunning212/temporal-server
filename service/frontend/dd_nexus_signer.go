package frontend

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.temporal.io/server/common/authorization"
)

// DD caller identity headers injected by the frontend onto a Nexus task's
// request.Request.Header, describing the authenticated caller of the request.
// A downstream Datadog Nexus bridge worker verifies the HMAC signature and
// uses the fields for allowlist enforcement. Header names are lowercase to
// match the Nexus SDK's normalization of incoming HTTP headers.
const (
	ddCallerSubjectHeader    = "x-dd-caller-subject"
	ddCallerSystemRoleHeader = "x-dd-caller-system-role"
	ddCallerNsRolesHeader    = "x-dd-caller-ns-roles"
	ddCallerTargetNsHeader   = "x-dd-caller-target-ns"
	ddCallerEndpointHeader   = "x-dd-caller-endpoint"
	ddCallerTSHeader         = "x-dd-caller-ts"
	ddCallerClusterHeader    = "x-dd-caller-cluster"
	ddCallerNonceHeader      = "x-dd-caller-nonce"
	ddCallerAuthTypeHeader   = "x-dd-caller-auth-type"
	ddCallerSigHeader        = "x-dd-caller-sig"
)

// ddCallerHeaders lists every caller-identity header the frontend populates.
// interceptRequest strips any existing entries with these keys from both the
// inbound nexus.Header and the matching request's header map before writing
// the server-authenticated values, preventing a hostile caller from forging an
// attestation. The strip runs unconditionally whenever a signer is configured,
// including on the cross-cluster forward path where options.Header is relayed
// verbatim to the active cluster.
var ddCallerHeaders = []string{
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
}

// minHMACKeyBytes is the minimum accepted key size for HMAC-SHA256. Shorter
// keys are rejected at construction to guard against deploying a weak key by
// accident.
const minHMACKeyBytes = 32

// ddCallerSigner produces HMAC-SHA256 signatures over caller-identity
// attestations. A nil *ddCallerSigner is valid and disables header injection.
//
// Signature input (the "signed payload") is a length-prefixed concatenation
// of caller identity fields — see signedPayload. Signers emit hex-encoded
// MAC; verifiers MUST use hmac.Equal for constant-time comparison.
type ddCallerSigner struct {
	key []byte
}

// newDDCallerSigner decodes a base64 HMAC key and returns a signer. Accepts
// standard and URL-safe alphabets, padded or unpadded, so operators can paste
// whichever form their key-management system emits (e.g. `openssl rand -base64`
// uses the standard alphabet; some KMS exports use URL-safe).
//
// An empty b64Key returns (nil, nil), meaning injection is disabled — this is
// the default posture for clusters that have not opted in, and it is also the
// only way to disable injection at runtime: rotating to a malformed or
// too-short key returns an error, which GlobalCachedTypedValue treats as a
// transient conversion failure and preserves the previously cached signer.
func newDDCallerSigner(b64Key string) (*ddCallerSigner, error) {
	if b64Key == "" {
		return nil, nil
	}
	trimmed := strings.TrimRight(b64Key, "=")
	key, err := base64.RawStdEncoding.DecodeString(trimmed)
	if err != nil {
		// Fall through to URL-safe on decode error; report the standard
		// alphabet's error if URL-safe also fails, since that's the common case.
		key, urlErr := base64.RawURLEncoding.DecodeString(trimmed)
		if urlErr != nil {
			return nil, fmt.Errorf("decode DD caller HMAC key: %w", err)
		}
		if len(key) < minHMACKeyBytes {
			return nil, fmt.Errorf("DD caller HMAC key too short: got %d bytes, want >= %d", len(key), minHMACKeyBytes)
		}
		return &ddCallerSigner{key: key}, nil
	}
	if len(key) < minHMACKeyBytes {
		return nil, fmt.Errorf("DD caller HMAC key too short: got %d bytes, want >= %d", len(key), minHMACKeyBytes)
	}
	return &ddCallerSigner{key: key}, nil
}

// Sign returns the hex-encoded HMAC-SHA256 of payload.
func (s *ddCallerSigner) Sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// signedPayload produces the canonical payload string that Sign is computed
// over. Each field is length-prefixed as "<N>:<field>" and concatenated; any
// byte may appear in a field value without ambiguity for the verifier, which
// reads the decimal length, a colon, then that many bytes of field content,
// repeating for every field in order.
//
// The subject is derived from a JWT claim and can legally contain arbitrary
// bytes, so length-prefixing is required to prevent field-boundary
// manipulation by a hostile caller who can influence their own subject value.
//
// Field order is stable and MUST match the bridge worker's verification logic:
//
//	subject, systemRole, nsRoles, targetNs, endpoint, ts, cluster, nonce, authType
//
// cluster binds the attestation to the issuing cluster (prevents replay across
// clusters that share the HMAC key). nonce is a per-request random value
// (prevents replay within the timestamp acceptance window; the bridge worker
// MUST maintain a seen-nonce cache sized to the window). authType tags the
// auth mode that produced the subject (prevents subject collision between a
// JWT user and a matching mTLS CN).
func signedPayload(subject, systemRole, nsRoles, targetNs, endpoint, ts, cluster, nonce, authType string) string {
	var b strings.Builder
	b.Grow(len(subject) + len(systemRole) + len(nsRoles) + len(targetNs) + len(endpoint) + len(ts) + len(cluster) + len(nonce) + len(authType) + 72)
	for _, f := range [...]string{subject, systemRole, nsRoles, targetNs, endpoint, ts, cluster, nonce, authType} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

// Auth-type tags embedded in signed attestations. Bridge-worker allowlists
// MUST treat each value as a distinct subject namespace — an "mtls" subject
// "host.example.com" is NOT equivalent to a "jwt" subject of the same string.
const (
	ddAuthTypeMTLS = "mtls"
	ddAuthTypeJWT  = "jwt"
)

// inferAuthType is a best-effort classifier for the auth path that produced
// the given claims. The DD claim mapper emits Claims{System: RoleAdmin,
// Namespaces: nil} for internode and replication mTLS paths; JWT-backed user
// claims populate Namespaces from the mapped domain grants. Anything that
// doesn't match the mTLS pattern is treated as "jwt".
//
// This heuristic has a known false-positive: a JWT issued with admin scope
// and zero domain grants would be mislabeled as mtls. The bridge worker MUST
// defend against this by refusing to honor any "mtls" subject that is not on
// its explicit CN allowlist; the auth_type tag is one input to that decision,
// not a replacement for the allowlist. Returns "" for nil claims (anonymous).
//
// A proper fix — plumbing the real auth path out of the claim mapper — is
// tracked as a follow-up and requires dd-source changes outside this fork.
func inferAuthType(claims *authorization.Claims) string {
	if claims == nil {
		return ""
	}
	if claims.System == authorization.RoleAdmin && len(claims.Namespaces) == 0 {
		return ddAuthTypeMTLS
	}
	return ddAuthTypeJWT
}

// encodeRole renders an authorization.Role bitmask as a deterministic, stable
// human-readable string. Components are joined by "+" in ascending-bit order
// to match the iota definition in common/authorization/roles.go. Bitmask
// semantics are preserved: a role with both worker and admin bits set
// renders as "worker+admin". RoleUndefined renders as the empty string.
//
// If the role holds bits outside the defined set (a future role added
// upstream, or a garbage value from a buggy claim mapper), those bits are
// appended as "unknown(0xNN)" so the signature reflects the actual claim and
// verifiers can refuse to honor it.
func encodeRole(r authorization.Role) string {
	if r == authorization.RoleUndefined {
		return ""
	}
	var parts []string
	if r&authorization.RoleWorker != 0 {
		parts = append(parts, "worker")
	}
	if r&authorization.RoleReader != 0 {
		parts = append(parts, "reader")
	}
	if r&authorization.RoleWriter != 0 {
		parts = append(parts, "writer")
	}
	if r&authorization.RoleAdmin != 0 {
		parts = append(parts, "admin")
	}
	if !r.IsValid() {
		parts = append(parts, fmt.Sprintf("unknown(0x%x)", uint16(r)))
	}
	return strings.Join(parts, "+")
}

// encodeNamespaceRoles serializes a Claims.Namespaces map deterministically:
// keys sorted ascending, each entry rendered "ns=role[+role...]", entries
// joined with ",". Temporal namespace names are restricted by validation to
// a small alphanumeric+punctuation character set that excludes ",", "=", and
// "|", and the DD claim mapper keys its domain-v1:<name> entries with the
// same safe alphabet, so these separators are unambiguous for both standard
// and DD-issued claims. The overall encoded string is itself length-prefixed
// as a single field in signedPayload, so any future ambiguity within this
// encoding cannot leak into adjacent signed fields.
func encodeNamespaceRoles(m map[string]authorization.Role) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+encodeRole(m[k]))
	}
	return strings.Join(parts, ",")
}
