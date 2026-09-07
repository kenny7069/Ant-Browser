package backend

// BF-P1.11 structured policy/config attestation.
//
// The Go Agent is deliberately not a policy-hash authority.  It receives
// opaque Server tokens, saves them byte-for-byte, and reports only the
// allowlisted fields observed in an accepted launch state.  Canonical policy
// and config hashing lives in the Control Plane (auto-scraper).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	FarmAttestationVersion       = 1
	maxFarmAttestationTokenBytes = 4096
)

var (
	ErrFarmAttestationInvalid            = errors.New("invalid farm attestation")
	ErrFarmAttestationNotReady           = errors.New("farm attestation launch state is not verified")
	ErrFarmAttestationTokenMismatch      = errors.New("farm attestation token mismatch")
	ErrFarmAttestationStructuredMismatch = errors.New("farm attestation structured state mismatch")
	ErrFarmAttestationIdentityMismatch   = errors.New("farm attestation runtime identity mismatch")
	ErrFarmAttestationUnownedRestart     = errors.New("controlled restart requires an owned runtime")
)

// FarmAttestationPolicy is the safe, structured policy projection.  It is
// intentionally smaller than a profile record and contains no path, proxy
// URL, username, password, or secret reference.
type FarmAttestationPolicy struct {
	AllowedDomains []string `json:"allowed_domains"`
	Locale         string   `json:"locale"`
	Timezone       string   `json:"timezone"`
	WebRTCMode     string   `json:"webrtc_mode"`
}

// FarmAttestationProxy is the only proxy state allowed in an attestation.
// The revisions are public, opaque binding labels. Credentials and credential
// tokens are local connector-store material and cannot cross Control WSS.
type FarmAttestationProxy struct {
	Enabled            bool   `json:"enabled"`
	ConnectorType      string `json:"connector_type"`
	CredentialRevision string `json:"credential_revision"`
	ConfigRevision     string `json:"config_revision"`
}

// FarmAttestationRuntime is both the safe runtime config request and the
// structured applied_runtime response.  Policy fields are repeated here on
// purpose: the Server compares every field in one closed object.
type FarmAttestationRuntime struct {
	AllowedDomains []string             `json:"allowed_domains"`
	Locale         string               `json:"locale"`
	Timezone       string               `json:"timezone"`
	WebRTCMode     string               `json:"webrtc_mode"`
	Proxy          FarmAttestationProxy `json:"proxy"`
}

// FarmAttestationRequest is the Server→Agent contract.  PolicyHash and
// ConfigHash are opaque Server tokens; no method in this file computes one.
type FarmAttestationRequest struct {
	Version         int                    `json:"version"`
	RuntimeIdentity FarmRuntimeIdentity    `json:"runtime_identity"`
	PolicyHash      string                 `json:"policy_hash"`
	ConfigHash      string                 `json:"config_hash"`
	Policy          FarmAttestationPolicy  `json:"policy"`
	RuntimeConfig   FarmAttestationRuntime `json:"runtime_config"`
}

// FarmAttestationResponse is the Agent→Server contract.  Applied fields come
// from the saved request plus the launch state supplied to ApplyAttestation,
// never from an arbitrary echo field.
type FarmAttestationResponse struct {
	Version         int                    `json:"version"`
	RuntimeIdentity FarmRuntimeIdentity    `json:"runtime_identity"`
	PolicyHash      string                 `json:"policy_hash"`
	ConfigHash      string                 `json:"config_hash"`
	AppliedPolicy   FarmAttestationPolicy  `json:"applied_policy"`
	AppliedRuntime  FarmAttestationRuntime `json:"applied_runtime"`
	RestartRequired bool                   `json:"restart_required,omitempty"`
	Status          string                 `json:"status,omitempty"`
}

// MarshalJSON is the final response wire fence.  Keeping the response as a
// closed value type is important here: an attestation must never grow an
// arbitrary error/path/proxy field through an “any“ compatibility boundary.
func (response FarmAttestationResponse) MarshalJSON() ([]byte, error) {
	if err := response.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Version         int                    `json:"version"`
		RuntimeIdentity FarmRuntimeIdentity    `json:"runtime_identity"`
		PolicyHash      string                 `json:"policy_hash"`
		ConfigHash      string                 `json:"config_hash"`
		AppliedPolicy   FarmAttestationPolicy  `json:"applied_policy"`
		AppliedRuntime  FarmAttestationRuntime `json:"applied_runtime"`
		RestartRequired bool                   `json:"restart_required,omitempty"`
		Status          string                 `json:"status,omitempty"`
	}{
		Version:         response.Version,
		RuntimeIdentity: response.RuntimeIdentity,
		PolicyHash:      response.PolicyHash,
		ConfigHash:      response.ConfigHash,
		AppliedPolicy:   response.AppliedPolicy,
		AppliedRuntime:  response.AppliedRuntime,
		RestartRequired: response.RestartRequired,
		Status:          response.Status,
	})
}

// FarmAttestationLaunchState is a host-verifiable snapshot.  A Farm agent
// must set Ready only after the runtime has accepted/saved these structured
// fields and the launch/readiness checks have succeeded.  This type has no
// proxy secret-bearing field by construction.
type FarmAttestationLaunchState struct {
	Ready          bool                   `json:"ready"`
	Policy         FarmAttestationPolicy  `json:"policy"`
	AppliedRuntime FarmAttestationRuntime `json:"applied_runtime"`
}

// FarmAttestationCommandPayload is kept as a naming alias for transport
// adapters. The wire payload is exactly the request; launch state is never a
// remotely supplied field and is obtained from the local Agent host callback.
type FarmAttestationCommandPayload = FarmAttestationRequest

type farmAttestationRecord struct {
	request FarmAttestationRequest
	state   FarmAttestationLaunchState
}

// FarmAttestationAgent keeps only runtimes explicitly attested by this Agent
// process.  It is intentionally process-local at P1.11; durable adoption and
// reconcile belong to the later controller/fencing gates.
type FarmAttestationAgent struct {
	mu      sync.RWMutex
	records map[string]farmAttestationRecord
}

func NewFarmAttestationAgent() *FarmAttestationAgent {
	return &FarmAttestationAgent{records: make(map[string]farmAttestationRecord)}
}

func validateAttestationToken(token string, required bool) error {
	if required && token == "" {
		return fmt.Errorf("%w: token is required", ErrFarmAttestationInvalid)
	}
	if err := validateAttestationText(token, "token", maxFarmAttestationTokenBytes); err != nil {
		return err
	}
	// Do not trim or normalise.  Opaque token bytes must round-trip exactly.
	return nil
}

func validateAttestationText(value, field string, maximum int) error {
	if len(value) > maximum || !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is invalid", ErrFarmAttestationInvalid, field)
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return fmt.Errorf("%w: %s contains control characters", ErrFarmAttestationInvalid, field)
		}
	}
	return nil
}

func validateAttestationPolicy(policy FarmAttestationPolicy) error {
	if policy.AllowedDomains == nil {
		return fmt.Errorf("%w: allowed_domains must be an array", ErrFarmAttestationInvalid)
	}
	if err := validateAttestationText(policy.Locale, "locale", 32); err != nil {
		return err
	}
	if err := validateAttestationText(policy.Timezone, "timezone", 64); err != nil {
		return err
	}
	if err := validateAttestationText(policy.WebRTCMode, "webrtc_mode", 128); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(policy.AllowedDomains))
	for _, domain := range policy.AllowedDomains {
		if err := validateAttestationText(domain, "allowed_domains", 255); err != nil {
			return err
		}
		if domain == "" {
			return fmt.Errorf("%w: allowed_domains contains an empty value", ErrFarmAttestationInvalid)
		}
		if _, ok := seen[domain]; ok {
			return fmt.Errorf("%w: allowed_domains contains a duplicate", ErrFarmAttestationInvalid)
		}
		seen[domain] = struct{}{}
	}
	return nil
}

func validateAttestationProxy(proxy FarmAttestationProxy) error {
	if err := validateAttestationText(proxy.ConnectorType, "proxy.connector_type", 64); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"proxy.credential_revision": proxy.CredentialRevision,
		"proxy.config_revision":     proxy.ConfigRevision,
	} {
		if err := validateAttestationToken(value, false); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateAttestationRuntime(runtime FarmAttestationRuntime) error {
	if err := validateAttestationPolicy(FarmAttestationPolicy{
		AllowedDomains: runtime.AllowedDomains,
		Locale:         runtime.Locale,
		Timezone:       runtime.Timezone,
		WebRTCMode:     runtime.WebRTCMode,
	}); err != nil {
		return err
	}
	return validateAttestationProxy(runtime.Proxy)
}

func attestationPolicyMatchesRuntime(policy FarmAttestationPolicy, runtime FarmAttestationRuntime) bool {
	return equalStringSlice(policy.AllowedDomains, runtime.AllowedDomains) &&
		policy.Locale == runtime.Locale &&
		policy.Timezone == runtime.Timezone &&
		policy.WebRTCMode == runtime.WebRTCMode
}

func equalStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalAttestationProxy(left, right FarmAttestationProxy) bool {
	return left.Enabled == right.Enabled &&
		left.ConnectorType == right.ConnectorType &&
		left.CredentialRevision == right.CredentialRevision &&
		left.ConfigRevision == right.ConfigRevision
}

func equalAttestationRuntime(left, right FarmAttestationRuntime) bool {
	return attestationPolicyMatchesRuntime(FarmAttestationPolicy{
		AllowedDomains: left.AllowedDomains,
		Locale:         left.Locale,
		Timezone:       left.Timezone,
		WebRTCMode:     left.WebRTCMode,
	}, right) && equalAttestationProxy(left.Proxy, right.Proxy)
}

func validateAttestationIdentity(identity FarmRuntimeIdentity) error {
	for name, value := range map[string]string{
		"node_uid":             identity.NodeUID,
		"profile_id":           identity.ProfileID,
		"runtime_uid":          identity.RuntimeUID,
		"provider_instance_id": identity.ProviderInstanceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: runtime identity is incomplete", ErrFarmAttestationInvalid)
		}
		if err := validateAttestationText(value, "runtime_identity."+name, 256); err != nil {
			return err
		}
	}
	if identity.FencingEpoch == 0 || identity.Generation == 0 {
		return fmt.Errorf("%w: runtime identity is incomplete", ErrFarmAttestationInvalid)
	}
	return nil
}

func (request FarmAttestationRequest) validate() error {
	if request.Version != FarmAttestationVersion {
		return fmt.Errorf("%w: unsupported version", ErrFarmAttestationInvalid)
	}
	if err := validateAttestationIdentity(request.RuntimeIdentity); err != nil {
		return err
	}
	if err := validateAttestationToken(request.PolicyHash, true); err != nil {
		return err
	}
	if err := validateAttestationToken(request.ConfigHash, true); err != nil {
		return err
	}
	if request.RuntimeIdentity.ConfigHash == "" ||
		!bytes.Equal([]byte(request.RuntimeIdentity.ConfigHash), []byte(request.ConfigHash)) {
		return fmt.Errorf("%w: config token is not bound to runtime identity", ErrFarmAttestationInvalid)
	}
	if err := validateAttestationPolicy(request.Policy); err != nil {
		return err
	}
	if err := validateAttestationRuntime(request.RuntimeConfig); err != nil {
		return err
	}
	if !attestationPolicyMatchesRuntime(request.Policy, request.RuntimeConfig) {
		return fmt.Errorf("%w: policy/runtime contradiction", ErrFarmAttestationInvalid)
	}
	return nil
}

func (response FarmAttestationResponse) validate() error {
	if response.Version != FarmAttestationVersion {
		return fmt.Errorf("%w: unsupported response version", ErrFarmAttestationInvalid)
	}
	if err := validateAttestationIdentity(response.RuntimeIdentity); err != nil {
		return err
	}
	if response.RuntimeIdentity.ConfigHash == "" {
		return fmt.Errorf("%w: response runtime identity config token is required", ErrFarmAttestationInvalid)
	}
	if err := validateAttestationToken(response.PolicyHash, true); err != nil {
		return err
	}
	if err := validateAttestationToken(response.ConfigHash, true); err != nil {
		return err
	}
	if err := validateAttestationPolicy(response.AppliedPolicy); err != nil {
		return err
	}
	if err := validateAttestationRuntime(response.AppliedRuntime); err != nil {
		return err
	}
	if !attestationPolicyMatchesRuntime(response.AppliedPolicy, response.AppliedRuntime) {
		return fmt.Errorf("%w: response policy/runtime contradiction", ErrFarmAttestationInvalid)
	}
	if response.Status != "" && response.Status != "applied" && response.Status != "restart_required" {
		return fmt.Errorf("%w: response status is not allowlisted", ErrFarmAttestationInvalid)
	}
	return nil
}

func cloneFarmAttestationPolicy(policy FarmAttestationPolicy) FarmAttestationPolicy {
	if policy.AllowedDomains != nil {
		policy.AllowedDomains = append([]string{}, policy.AllowedDomains...)
	}
	return policy
}

func cloneFarmAttestationProxy(proxy FarmAttestationProxy) FarmAttestationProxy {
	return proxy
}

func cloneFarmAttestationRuntime(runtime FarmAttestationRuntime) FarmAttestationRuntime {
	if runtime.AllowedDomains != nil {
		runtime.AllowedDomains = append([]string{}, runtime.AllowedDomains...)
	}
	runtime.Proxy = cloneFarmAttestationProxy(runtime.Proxy)
	return runtime
}

func cloneFarmAttestationRequest(request FarmAttestationRequest) FarmAttestationRequest {
	request.Policy = cloneFarmAttestationPolicy(request.Policy)
	request.RuntimeConfig = cloneFarmAttestationRuntime(request.RuntimeConfig)
	return request
}

func cloneFarmAttestationLaunchState(state FarmAttestationLaunchState) FarmAttestationLaunchState {
	state.Policy = cloneFarmAttestationPolicy(state.Policy)
	state.AppliedRuntime = cloneFarmAttestationRuntime(state.AppliedRuntime)
	return state
}

func cloneFarmAttestationResponse(response FarmAttestationResponse) FarmAttestationResponse {
	response.AppliedPolicy = cloneFarmAttestationPolicy(response.AppliedPolicy)
	response.AppliedRuntime = cloneFarmAttestationRuntime(response.AppliedRuntime)
	return response
}

func (state FarmAttestationLaunchState) validate() error {
	if !state.Ready {
		return ErrFarmAttestationNotReady
	}
	if err := validateAttestationPolicy(state.Policy); err != nil {
		return err
	}
	if err := validateAttestationRuntime(state.AppliedRuntime); err != nil {
		return err
	}
	if !attestationPolicyMatchesRuntime(state.Policy, state.AppliedRuntime) {
		return fmt.Errorf("%w: launch policy/runtime contradiction", ErrFarmAttestationInvalid)
	}
	return nil
}

// ApplyAttestation accepts a request only when the host reports a ready,
// structured launch state that exactly matches it.  The response is generated
// from the state saved under the runtime UID, not by echoing arbitrary input.
func (agent *FarmAttestationAgent) ApplyAttestation(
	request FarmAttestationRequest,
	state FarmAttestationLaunchState,
) (FarmAttestationResponse, error) {
	if agent == nil {
		return FarmAttestationResponse{}, ErrFarmAttestationInvalid
	}
	if err := request.validate(); err != nil {
		return FarmAttestationResponse{}, err
	}
	if err := state.validate(); err != nil {
		return FarmAttestationResponse{}, err
	}
	if !attestationPolicyMatchesRuntime(request.Policy, state.AppliedRuntime) ||
		!equalAttestationRuntime(request.RuntimeConfig, state.AppliedRuntime) {
		return FarmAttestationResponse{}, ErrFarmAttestationStructuredMismatch
	}
	request = cloneFarmAttestationRequest(request)
	state = cloneFarmAttestationLaunchState(state)
	agent.mu.Lock()
	if agent.records == nil {
		agent.records = make(map[string]farmAttestationRecord)
	}
	agent.records[request.RuntimeIdentity.RuntimeUID] = farmAttestationRecord{request: request, state: state}
	agent.mu.Unlock()
	response := FarmAttestationResponse{
		Version:         FarmAttestationVersion,
		RuntimeIdentity: request.RuntimeIdentity,
		PolicyHash:      request.PolicyHash,
		ConfigHash:      request.ConfigHash,
		AppliedPolicy:   state.Policy,
		AppliedRuntime:  state.AppliedRuntime,
		Status:          "applied",
	}
	return cloneFarmAttestationResponse(response), nil
}

// Attest is a concise compatibility alias for Agent adapters.
func (agent *FarmAttestationAgent) Attest(request FarmAttestationRequest, state FarmAttestationLaunchState) (FarmAttestationResponse, error) {
	return agent.ApplyAttestation(request, state)
}

func (agent *FarmAttestationAgent) Snapshot(runtimeUID string) (FarmAttestationResponse, bool) {
	if agent == nil {
		return FarmAttestationResponse{}, false
	}
	agent.mu.RLock()
	record, ok := agent.records[runtimeUID]
	agent.mu.RUnlock()
	if !ok {
		return FarmAttestationResponse{}, false
	}
	response := FarmAttestationResponse{
		Version:         FarmAttestationVersion,
		RuntimeIdentity: record.request.RuntimeIdentity,
		PolicyHash:      record.request.PolicyHash,
		ConfigHash:      record.request.ConfigHash,
		AppliedPolicy:   record.state.Policy,
		AppliedRuntime:  record.state.AppliedRuntime,
		Status:          "applied",
	}
	return cloneFarmAttestationResponse(response), true
}

// VerifyFarmAttestationResponse is a non-authoritative Agent-side consistency
// check.  It compares opaque tokens byte-for-byte and checks every structured
// field; it intentionally does not calculate either hash.
func VerifyFarmAttestationResponse(request FarmAttestationRequest, response FarmAttestationResponse) error {
	if err := request.validate(); err != nil {
		return err
	}
	if err := response.validate(); err != nil {
		return err
	}
	if response.RuntimeIdentity != request.RuntimeIdentity {
		return ErrFarmAttestationIdentityMismatch
	}
	if !bytes.Equal([]byte(response.PolicyHash), []byte(request.PolicyHash)) ||
		!bytes.Equal([]byte(response.ConfigHash), []byte(request.ConfigHash)) {
		return ErrFarmAttestationTokenMismatch
	}
	if err := validateAttestationPolicy(response.AppliedPolicy); err != nil {
		return err
	}
	if err := validateAttestationRuntime(response.AppliedRuntime); err != nil {
		return err
	}
	if !attestationPolicyMatchesRuntime(response.AppliedPolicy, response.AppliedRuntime) ||
		!equalAttestationRuntime(request.RuntimeConfig, response.AppliedRuntime) {
		return ErrFarmAttestationStructuredMismatch
	}
	return nil
}

func attestationObject(raw []byte, name string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%w: %s must be an object", ErrFarmAttestationInvalid, name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%w: %s must be an object", ErrFarmAttestationInvalid, name)
	}
	return object, nil
}

func attestationKeySet(keys ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	return set
}

func validateAttestationObjectKeys(object map[string]json.RawMessage, allowed, required map[string]struct{}, name string) error {
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%w: %s contains unknown field", ErrFarmAttestationInvalid, name)
		}
	}
	for key := range required {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("%w: %s has missing field", ErrFarmAttestationInvalid, name)
		}
	}
	return nil
}

func validateAttestationJSONKind(raw json.RawMessage, kind byte, name string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("%w: %s has invalid type", ErrFarmAttestationInvalid, name)
	}
	first := trimmed[0]
	valid := first == kind
	if kind == '#' {
		valid = (first >= '0' && first <= '9') || first == '-'
	}
	if kind == 'b' {
		valid = first == 't' || first == 'f'
	}
	if !valid {
		return fmt.Errorf("%w: %s has invalid type", ErrFarmAttestationInvalid, name)
	}
	return nil
}

func validateAttestationStringArray(raw json.RawMessage, name string) error {
	if err := validateAttestationJSONKind(raw, '[', name); err != nil {
		return err
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("%w: %s has invalid type", ErrFarmAttestationInvalid, name)
	}
	for index, value := range values {
		if err := validateAttestationJSONKind(value, '"', fmt.Sprintf("%s[%d]", name, index)); err != nil {
			return err
		}
	}
	return nil
}

// validateFarmAttestationWireShape validates the closed schema before the Go
// decoder fills zero values for omitted/null fields. The generic runtime JSON
// walker already rejects duplicate and case-alias keys; this second pass
// enforces the exact request/response object shape used by the Server.
func validateFarmAttestationWireShape(raw []byte, response bool) error {
	root, err := attestationObject(raw, "attestation")
	if err != nil {
		return err
	}
	topKeys := attestationKeySet("version", "runtime_identity", "policy_hash", "config_hash")
	topRequired := attestationKeySet("version", "runtime_identity", "policy_hash", "config_hash")
	if response {
		topKeys["applied_policy"] = struct{}{}
		topKeys["applied_runtime"] = struct{}{}
		topKeys["restart_required"] = struct{}{}
		topKeys["status"] = struct{}{}
		topRequired["applied_policy"] = struct{}{}
		topRequired["applied_runtime"] = struct{}{}
	} else {
		topKeys["policy"] = struct{}{}
		topKeys["runtime_config"] = struct{}{}
		topRequired["policy"] = struct{}{}
		topRequired["runtime_config"] = struct{}{}
	}
	if err := validateAttestationObjectKeys(root, topKeys, topRequired, "attestation"); err != nil {
		return err
	}
	if err := validateAttestationJSONKind(root["version"], '#', "attestation.version"); err != nil {
		return err
	}
	for _, key := range []string{"policy_hash", "config_hash"} {
		if err := validateAttestationJSONKind(root[key], '"', "attestation."+key); err != nil {
			return err
		}
	}

	identity, err := attestationObject(root["runtime_identity"], "runtime_identity")
	if err != nil {
		return err
	}
	identityKeys := attestationKeySet(
		"node_uid", "profile_id", "runtime_uid", "provider_instance_id",
		"fencing_epoch", "config_hash", "generation",
	)
	if err := validateAttestationObjectKeys(identity, identityKeys, identityKeys, "runtime_identity"); err != nil {
		return err
	}
	for _, key := range []string{"node_uid", "profile_id", "runtime_uid", "provider_instance_id", "config_hash"} {
		if err := validateAttestationJSONKind(identity[key], '"', "runtime_identity."+key); err != nil {
			return err
		}
	}
	for _, key := range []string{"fencing_epoch", "generation"} {
		if err := validateAttestationJSONKind(identity[key], '#', "runtime_identity."+key); err != nil {
			return err
		}
	}

	policyKey := "policy"
	runtimeKey := "runtime_config"
	if response {
		policyKey = "applied_policy"
		runtimeKey = "applied_runtime"
	}
	policy, err := attestationObject(root[policyKey], policyKey)
	if err != nil {
		return err
	}
	policyKeys := attestationKeySet("allowed_domains", "locale", "timezone", "webrtc_mode")
	if err := validateAttestationObjectKeys(policy, policyKeys, policyKeys, policyKey); err != nil {
		return err
	}
	if err := validateAttestationStringArray(policy["allowed_domains"], policyKey+".allowed_domains"); err != nil {
		return err
	}
	for _, key := range []string{"locale", "timezone", "webrtc_mode"} {
		if err := validateAttestationJSONKind(policy[key], '"', policyKey+"."+key); err != nil {
			return err
		}
	}

	runtime, err := attestationObject(root[runtimeKey], runtimeKey)
	if err != nil {
		return err
	}
	runtimeKeys := attestationKeySet("allowed_domains", "locale", "timezone", "webrtc_mode", "proxy")
	if err := validateAttestationObjectKeys(runtime, runtimeKeys, runtimeKeys, runtimeKey); err != nil {
		return err
	}
	if err := validateAttestationStringArray(runtime["allowed_domains"], runtimeKey+".allowed_domains"); err != nil {
		return err
	}
	for _, key := range []string{"locale", "timezone", "webrtc_mode"} {
		if err := validateAttestationJSONKind(runtime[key], '"', runtimeKey+"."+key); err != nil {
			return err
		}
	}
	proxy, err := attestationObject(runtime["proxy"], runtimeKey+".proxy")
	if err != nil {
		return err
	}
	proxyKeys := attestationKeySet("enabled", "connector_type", "credential_revision", "config_revision")
	if err := validateAttestationObjectKeys(proxy, proxyKeys, proxyKeys, runtimeKey+".proxy"); err != nil {
		return err
	}
	if err := validateAttestationJSONKind(proxy["enabled"], 'b', runtimeKey+".proxy.enabled"); err != nil {
		return err
	}
	for _, key := range []string{"connector_type", "credential_revision", "config_revision"} {
		if err := validateAttestationJSONKind(proxy[key], '"', runtimeKey+".proxy."+key); err != nil {
			return err
		}
	}
	if response {
		if rawStatus, ok := root["status"]; ok {
			if err := validateAttestationJSONKind(rawStatus, '"', "attestation.status"); err != nil {
				return err
			}
		}
		if rawRestart, ok := root["restart_required"]; ok {
			if err := validateAttestationJSONKind(rawRestart, 'b', "attestation.restart_required"); err != nil {
				return err
			}
		}
	}
	return nil
}

func DecodeFarmAttestationRequest(raw []byte) (FarmAttestationRequest, error) {
	if len(raw) == 0 || len(raw) > maxFarmRuntimeEnvelopeBytes {
		return FarmAttestationRequest{}, ErrFarmAttestationInvalid
	}
	if !utf8.Valid(raw) {
		return FarmAttestationRequest{}, fmt.Errorf("%w: request is not valid UTF-8", ErrFarmAttestationInvalid)
	}
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return FarmAttestationRequest{}, fmt.Errorf("%w: invalid request JSON", ErrFarmAttestationInvalid)
	}
	if err := validateFarmAttestationWireShape(raw, false); err != nil {
		return FarmAttestationRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request FarmAttestationRequest
	if err := decoder.Decode(&request); err != nil {
		return FarmAttestationRequest{}, fmt.Errorf("%w: %v", ErrFarmAttestationInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return FarmAttestationRequest{}, fmt.Errorf("%w: trailing request JSON", ErrFarmAttestationInvalid)
	} else if !errors.Is(err, io.EOF) {
		return FarmAttestationRequest{}, fmt.Errorf("%w: invalid request tail", ErrFarmAttestationInvalid)
	}
	if err := request.validate(); err != nil {
		return FarmAttestationRequest{}, err
	}
	return request, nil
}

func DecodeFarmAttestationResponse(raw []byte) (FarmAttestationResponse, error) {
	if len(raw) == 0 || len(raw) > maxFarmRuntimeEnvelopeBytes {
		return FarmAttestationResponse{}, ErrFarmAttestationInvalid
	}
	if !utf8.Valid(raw) {
		return FarmAttestationResponse{}, fmt.Errorf("%w: response is not valid UTF-8", ErrFarmAttestationInvalid)
	}
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return FarmAttestationResponse{}, fmt.Errorf("%w: invalid response JSON", ErrFarmAttestationInvalid)
	}
	if err := validateFarmAttestationWireShape(raw, true); err != nil {
		return FarmAttestationResponse{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response FarmAttestationResponse
	if err := decoder.Decode(&response); err != nil {
		return FarmAttestationResponse{}, fmt.Errorf("%w: %v", ErrFarmAttestationInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return FarmAttestationResponse{}, fmt.Errorf("%w: trailing response JSON", ErrFarmAttestationInvalid)
	} else if !errors.Is(err, io.EOF) {
		return FarmAttestationResponse{}, fmt.Errorf("%w: invalid response tail", ErrFarmAttestationInvalid)
	}
	if err := response.validate(); err != nil {
		return FarmAttestationResponse{}, err
	}
	return response, nil
}

// ControlledRestartSelector creates the only selector permitted for a stale
// runtime: the exact old owned identity.  It never creates a replacement UID
// and cannot target an unowned runtime.
func ControlledRestartSelector(identity FarmRuntimeIdentity, owned bool) (FarmRuntimeStopRequest, error) {
	if !owned {
		return FarmRuntimeStopRequest{}, ErrFarmAttestationUnownedRestart
	}
	if err := validateAttestationIdentity(identity); err != nil {
		return FarmRuntimeStopRequest{}, err
	}
	return FarmRuntimeStopRequest{
		NodeUID:            identity.NodeUID,
		ProfileID:          identity.ProfileID,
		RuntimeUID:         identity.RuntimeUID,
		ProviderInstanceID: identity.ProviderInstanceID,
		FencingEpoch:       identity.FencingEpoch,
		ConfigHash:         identity.ConfigHash,
		Generation:         identity.Generation,
	}, nil
}

// SortAttestationDomains is a non-hashing helper for host adapters that need
// to present a deterministic field order.  It preserves every Unicode/IDN
// spelling and does not convert labels to punycode.
func SortAttestationDomains(domains []string) []string {
	result := append([]string(nil), domains...)
	sort.Strings(result)
	return result
}
