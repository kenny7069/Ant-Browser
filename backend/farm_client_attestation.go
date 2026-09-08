package backend

import (
	"strings"
	"sync"
)

// farmClientCapturedLaunch is the local evidence captured at the process
// boundary. It is never serialized or returned to the controller.
type farmClientCapturedLaunch struct {
	spec       BrowserRuntimeLaunchSpec
	pid        int
	generation uint64
}

type farmClientLaunchCapture struct {
	mu      sync.RWMutex
	entries map[string]farmClientCapturedLaunch
}

func newFarmClientLaunchCapture() *farmClientLaunchCapture {
	return &farmClientLaunchCapture{entries: make(map[string]farmClientCapturedLaunch)}
}

func cloneFarmClientLaunchSpec(spec BrowserRuntimeLaunchSpec) BrowserRuntimeLaunchSpec {
	spec.Args = append([]string(nil), spec.Args...)
	spec.DeferredStartTargets = append([]string(nil), spec.DeferredStartTargets...)
	return spec
}

func (c *farmClientLaunchCapture) CaptureStart(profileID string, spec BrowserRuntimeLaunchSpec, pid int) {
	if c == nil || strings.TrimSpace(profileID) == "" || pid <= 0 {
		return
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]farmClientCapturedLaunch)
	}
	c.entries[strings.TrimSpace(profileID)] = farmClientCapturedLaunch{spec: cloneFarmClientLaunchSpec(spec), pid: pid}
	c.mu.Unlock()
}

func (c *farmClientLaunchCapture) MarkGeneration(profileID string, generation uint64) {
	if c == nil || generation == 0 {
		return
	}
	c.mu.Lock()
	entry, ok := c.entries[strings.TrimSpace(profileID)]
	if ok {
		entry.generation = generation
		c.entries[strings.TrimSpace(profileID)] = entry
	}
	c.mu.Unlock()
}

func (c *farmClientLaunchCapture) ClearGeneration(profileID string, generation uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	key := strings.TrimSpace(profileID)
	if entry, ok := c.entries[key]; ok && (generation == 0 || entry.generation == generation) {
		delete(c.entries, key)
	}
	c.mu.Unlock()
}

func (c *farmClientLaunchCapture) Snapshot(profileID string) (farmClientCapturedLaunch, bool) {
	if c == nil {
		return farmClientCapturedLaunch{}, false
	}
	c.mu.RLock()
	entry, ok := c.entries[strings.TrimSpace(profileID)]
	c.mu.RUnlock()
	if !ok {
		return farmClientCapturedLaunch{}, false
	}
	entry.spec = cloneFarmClientLaunchSpec(entry.spec)
	return entry, true
}

func newFarmClientAttestationProvider(runtimeService *BrowserRuntimeService, capture *farmClientLaunchCapture) func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
	return func(identity FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
		if runtimeService == nil || capture == nil || strings.TrimSpace(identity.ProfileID) == "" || identity.Generation == 0 {
			return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
		}
		captured, ok := capture.Snapshot(identity.ProfileID)
		if !ok || captured.generation == 0 || captured.generation != identity.Generation || captured.pid <= 0 || captured.spec.ProfileID != identity.ProfileID {
			return FarmAttestationLaunchState{}, ErrFarmAttestationIdentityMismatch
		}
		snapshot, err := runtimeService.RuntimeSnapshot(identity.ProfileID)
		if err != nil {
			return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
		}
		if snapshot == nil || snapshot.Profile == nil || snapshot.Generation != identity.Generation ||
			!snapshot.Profile.Running || !snapshot.Profile.DebugReady || snapshot.Profile.Pid != captured.pid ||
			snapshot.Profile.DebugPort <= 0 || captured.spec.AssignedDebugPort != snapshot.Profile.DebugPort {
			return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
		}

		// Use the same final-argument normalization as the existing browser
		// fingerprint capability report. This keeps attestation aligned with
		// the launch plan when an argument is intentionally repeated.
		expected := buildBrowserFingerprintExpected(captured.spec.Args)
		policy := FarmAttestationPolicy{
			AllowedDomains: []string{},
			Locale:         expected.Language,
			Timezone:       expected.Timezone,
			WebRTCMode:     expected.WebRTCPolicy,
		}
		applied := FarmAttestationRuntime{AllowedDomains: []string{}, Locale: policy.Locale, Timezone: policy.Timezone, WebRTCMode: policy.WebRTCMode}
		switch strings.TrimSpace(captured.spec.EffectiveProxy) {
		case "direct://":
			if !farmClientHasFlag(captured.spec.Args, "--no-proxy-server") {
				return FarmAttestationLaunchState{}, ErrFarmAttestationStructuredMismatch
			}
		case "":
			return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
		default:
			if !farmClientHasArg(captured.spec.Args, "--proxy-server") {
				return FarmAttestationLaunchState{}, ErrFarmAttestationStructuredMismatch
			}
			binding, bindingErr := runtimeService.LocalProfileProxyBinding(identity.ProfileID)
			if bindingErr != nil || !binding.Enabled || strings.TrimSpace(binding.ConnectorType) == "" {
				return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
			}
			applied.Proxy = FarmAttestationProxy{
				Enabled: true, ConnectorType: binding.ConnectorType,
				CredentialRevision: binding.CredentialRevision, ConfigRevision: binding.ConfigRevision,
			}
		}
		return FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: applied}, nil
	}
}

func farmClientHasArg(args []string, key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, arg := range args {
		arg = strings.ToLower(strings.TrimSpace(arg))
		if arg == key || strings.HasPrefix(arg, key+"=") {
			return true
		}
	}
	return false
}

func farmClientHasFlag(args []string, key string) bool {
	return farmClientHasArg(args, key)
}
