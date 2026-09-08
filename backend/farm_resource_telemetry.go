package backend

// Resource telemetry is the only Agent -> Server projection of host memory,
// runtime RSS and Control RTT.  It is intentionally a closed data contract:
// no process command line, user-data path, proxy material, launch argument or
// arbitrary error can be represented here.

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	proxyinternal "ant-chrome/backend/internal/proxy"
)

const (
	FarmResourceTelemetryVersion = 1
	FarmRTTHealthyMaxMS          = 50.0
	FarmRTTAcceptableMaxMS       = 100.0
	FarmRTTDegradedMaxMS         = 200.0
	FarmRTTSoftDrainAfter        = 5 * time.Minute
	FarmRTTHealthyClass          = "healthy"
	FarmRTTAcceptableClass       = "acceptable"
	FarmRTTDegradedClass         = "degraded"
	FarmRTTNoPlacementClass      = "no_placement"
	FarmRTTUnknownClass          = "unknown"
)

var ErrFarmResourceTelemetryInvalid = errors.New("farm resource telemetry invalid")

// FarmNodeMemoryTelemetry is a small, platform-neutral memory summary.  The
// Agent may report unknown values as zero; the health classification remains
// explicit so the Server never treats a missing sample as healthy.
type FarmNodeMemoryTelemetry struct {
	TotalMB     int64   `json:"total_mb,omitempty"`
	AvailableMB int64   `json:"available_mb,omitempty"`
	UsedPercent float64 `json:"used_percent,omitempty"`
	SwapUsedMB  int64   `json:"swap_used_mb,omitempty"`
	Health      string  `json:"health"`
}

// FarmRuntimeResourceTelemetry is bound to one strict Farm runtime identity.
// RSS is the Agent-observed process tree RSS, not a Server-side PID lookup.
type FarmRuntimeResourceTelemetry struct {
	NodeUID              string `json:"node_uid"`
	ProfileID            string `json:"profile_id"`
	RuntimeUID           string `json:"runtime_uid"`
	Provider             string `json:"provider"`
	ProviderInstanceID   string `json:"provider_instance_id"`
	FencingEpoch         uint64 `json:"fencing_epoch"`
	Generation           uint64 `json:"generation"`
	ConfigHash           string `json:"config_hash"`
	ControllerID         string `json:"controller_id"`
	ControllerGeneration uint64 `json:"controller_generation"`
	PID                  int    `json:"pid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	ProfileIncarnation   string `json:"profile_incarnation"`
	RSSMB                int64  `json:"rss_mb,omitempty"`
	RSSValid             bool   `json:"rss_valid"`
	State                string `json:"state"`
	Health               string `json:"health"`
	ObservedAt           string `json:"observed_at"`
}

// FarmResourceTelemetry is sent nested inside an authenticated heartbeat.
// The Server accepts only this projection and treats the WSS session identity
// as the authority for node_uid/device ownership.
type FarmResourceTelemetry struct {
	Version              int                            `json:"version"`
	NodeUID              string                         `json:"node_uid"`
	Provider             string                         `json:"provider"`
	ProviderInstanceID   string                         `json:"provider_instance_id"`
	FencingEpoch         uint64                         `json:"fencing_epoch"`
	ControllerID         string                         `json:"controller_id"`
	ControllerGeneration uint64                         `json:"controller_generation"`
	ConnectionGeneration uint64                         `json:"connection_generation"`
	SampleSequence       uint64                         `json:"sample_sequence"`
	ObservedAt           string                         `json:"observed_at"`
	ControlRTTMS         float64                        `json:"control_rtt_ms,omitempty"`
	RTTClass             string                         `json:"rtt_class"`
	NodeMemory           FarmNodeMemoryTelemetry        `json:"node_memory"`
	Runtimes             []FarmRuntimeResourceTelemetry `json:"runtimes,omitempty"`
}

// FarmResourceTelemetryHooks are test seams and host overrides.  Production
// defaults use /proc, vm_stat and a bounded Agent-local ps table.  A hook may
// report an error; ResourceTelemetry then emits an explicit unknown health
// rather than putting an error string on the wire.
type FarmResourceTelemetryHooks struct {
	Now             func() time.Time
	NodeMemory      func() (FarmNodeMemoryTelemetry, error)
	ProcessRSS      func(pid int) (int64, error)
	ProcessIdentity func(pid int) (string, error)
}

func ClassifyFarmRTT(rttMS float64) string {
	if math.IsNaN(rttMS) || math.IsInf(rttMS, 0) || rttMS < 0 {
		return FarmRTTUnknownClass
	}
	switch {
	case rttMS <= FarmRTTHealthyMaxMS:
		return FarmRTTHealthyClass
	case rttMS <= FarmRTTAcceptableMaxMS:
		return FarmRTTAcceptableClass
	case rttMS <= FarmRTTDegradedMaxMS:
		return FarmRTTDegradedClass
	default:
		return FarmRTTNoPlacementClass
	}
}

func resourceTelemetryNow(hooks *FarmResourceTelemetryHooks) time.Time {
	if hooks != nil && hooks.Now != nil {
		if value := hooks.Now(); !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func normalizeTelemetryHealth(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "healthy", "acceptable", "degraded", "critical", "unknown":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func defaultNodeMemoryTelemetry() (FarmNodeMemoryTelemetry, error) {
	switch runtime.GOOS {
	case "linux":
		return linuxNodeMemoryTelemetry()
	case "darwin":
		return darwinNodeMemoryTelemetry()
	default:
		return FarmNodeMemoryTelemetry{Health: "unknown"}, fmt.Errorf("node memory unsupported")
	}
}

func memoryHealth(totalMB, availableMB int64) string {
	if totalMB <= 0 || availableMB < 0 || availableMB > totalMB {
		return "unknown"
	}
	availablePercent := (float64(availableMB) / float64(totalMB)) * 100
	switch {
	case availablePercent >= 20:
		return "healthy"
	case availablePercent >= 10:
		return "degraded"
	default:
		return "critical"
	}
}

func linuxNodeMemoryTelemetry() (FarmNodeMemoryTelemetry, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return FarmNodeMemoryTelemetry{Health: "unknown"}, err
	}
	defer file.Close()
	values := map[string]int64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		value, parseErr := strconv.ParseInt(parts[1], 10, 64)
		if parseErr != nil || value < 0 {
			continue
		}
		values[strings.TrimSuffix(parts[0], ":")] = value
	}
	if err := scanner.Err(); err != nil {
		return FarmNodeMemoryTelemetry{Health: "unknown"}, err
	}
	total := values["MemTotal"] / 1024
	available := values["MemAvailable"] / 1024
	swap := values["SwapTotal"] - values["SwapFree"]
	if swap > 0 {
		swap /= 1024
	}
	health := memoryHealth(total, available)
	if total <= 0 || available < 0 {
		return FarmNodeMemoryTelemetry{Health: "unknown"}, fmt.Errorf("node memory fields unavailable")
	}
	return FarmNodeMemoryTelemetry{
		TotalMB: total, AvailableMB: available,
		UsedPercent: (1 - float64(available)/float64(total)) * 100,
		SwapUsedMB:  swap, Health: health,
	}, nil
}

func darwinNodeMemoryTelemetry() (FarmNodeMemoryTelemetry, error) {
	// Keep the Darwin path deliberately small and secret-free.  vm_stat is the
	// same host primitive used by the Server's local watchdog, but it executes
	// here on the Agent host; the Server never shells out for remote telemetry.
	totalRaw, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return FarmNodeMemoryTelemetry{Health: "unknown"}, err
	}
	totalBytes, err := strconv.ParseInt(strings.TrimSpace(string(totalRaw)), 10, 64)
	if err != nil || totalBytes <= 0 {
		return FarmNodeMemoryTelemetry{Health: "unknown"}, fmt.Errorf("node total memory invalid")
	}
	output, err := exec.Command("vm_stat").Output()
	if err != nil {
		return FarmNodeMemoryTelemetry{Health: "unknown"}, err
	}
	pageSize := int64(4096)
	free, inactive, speculative := int64(0), int64(0), int64(0)
	for _, line := range strings.Split(string(output), "\n") {
		if marker := strings.Index(line, "page size of"); marker >= 0 {
			fields := strings.Fields(line[marker+len("page size of"):])
			if len(fields) > 0 {
				if parsed, parseErr := strconv.ParseInt(fields[0], 10, 64); parseErr == nil && parsed > 0 {
					pageSize = parsed
				}
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))
		value = strings.ReplaceAll(value, ".", "")
		pages, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || pages < 0 {
			continue
		}
		switch strings.TrimSpace(parts[0]) {
		case "Pages free":
			free = pages
		case "Pages inactive":
			inactive = pages
		case "Pages speculative":
			speculative = pages
		}
	}
	availableBytes := (free + inactive + speculative) * pageSize
	totalMB := totalBytes / (1024 * 1024)
	availableMB := availableBytes / (1024 * 1024)
	return FarmNodeMemoryTelemetry{
		TotalMB: totalMB, AvailableMB: availableMB,
		UsedPercent: (1 - float64(availableMB)/float64(totalMB)) * 100,
		Health:      memoryHealth(totalMB, availableMB),
	}, nil
}

func defaultProcessTreeRSS(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid process id")
	}
	if runtime.GOOS == "windows" {
		return 0, fmt.Errorf("process rss unsupported")
	}
	output, err := exec.Command("ps", "-axo", "pid=,ppid=,rss=").Output()
	if err != nil {
		return 0, err
	}
	type processRow struct{ parent, rss int64 }
	rows := map[int64]processRow{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		processID, e1 := strconv.ParseInt(fields[0], 10, 64)
		parentID, e2 := strconv.ParseInt(fields[1], 10, 64)
		rssKB, e3 := strconv.ParseInt(fields[2], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || processID <= 0 || rssKB < 0 {
			continue
		}
		rows[processID] = processRow{parent: parentID, rss: rssKB}
	}
	if _, ok := rows[int64(pid)]; !ok {
		return 0, fmt.Errorf("process not found")
	}
	children := map[int64][]int64{}
	for processID, row := range rows {
		children[row.parent] = append(children[row.parent], processID)
	}
	stack := []int64{int64(pid)}
	seen := map[int64]struct{}{}
	var totalKB int64
	for len(stack) > 0 {
		last := len(stack) - 1
		processID := stack[last]
		stack = stack[:last]
		if _, ok := seen[processID]; ok {
			continue
		}
		seen[processID] = struct{}{}
		row, ok := rows[processID]
		if !ok {
			continue
		}
		totalKB += row.rss
		stack = append(stack, children[processID]...)
	}
	return totalKB / 1024, nil
}

func defaultProcessStartIdentity(pid int) (string, error) {
	return proxyinternal.ProcessStartIdentityForPID(pid)
}

func (s *FarmRuntimeService) readProcessStartIdentity(pid int) (string, error) {
	reader := defaultProcessStartIdentity
	if s != nil && s.resourceTelemetryHooks != nil && s.resourceTelemetryHooks.ProcessIdentity != nil {
		reader = s.resourceTelemetryHooks.ProcessIdentity
	}
	return reader(pid)
}

func (s *FarmRuntimeService) ResourceTelemetry(controlRTTMS float64) (FarmResourceTelemetry, error) {
	if s == nil {
		return FarmResourceTelemetry{}, ErrFarmRuntimeServiceUnavailable
	}
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	controllerID, controllerGeneration := s.controllerBinding()
	connectionGeneration := s.ConnectionGeneration()
	if math.IsNaN(controlRTTMS) || math.IsInf(controlRTTMS, 0) || controlRTTMS < 0 {
		controlRTTMS = -1
	}
	now := resourceTelemetryNow(s.resourceTelemetryHooks)
	memory := FarmNodeMemoryTelemetry{Health: "unknown"}
	if s.resourceTelemetryHooks != nil && s.resourceTelemetryHooks.NodeMemory != nil {
		if value, err := s.resourceTelemetryHooks.NodeMemory(); err == nil {
			memory = value
		}
	} else if value, err := defaultNodeMemoryTelemetry(); err == nil {
		memory = value
	}
	memory.Health = normalizeTelemetryHealth(memory.Health)
	if memory.TotalMB < 0 || memory.AvailableMB < 0 || memory.SwapUsedMB < 0 ||
		((memory.TotalMB == 0 && memory.AvailableMB > 0) || (memory.TotalMB > 0 && memory.AvailableMB > memory.TotalMB)) ||
		math.IsNaN(memory.UsedPercent) || math.IsInf(memory.UsedPercent, 0) ||
		memory.UsedPercent < 0 || memory.UsedPercent > 100 {
		memory = FarmNodeMemoryTelemetry{Health: "unknown"}
	}

	s.recordsMu.RLock()
	profileIDs := make([]string, 0, len(s.records))
	for profileID := range s.records {
		profileIDs = append(profileIDs, profileID)
	}
	s.recordsMu.RUnlock()
	sort.Strings(profileIDs)
	runtimes := make([]FarmRuntimeResourceTelemetry, 0, len(profileIDs))
	for _, profileID := range profileIDs {
		record, ok := s.currentRecord(profileID)
		if !ok || record.runtime.State == FarmRuntimeStateStopped || record.runtime.State == FarmRuntimeStateCrashed || record.runtime.State == FarmRuntimeStateStale {
			continue
		}
		pid := record.runtime.PID
		observedGeneration := record.runtime.Generation
		profileIncarnation := ""
		if snapshot, err := s.snapshot(profileID); err == nil && snapshot != nil && snapshot.Profile != nil && snapshot.Profile.Pid > 0 && snapshot.Generation == record.runtime.Generation {
			pid = snapshot.Profile.Pid
			observedGeneration = snapshot.Generation
			profileIncarnation = snapshot.ProfileIncarnation
		} else if s.runtimeService != nil {
			return FarmResourceTelemetry{}, ErrFarmResourceTelemetryInvalid
		}
		rss := int64(0)
		rssValid := false
		processStartIdentity := ""
		if pid > 0 {
			reader := defaultProcessTreeRSS
			if s.resourceTelemetryHooks != nil && s.resourceTelemetryHooks.ProcessRSS != nil {
				reader = s.resourceTelemetryHooks.ProcessRSS
			}
			beforeIdentity, identityErr := s.readProcessStartIdentity(pid)
			if identityErr == nil && beforeIdentity != "" && record.processStartIdentity != "" && beforeIdentity == record.processStartIdentity {
				value, rssErr := reader(pid)
				if rssErr == nil && value > 0 {
					afterIdentity, afterIdentityErr := s.readProcessStartIdentity(pid)
					if s.runtimeService == nil {
						if afterIdentityErr == nil && afterIdentity == beforeIdentity {
							rss = value
							rssValid = true
							processStartIdentity = beforeIdentity
						}
					} else if after, afterErr := s.snapshot(profileID); afterErr == nil && after != nil && after.Profile != nil && after.Profile.Pid == pid && after.Generation == observedGeneration && after.ProfileIncarnation == profileIncarnation && profileIncarnation != "" && afterIdentityErr == nil && afterIdentity == beforeIdentity {
						rss = value
						rssValid = true
						processStartIdentity = beforeIdentity
					}
				}
			}
		}
		runtimes = append(runtimes, FarmRuntimeResourceTelemetry{
			NodeUID: s.nodeUID, ProfileID: record.runtime.ProfileID,
			RuntimeUID: record.runtime.RuntimeUID, Provider: "farm",
			ProviderInstanceID: s.providerInstance, FencingEpoch: s.fencingEpoch,
			Generation:   record.runtime.Generation,
			ConfigHash:   record.runtime.ConfigHash,
			ControllerID: controllerID, ControllerGeneration: controllerGeneration,
			PID: pid, ProcessStartIdentity: processStartIdentity, ProfileIncarnation: profileIncarnation,
			RSSMB: rss, RSSValid: rssValid, State: record.runtime.State,
			Health: memory.Health, ObservedAt: now.Format(time.RFC3339Nano),
		})
	}
	sequence := atomic.AddUint64(&s.resourceTelemetrySequence, 1)
	telemetry := FarmResourceTelemetry{
		Version: FarmResourceTelemetryVersion, NodeUID: s.nodeUID,
		Provider: "farm", ProviderInstanceID: s.providerInstance,
		FencingEpoch: s.fencingEpoch, ControllerID: controllerID,
		ControllerGeneration: controllerGeneration,
		ConnectionGeneration: connectionGeneration, SampleSequence: sequence,
		ObservedAt:   now.Format(time.RFC3339Nano),
		ControlRTTMS: 0, RTTClass: FarmRTTUnknownClass,
		NodeMemory: memory, Runtimes: runtimes,
	}
	if controlRTTMS >= 0 {
		telemetry.ControlRTTMS = controlRTTMS
		telemetry.RTTClass = ClassifyFarmRTT(controlRTTMS)
	}
	if err := ValidateFarmResourceTelemetry(telemetry); err != nil {
		return FarmResourceTelemetry{}, err
	}
	return telemetry, nil
}

func (adapter *FarmRuntimeControlAdapter) AcknowledgeResourceTelemetry(sequence uint64, observedAt string) {
	if adapter == nil || adapter.service == nil || sequence == 0 || observedAt == "" {
		return
	}
	adapter.service.resourceTelemetryMu.Lock()
	if sequence > adapter.service.latestResourceSequence {
		adapter.service.latestResourceSequence = sequence
		adapter.service.latestResourceObservedAt = observedAt
	}
	adapter.service.resourceTelemetryMu.Unlock()
}

func ValidateFarmResourceTelemetry(value FarmResourceTelemetry) error {
	if value.Version != FarmResourceTelemetryVersion || strings.TrimSpace(value.NodeUID) == "" || value.Provider != "farm" || strings.TrimSpace(value.ProviderInstanceID) == "" || value.FencingEpoch == 0 || strings.TrimSpace(value.ControllerID) == "" || value.ControllerGeneration == 0 || value.SampleSequence == 0 {
		return ErrFarmResourceTelemetryInvalid
	}
	if _, err := time.Parse(time.RFC3339Nano, value.ObservedAt); err != nil {
		return ErrFarmResourceTelemetryInvalid
	}
	if value.NodeMemory.TotalMB < 0 || value.NodeMemory.AvailableMB < 0 || value.NodeMemory.SwapUsedMB < 0 ||
		((value.NodeMemory.TotalMB == 0 && value.NodeMemory.AvailableMB > 0) || (value.NodeMemory.TotalMB > 0 && value.NodeMemory.AvailableMB > value.NodeMemory.TotalMB)) ||
		math.IsNaN(value.NodeMemory.UsedPercent) || math.IsInf(value.NodeMemory.UsedPercent, 0) ||
		value.NodeMemory.UsedPercent < 0 || value.NodeMemory.UsedPercent > 100 ||
		!validResourceHealth(value.NodeMemory.Health) {
		return ErrFarmResourceTelemetryInvalid
	}
	if value.RTTClass == FarmRTTUnknownClass && value.ControlRTTMS == 0 {
		// Zero is omitted by encoding/json while no RTT sample exists. A real
		// measured zero is healthy and therefore carries the healthy class.
	} else if value.ControlRTTMS < 0 || math.IsNaN(value.ControlRTTMS) || math.IsInf(value.ControlRTTMS, 0) {
		return ErrFarmResourceTelemetryInvalid
	} else if value.RTTClass != ClassifyFarmRTT(value.ControlRTTMS) {
		return ErrFarmResourceTelemetryInvalid
	}
	for _, runtimeTelemetry := range value.Runtimes {
		if runtimeTelemetry.NodeUID != value.NodeUID || runtimeTelemetry.Provider != "farm" || runtimeTelemetry.ProviderInstanceID != value.ProviderInstanceID || runtimeTelemetry.FencingEpoch != value.FencingEpoch || runtimeTelemetry.ControllerID != value.ControllerID || runtimeTelemetry.ControllerGeneration != value.ControllerGeneration || strings.TrimSpace(runtimeTelemetry.ProfileID) == "" || strings.TrimSpace(runtimeTelemetry.RuntimeUID) == "" || runtimeTelemetry.Generation == 0 || runtimeTelemetry.PID <= 0 || strings.TrimSpace(runtimeTelemetry.ProcessStartIdentity) == "" {
			return ErrFarmResourceTelemetryInvalid
		}
		if !runtimeTelemetry.RSSValid || runtimeTelemetry.RSSMB <= 0 || !validResourceHealth(runtimeTelemetry.Health) || !validRuntimeTelemetryState(runtimeTelemetry.State) {
			return ErrFarmResourceTelemetryInvalid
		}
		if _, err := time.Parse(time.RFC3339Nano, runtimeTelemetry.ObservedAt); err != nil {
			return ErrFarmResourceTelemetryInvalid
		}
	}
	return nil
}

func validRuntimeTelemetryState(value string) bool {
	switch value {
	case FarmRuntimeStateStarting, FarmRuntimeStateIdle:
		return true
	default:
		return false
	}
}

func validResourceHealth(value string) bool {
	switch value {
	case "healthy", "acceptable", "degraded", "critical", "unknown":
		return true
	default:
		return false
	}
}
