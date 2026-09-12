package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
)

type SuiteDoctorLayer struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Code        string `json:"code"`
	SafeMessage string `json:"safe_message,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}
type SuiteDoctorReport struct {
	SchemaVersion int                `json:"schema_version"`
	Overall       string             `json:"overall"`
	ExitClass     string             `json:"exit_class"`
	DominantCode  string             `json:"dominant_code"`
	Layers        []SuiteDoctorLayer `json:"layers"`
}

func DoctorSuite(ctx context.Context, roots SuiteUserRoots) SuiteDoctorReport {
	return doctorSuiteWithPlatform(ctx, roots, newSuiteServicePlatform())
}

func doctorSuiteWithPlatform(ctx context.Context, roots SuiteUserRoots, platform suiteServicePlatform) (report SuiteDoctorReport) {
	report = SuiteDoctorReport{SchemaVersion: 1, Overall: "NOT_READY", ExitClass: "DEFERRED", DominantCode: "CHECK_NOT_IMPLEMENTED"}
	defer classifySuiteDoctorReport(&report)
	add := func(name, status, code string, retry bool) {
		report.Layers = append(report.Layers, SuiteDoctorLayer{Name: name, Status: status, Code: code, SafeMessage: code, Remediation: "RUN_SETUP_OR_DOCTOR", Retryable: retry})
	}
	block := func(names ...string) {
		for _, name := range names {
			add(name, "BLOCKED", "PREREQUISITE_BLOCKED", false)
		}
	}
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil {
		add("install_release", "FAIL", "INSTALL_EVIDENCE_INVALID", false)
		block("handoff_config_identity", "session_display", "dns_tcp", "tls", "discovery", "enrollment", "registration", "resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	add("install_release", "PASS", "INSTALLED_RELEASE_VERIFIED", false)
	add("handoff_config_identity", "PASS", "OWNERSHIP_EVIDENCE_VERIFIED", false)
	for _, name := range []string{"session_display", "dns_tcp", "tls", "discovery"} {
		add(name, "UNKNOWN", "CHECK_NOT_IMPLEMENTED", false)
	}
	checkpoint, checkpointErr := LoadSetupCheckpoint(filepath.Join(roots.AgentState, "setup.json"))
	if checkpointErr != nil {
		add("enrollment", "FAIL", "CHECKPOINT_INVALID", false)
		block("registration", "resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	if checkpoint == nil || setupStageIndex(checkpoint.Stage) < setupStageIndex(SetupEnrolled) || checkpoint.RequestUID != handoff.SetupRequestUID {
		add("enrollment", "FAIL", "ENROLLMENT_NOT_CONFIRMED", true)
		block("registration", "resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	add("enrollment", "PASS", "ENROLLED", false)
	journal, journalErr := LoadSuiteActivationJournal(roots)
	registered := journalErr == nil && journal != nil && journal.Stage != SuiteActivationReconcileRequired && suiteActivationStageIndex(journal.Stage) >= suiteActivationStageIndex(SuiteActivationTaskAudited) && journal.RequestUID == handoff.SetupRequestUID && journal.ClientConfigSHA256 == handoff.ClientConfigSHA256 && journal.ManifestSHA256 == handoff.ManifestSHA256 && journal.SetupStageID == handoff.SetupStageID
	if !registered {
		add("registration", "FAIL", "REGISTRATION_NOT_CONFIRMED", true)
		block("resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	identity, observeErr := platform.ValidateInstall(*handoff)
	digest := sha256.Sum256([]byte(identity))
	if observeErr != nil || strings.TrimSpace(identity) == "" || hex.EncodeToString(digest[:]) != journal.TaskIdentityDigest {
		add("registration", "UNKNOWN", "REGISTRATION_OBSERVATION_DEFERRED", false)
		block("resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	wantRegistration := suiteServiceRegistrationExactDisabled
	if suiteActivationStageIndex(journal.Stage) >= suiteActivationStageIndex(SuiteActivationEnabled) {
		wantRegistration = suiteServiceRegistrationExactEnabled
	}
	observedRegistration, inspectErr := platform.InspectRegistration(*handoff, identity)
	if inspectErr != nil {
		add("registration", "UNKNOWN", "REGISTRATION_OBSERVATION_DEFERRED", false)
		block("resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	if observedRegistration != wantRegistration {
		add("registration", "FAIL", "REGISTRATION_AUDIT_FAILED", true)
		block("resident_ipc", "control", "browser_smoke", "ready")
		return report
	}
	add("registration", "PASS", "REGISTRATION_OBSERVED", false)
	if suiteResidentProof(ctx, handoff.ClientConfigPath) != nil {
		add("resident_ipc", "FAIL", "IPC_PROOF_FAILED", true)
		block("control", "browser_smoke", "ready")
		return report
	}
	add("resident_ipc", "PASS", "RESIDENT_PROVED", false)
	levels := []struct {
		name  string
		stage SetupStage
		fail  string
	}{{"control", SetupControlAuthenticated, "CONTROL_NOT_CONFIRMED"}, {"browser_smoke", SetupBrowserSmokePassed, "BROWSER_SMOKE_NOT_CONFIRMED"}, {"ready", SetupReadyForManagement, "READY_NOT_CONFIRMED"}}
	for i, level := range levels {
		if setupStageIndex(checkpoint.Stage) < setupStageIndex(level.stage) {
			add(level.name, "FAIL", level.fail, true)
			for _, rest := range levels[i+1:] {
				add(rest.name, "BLOCKED", "PREREQUISITE_BLOCKED", false)
			}
			return report
		}
		add(level.name, "PASS", "CONFIRMED", false)
	}
	report.Overall = "READY"
	for _, layer := range report.Layers {
		if layer.Status != "PASS" {
			report.Overall = "NOT_READY"
			break
		}
	}
	return report
}

func classifySuiteDoctorReport(report *SuiteDoctorReport) {
	if report == nil {
		return
	}
	for _, layer := range report.Layers {
		if layer.Status != "FAIL" {
			continue
		}
		report.DominantCode = layer.Code
		switch layer.Name {
		case "dns_tcp", "tls", "discovery":
			report.ExitClass = "NETWORK_TLS"
		case "enrollment":
			report.ExitClass = "ENROLLMENT"
		case "session_display":
			report.ExitClass = "USER_SESSION"
		case "browser_smoke", "resident_ipc":
			report.ExitClass = "RUNTIME_SMOKE"
		default:
			report.ExitClass = "NATIVE_PERMISSION"
		}
		return
	}
	for _, layer := range report.Layers {
		if layer.Status == "UNKNOWN" {
			report.ExitClass = "DEFERRED"
			report.DominantCode = layer.Code
			return
		}
	}
	if report.Overall == "READY" {
		report.ExitClass = "NONE"
		report.DominantCode = "OK"
	}
}

func SuiteDoctorExitCode(report SuiteDoctorReport) int {
	switch report.ExitClass {
	case "NONE":
		return 0
	case "NETWORK_TLS":
		return 3
	case "ENROLLMENT":
		return 4
	case "RUNTIME_SMOKE":
		return 6
	case "USER_SESSION":
		return 7
	case "DEFERRED":
		return 5
	default:
		return 5
	}
}

func SuiteServiceStatus(ctx context.Context, roots SuiteUserRoots) SuiteDoctorReport {
	if runtime.GOOS != "windows" {
		return SuiteDoctorReport{SchemaVersion: 1, Overall: "UNKNOWN", ExitClass: "DEFERRED", DominantCode: "PLATFORM_ADAPTER_DEFERRED", Layers: []SuiteDoctorLayer{{Name: "registration", Status: "UNKNOWN", Code: "PLATFORM_ADAPTER_DEFERRED", SafeMessage: "PLATFORM_ADAPTER_DEFERRED", Remediation: "USE_SUPPORTED_PLATFORM", Retryable: false}, {Name: "resident_ipc", Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED", SafeMessage: "PREREQUISITE_BLOCKED", Remediation: "USE_SUPPORTED_PLATFORM", Retryable: false}}}
	}
	full := DoctorSuite(ctx, roots)
	result := SuiteDoctorReport{SchemaVersion: 1, Overall: "INACTIVE", ExitClass: full.ExitClass, DominantCode: full.DominantCode}
	for _, layer := range full.Layers {
		if layer.Name == "registration" || layer.Name == "resident_ipc" {
			result.Layers = append(result.Layers, layer)
		}
	}
	if len(result.Layers) == 2 && result.Layers[0].Status == "PASS" && result.Layers[1].Status == "PASS" {
		result.Overall = "ACTIVE"
		result.ExitClass = "NONE"
		result.DominantCode = "OK"
	}
	return result
}
