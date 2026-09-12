package backend

import (
	"context"
	"path/filepath"
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
	Layers        []SuiteDoctorLayer `json:"layers"`
}

func DoctorSuite(ctx context.Context, roots SuiteUserRoots) SuiteDoctorReport {
	report := SuiteDoctorReport{SchemaVersion: 1, Overall: "NOT_READY"}
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
	add("registration", "PASS", "REGISTRATION_JOURNAL_CONFIRMED", false)
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
		if layer.Status != "PASS" { report.Overall = "NOT_READY"; break }
	}
	return report
}
