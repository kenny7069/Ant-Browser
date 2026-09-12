package main

import (
	"ant-chrome/backend"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	setupExitInput       = 2
	setupExitTransport   = 3
	setupExitEnrollment  = 4
	setupExitNativeStore = 5
)

// Release packaging must set both values with go build -ldflags -X. Setup has
// no runtime flag or environment fallback for its trust anchor.
var suiteReleaseKeyID = ""
var suiteReleasePublicKeyBase64 = ""

type setupCommandResult struct {
	State      backend.SetupStage `json:"state"`
	NextAction string             `json:"next_action"`
}

type setupCommandError struct {
	Code        string `json:"code"`
	Stage       string `json:"stage"`
	Field       string `json:"field,omitempty"`
	SafeMessage string `json:"safe_message"`
	Remediation string `json:"remediation"`
	Retryable   bool   `json:"retryable"`
}

type canonicalSetupError struct {
	stage string
	err   error
}

func (e canonicalSetupError) Error() string { return e.stage + ": setup failed" }
func (e canonicalSetupError) Unwrap() error { return e.err }

type canonicalSetupStep func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) error

type canonicalSetupOperations struct {
	Executable       func() (string, error)
	LoadRelease      func(string, string) (backend.VerifiedSuiteRelease, error)
	LoadCheckpoint   func(string) (*backend.SetupCheckpoint, error)
	Precheck         canonicalSetupStep
	Stage            canonicalSetupStep
	ConfigDraft      canonicalSetupStep
	Transport        canonicalSetupStep
	Identity         canonicalSetupStep
	ProbeACK         func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) (backend.SuiteCanonicalEnrollmentACKState, error)
	EnrollmentACK    func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string, string) error
	ApplicationInit  canonicalSetupStep
	EnrollmentFinish canonicalSetupStep
}

var resolveSetupUserRoots = backend.ResolveSuiteUserRoots
var executeCanonicalSetup = runCanonicalSetupWithInput

func productionCanonicalSetupOperations() canonicalSetupOperations {
	return canonicalSetupOperations{
		Executable:     os.Executable,
		LoadRelease:    loadEmbeddedSuiteRelease,
		LoadCheckpoint: backend.LoadSetupCheckpoint,
		Precheck: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalPrecheck(ctx, config, roots, release, root)
			return err
		},
		Stage: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalStage(ctx, config, roots, release, root)
			return err
		},
		ConfigDraft: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalConfigDraft(ctx, config, roots, release, root)
			return err
		},
		Transport: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalTransport(ctx, config, roots, release, root)
			return err
		},
		Identity: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalIdentity(ctx, config, roots, release, root)
			return err
		},
		ProbeACK: backend.ProbeSuiteCanonicalEnrollmentACKState,
		EnrollmentACK: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root, code string) error {
			_, err := backend.RunSuiteCanonicalEnrollmentACK(ctx, config, roots, release, root, code)
			return err
		},
		ApplicationInit: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalApplicationInit(ctx, config, roots, release, root)
			return err
		},
		EnrollmentFinish: func(ctx context.Context, config backend.BootstrapConfig, roots backend.SuiteUserRoots, release backend.VerifiedSuiteRelease, root string) error {
			_, err := backend.RunSuiteCanonicalEnrollmentFinalize(ctx, config, roots, release, root)
			return err
		},
	}
}

func runSetupCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	jsonOutput := setupArgsWantJSON(args)
	if !farmV3SetupEnabled() {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_DISABLED", Stage: "INPUT_VALIDATION",
			SafeMessage: "Browser Farm v3 setup 尚未啟用。",
			Remediation: "由管理員完成部署前置後設定 FARM_V3_SETUP_ENABLED=1。",
		})
		return setupExitInput
	}
	flags := flag.NewFlagSet("ant-farm-client setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	server := flags.String("server", "", "trusted HTTPS Server origin")
	nodeName := flags.String("node-name", "", "display name for this node")
	flags.BoolVar(&jsonOutput, "json", jsonOutput, "write machine-readable JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_INPUT_INVALID", Stage: "INPUT_VALIDATION",
			SafeMessage: "Setup 參數格式無效。",
			Remediation: "使用 setup --server https://主機[:port] [--node-name 名稱] [--json]。",
		})
		return setupExitInput
	}
	if strings.TrimSpace(*server) == "" {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_SERVER_REQUIRED", Stage: "INPUT_VALIDATION", Field: "server",
			SafeMessage: "必須提供可信 HTTPS Server origin。", Remediation: "加入 --server https://主機[:port]。",
		})
		return setupExitInput
	}
	if !validSetupServerOrigin(*server) {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_SERVER_INVALID", Stage: "INPUT_VALIDATION", Field: "server",
			SafeMessage: "Server 必須是沒有路徑、查詢或帳密的 HTTPS origin。", Remediation: "使用 https://主機[:port]，並先建立可信 TLS。",
		})
		return setupExitInput
	}
	displayName := strings.TrimSpace(*nodeName)
	if displayName == "" {
		displayName = defaultSetupNodeName()
	}
	if !validSetupNodeName(displayName) {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_NODE_NAME_INVALID", Stage: "INPUT_VALIDATION", Field: "node_name",
			SafeMessage: "節點名稱格式無效。", Remediation: "使用 1 至 100 字元且不含控制字元的名稱。",
		})
		return setupExitInput
	}

	roots, err := resolveSetupUserRoots()
	if err != nil {
		writeSetupError(stderr, jsonOutput, setupStorageError("SETUP_ROOTS_UNAVAILABLE", false))
		return setupExitNativeStore
	}
	config := backend.BootstrapConfig{
		ServerURL: strings.TrimSpace(*server), StatePath: filepath.Join(roots.AgentState, "setup.json"), NodeName: displayName,
	}
	coordinator, err := backend.NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_CONFIG_INVALID", Stage: "LOCAL_PREPARATION", SafeMessage: "Bootstrap 設定無效。",
			Remediation: "檢查目前使用者的 Suite 資料路徑。",
		})
		return setupExitInput
	}
	result, err := coordinator.Run()
	if err != nil {
		writeSetupError(stderr, jsonOutput, classifyPreparationError(result, err))
		return setupExitNativeStore
	}
	value, err := executeCanonicalSetup(context.Background(), config, roots, stdin, stderr)
	if err != nil {
		writeSetupError(stderr, jsonOutput, classifyCanonicalSetupError(err))
		return classifyCanonicalSetupExit(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		writeSetupError(stderr, jsonOutput, setupStorageError("SETUP_OUTPUT_FAILED", false))
		return setupExitNativeStore
	}
	if jsonOutput {
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprintln(stdout, "Setup 已完成：ENROLLED；下一步：service_activation。")
	}
	return 0
}

func runCanonicalSetupWithInput(ctx context.Context, bootstrap backend.BootstrapConfig, roots backend.SuiteUserRoots, input io.Reader, prompt io.Writer) (setupCommandResult, error) {
	return runCanonicalSetupWithOperations(ctx, bootstrap, roots, input, prompt, productionCanonicalSetupOperations())
}

func runCanonicalSetupWithOperations(ctx context.Context, bootstrap backend.BootstrapConfig, roots backend.SuiteUserRoots, input io.Reader, prompt io.Writer, ops canonicalSetupOperations) (setupCommandResult, error) {
	if ctx == nil || ops.Executable == nil || ops.LoadRelease == nil || ops.LoadCheckpoint == nil || ops.Precheck == nil || ops.Stage == nil ||
		ops.ConfigDraft == nil || ops.Transport == nil || ops.Identity == nil || ops.ProbeACK == nil || ops.EnrollmentACK == nil || ops.ApplicationInit == nil || ops.EnrollmentFinish == nil {
		return setupCommandResult{}, canonicalSetupError{"LOCAL_STATE", errors.New("canonical setup operations unavailable")}
	}
	executable, err := ops.Executable()
	if err != nil || executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return setupCommandResult{}, canonicalSetupError{"RELEASE", errors.New("executable path unavailable")}
	}
	suiteRoot := filepath.Dir(executable)
	if !strings.EqualFold(filepath.Base(filepath.Dir(suiteRoot)), "versions") {
		return setupCommandResult{}, canonicalSetupError{"RELEASE", errors.New("executable is outside immutable Suite versions root")}
	}
	release, err := ops.LoadRelease(suiteRoot, backend.FarmClientVersion)
	if err != nil {
		return setupCommandResult{}, canonicalSetupError{"RELEASE", err}
	}

	checkpoint, err := ops.LoadCheckpoint(bootstrap.StatePath)
	if err != nil {
		return setupCommandResult{}, canonicalSetupError{"LOCAL_STATE", err}
	}
	advance := func(stage string, expected backend.SetupStage, operation canonicalSetupStep) error {
		requestUID := ""
		if checkpoint != nil {
			requestUID = checkpoint.RequestUID
		}
		if err := operation(ctx, bootstrap, roots, release, suiteRoot); err != nil {
			return canonicalSetupError{stage, err}
		}
		confirmed, err := ops.LoadCheckpoint(bootstrap.StatePath)
		if err != nil || confirmed == nil || confirmed.Stage != expected || (requestUID != "" && confirmed.RequestUID != requestUID) {
			return canonicalSetupError{stage, errors.New("canonical checkpoint did not advance")}
		}
		checkpoint = confirmed
		return nil
	}
	if checkpoint == nil {
		if err := advance("PRECHECK", backend.SetupPrecheck, ops.Precheck); err != nil {
			return setupCommandResult{}, err
		}
	}
	for checkpoint != nil && checkpoint.Stage != backend.SetupIdentityReady && checkpoint.Stage != backend.SetupEnrolled {
		var stage string
		var expected backend.SetupStage
		var operation canonicalSetupStep
		switch checkpoint.Stage {
		case backend.SetupPrecheck:
			stage, expected, operation = "STAGED", backend.SetupStaged, ops.Stage
		case backend.SetupStaged:
			stage, expected, operation = "CONFIG_DRAFTED", backend.SetupConfigDrafted, ops.ConfigDraft
		case backend.SetupConfigDrafted:
			stage, expected, operation = "TRANSPORT_VERIFIED", backend.SetupTransportVerified, ops.Transport
		case backend.SetupTransportVerified:
			stage, expected, operation = "IDENTITY_READY", backend.SetupIdentityReady, ops.Identity
		default:
			return setupCommandResult{}, canonicalSetupError{"LOCAL_STATE", errors.New("unsupported setup checkpoint")}
		}
		if err := advance(stage, expected, operation); err != nil {
			return setupCommandResult{}, err
		}
	}
	if checkpoint == nil {
		return setupCommandResult{}, canonicalSetupError{"LOCAL_STATE", errors.New("canonical checkpoint unavailable")}
	}
	if checkpoint.Stage == backend.SetupIdentityReady {
		ackState, err := ops.ProbeACK(ctx, bootstrap, roots, release, suiteRoot)
		if err != nil {
			return setupCommandResult{}, canonicalSetupError{"ACK_STATE", err}
		}
		switch ackState {
		case backend.SuiteCanonicalEnrollmentACKCodeRequired:
			if input == nil {
				return setupCommandResult{}, canonicalSetupError{"ENROLLMENT", io.EOF}
			}
			code, err := readEnrollmentCode(input, prompt)
			if err != nil {
				return setupCommandResult{}, canonicalSetupError{"ENROLLMENT", err}
			}
			err = ops.EnrollmentACK(ctx, bootstrap, roots, release, suiteRoot, code)
			code = ""
			if err != nil {
				return setupCommandResult{}, canonicalSetupError{"ENROLLMENT", err}
			}
		case backend.SuiteCanonicalEnrollmentACKDurable:
		default:
			return setupCommandResult{}, canonicalSetupError{"ACK_STATE", errors.New("invalid acknowledgment probe state")}
		}
		if err := ops.ApplicationInit(ctx, bootstrap, roots, release, suiteRoot); err != nil {
			return setupCommandResult{}, canonicalSetupError{"APPLICATION_INIT", err}
		}
	}
	if err := advance("ENROLLMENT_FINALIZE", backend.SetupEnrolled, ops.EnrollmentFinish); err != nil {
		return setupCommandResult{}, err
	}
	return setupCommandResult{State: backend.SetupEnrolled, NextAction: "service_activation"}, nil
}

func loadEmbeddedSuiteRelease(suiteRoot, binaryVersion string) (backend.VerifiedSuiteRelease, error) {
	manifest, err := readSuiteReleaseVerificationFile(filepath.Join(suiteRoot, "release-manifest.json"), 1<<20)
	if err != nil {
		return backend.VerifiedSuiteRelease{}, err
	}
	envelope, err := readSuiteReleaseVerificationFile(filepath.Join(suiteRoot, "release-manifest.envelope.json"), 16<<10)
	if err != nil {
		return backend.VerifiedSuiteRelease{}, err
	}
	release, err := verifyEmbeddedSuiteRelease(manifest, envelope)
	if err != nil || release.Manifest().Version != filepath.Base(suiteRoot) || release.Manifest().Version != binaryVersion {
		return backend.VerifiedSuiteRelease{}, errors.New("embedded release binding failed")
	}
	return release, nil
}

func verifyEmbeddedSuiteRelease(manifest, envelope []byte) (backend.VerifiedSuiteRelease, error) {
	keyID := strings.TrimSpace(suiteReleaseKeyID)
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(suiteReleasePublicKeyBase64))
	if err != nil || len(key) != ed25519.PublicKeySize || keyID == "" {
		clearSetupBytes(key)
		return backend.VerifiedSuiteRelease{}, errors.New("embedded release trust anchor unavailable")
	}
	release, err := backend.VerifySuiteReleaseManifest(manifest, envelope, backend.SuiteReleaseTrustAnchor{KeyID: keyID, PublicKey: ed25519.PublicKey(key)})
	clearSetupBytes(key)
	return release, err
}

func clearSetupBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func farmV3SetupEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FARM_V3_SETUP_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func classifyPreparationError(result backend.SuiteSetupResult, err error) setupCommandError {
	code, remediation, retryable := "SETUP_STORAGE_FAILED", "檢查目前使用者的資料目錄權限後重試。", false
	if errors.Is(err, backend.ErrSuiteSetupLocked) {
		code, remediation, retryable = "SETUP_ALREADY_RUNNING", "等待同一使用者的 setup 完成後，以相同參數重試。", true
	} else if errors.Is(err, backend.ErrSuiteSetupExistingState) {
		code, remediation = "SETUP_EXISTING_STATE", "保留現有資料，使用後續 setup repair 流程處理。"
	} else if errors.Is(err, backend.ErrSuiteSetupCorrupt) {
		code, remediation = "SETUP_STATE_CORRUPT", "保留現有資料並進行診斷；不要刪除 Profile 或重建身份。"
	}
	return setupCommandError{Code: code, Stage: setupErrorStage(result), SafeMessage: "Setup 未能完成本機設定階段。", Remediation: remediation, Retryable: retryable}
}

func classifyCanonicalSetupError(err error) setupCommandError {
	stage := "CANONICAL_SETUP"
	var canonical canonicalSetupError
	if errors.As(err, &canonical) && canonical.stage != "" {
		stage = canonical.stage
	}
	code, remediation, retryable := "SETUP_LOCAL_STATE_FAILED", "檢查安裝來源與目前使用者資料目錄後重試。", false
	if canonicalSetupTransportError(err, stage) {
		code, remediation, retryable = "SETUP_TRANSPORT_FAILED", "確認可信 HTTPS Server、TLS 憑證與網絡後重試。", true
	} else if canonicalSetupEnrollmentError(err, stage) {
		code, remediation = "SETUP_ENROLLMENT_FAILED", "確認一次性 code 有效；若已使用，向管理端取得新 code 後重試。"
	} else if errors.Is(err, backend.ErrSuiteSetupLocked) {
		code, remediation, retryable = "SETUP_ALREADY_RUNNING", "等待同一使用者的 setup 完成後重試。", true
	}
	return setupCommandError{Code: code, Stage: stage, SafeMessage: "Setup 未能完成；秘密資料未被輸出。", Remediation: remediation, Retryable: retryable}
}

func classifyCanonicalSetupExit(err error) int {
	stage := ""
	var canonical canonicalSetupError
	if errors.As(err, &canonical) {
		stage = canonical.stage
	}
	if canonicalSetupTransportError(err, stage) {
		return setupExitTransport
	}
	if canonicalSetupEnrollmentError(err, stage) {
		return setupExitEnrollment
	}
	return setupExitNativeStore
}

func canonicalSetupTransportError(err error, stage string) bool {
	return stage == "TRANSPORT_VERIFIED" ||
		errors.Is(err, backend.ErrSuiteBootstrapTLS) || errors.Is(err, backend.ErrSuiteBootstrapTransport) || errors.Is(err, backend.ErrSuiteBootstrapRedirect) ||
		errors.Is(err, backend.ErrSuiteBootstrapEnrollmentTLS) || errors.Is(err, backend.ErrSuiteBootstrapEnrollmentTransport) || errors.Is(err, backend.ErrSuiteBootstrapEnrollmentRedirect) || errors.Is(err, backend.ErrSuiteBootstrapEnrollmentRetryable)
}

func canonicalSetupEnrollmentError(err error, stage string) bool {
	return stage == "ENROLLMENT" ||
		errors.Is(err, backend.ErrSuiteBootstrapEnrollmentRejected) ||
		errors.Is(err, backend.ErrSuiteBootstrapEnrollmentConflict) || errors.Is(err, backend.ErrSuiteBootstrapEnrollmentConfig) || errors.Is(err, backend.ErrSuiteBootstrapEnrollmentState)
}

func validSetupServerOrigin(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == ""
}

func validSetupNodeName(value string) bool {
	return value != "" && len(value) <= 100 && strings.TrimSpace(value) == value && strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

func setupArgsWantJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--json" || arg == "-json" {
			return true
		}
	}
	return false
}

func defaultSetupNodeName() string {
	name, err := os.Hostname()
	name = strings.TrimSpace(name)
	if err != nil || !validSetupNodeName(name) {
		return "Ant Farm Node"
	}
	return name
}

func setupErrorStage(result backend.SuiteSetupResult) string {
	if result.Checkpoint.Stage != "" {
		return string(result.Checkpoint.Stage)
	}
	return "LOCAL_PREPARATION"
}

func setupStorageError(code string, retryable bool) setupCommandError {
	return setupCommandError{Code: code, Stage: "USER_ROOTS", SafeMessage: "無法使用目前使用者的 Suite 資料目錄。", Remediation: "確認使用一般登入使用者執行，並檢查資料目錄權限。", Retryable: retryable}
}

func writeSetupError(writer io.Writer, jsonOutput bool, value setupCommandError) {
	if jsonOutput {
		encoded, _ := json.Marshal(value)
		fmt.Fprintln(writer, string(encoded))
		return
	}
	fmt.Fprintf(writer, "ant-farm-client: %s (%s)\n", value.SafeMessage, value.Code)
}
