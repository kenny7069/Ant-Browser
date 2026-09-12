package main

import (
	"ant-chrome/backend"
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
	setupExitNativeStore = 5
)

type setupCommandResult struct {
	SchemaVersion    int                              `json:"schema_version"`
	PreparationState backend.SetupStage               `json:"preparation_state"`
	Classification   backend.SuiteSetupClassification `json:"classification"`
	RequestUID       string                           `json:"request_uid"`
	Connected        bool                             `json:"connected"`
	NextAction       string                           `json:"next_action"`
}

type setupCommandError struct {
	Code        string `json:"code"`
	Stage       string `json:"stage"`
	Field       string `json:"field,omitempty"`
	SafeMessage string `json:"safe_message"`
	Remediation string `json:"remediation"`
	Retryable   bool   `json:"retryable"`
}

var resolveSetupUserRoots = backend.ResolveSuiteUserRoots

func runSetupCommand(args []string, stdout, stderr io.Writer) int {
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
			SafeMessage: "必須提供可信 HTTPS Server origin。",
			Remediation: "加入 --server https://主機[:port]。",
		})
		return setupExitInput
	}
	if !validSetupServerOrigin(*server) {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_SERVER_INVALID", Stage: "INPUT_VALIDATION", Field: "server",
			SafeMessage: "Server 必須是沒有路徑、查詢或帳密的 HTTPS origin。",
			Remediation: "使用 https://主機[:port]，並先建立可信 TLS。",
		})
		return setupExitInput
	}

	roots, err := resolveSetupUserRoots()
	if err != nil {
		writeSetupError(stderr, jsonOutput, setupStorageError("SETUP_ROOTS_UNAVAILABLE", err, false))
		return setupExitNativeStore
	}
	checkpointPath := filepath.Join(roots.AgentState, "setup.json")
	displayName := strings.TrimSpace(*nodeName)
	if displayName == "" {
		displayName = defaultSetupNodeName()
	}
	if !validSetupNodeName(displayName) {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_NODE_NAME_INVALID", Stage: "INPUT_VALIDATION", Field: "node_name",
			SafeMessage: "節點名稱格式無效。",
			Remediation: "使用 1 至 100 字元且不含控制字元的名稱。",
		})
		return setupExitInput
	}
	config := backend.BootstrapConfig{
		ServerURL: strings.TrimSpace(*server),
		StatePath: checkpointPath,
		NodeName:  displayName,
	}
	coordinator, err := backend.NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: "SETUP_CONFIG_INVALID", Stage: "LOCAL_PREPARATION",
			SafeMessage: "Bootstrap 設定無效。",
			Remediation: "檢查目前使用者的 Suite 資料路徑。",
		})
		return setupExitInput
	}
	result, err := coordinator.Run()
	if err != nil {
		code := "SETUP_STORAGE_FAILED"
		retryable := false
		remediation := "檢查目前使用者的資料目錄權限後重試。"
		if errors.Is(err, backend.ErrSuiteSetupLocked) {
			code = "SETUP_ALREADY_RUNNING"
			retryable = true
			remediation = "等待同一使用者的 setup 完成後，以相同參數重試。"
		} else if errors.Is(err, backend.ErrSuiteSetupExistingState) {
			code = "SETUP_EXISTING_STATE"
			remediation = "保留現有資料，使用後續 setup repair 流程處理。"
		} else if errors.Is(err, backend.ErrSuiteSetupCorrupt) {
			code = "SETUP_STATE_CORRUPT"
			remediation = "保留現有資料並進行診斷；不要刪除 Profile 或重建身份。"
		}
		writeSetupError(stderr, jsonOutput, setupCommandError{
			Code: code, Stage: setupErrorStage(result), SafeMessage: "Setup 未能完成本機設定階段。",
			Remediation: remediation, Retryable: retryable,
		})
		return setupExitNativeStore
	}
	value := setupCommandResult{
		SchemaVersion: 1, PreparationState: result.Checkpoint.Stage,
		Classification: result.Classification, RequestUID: result.Checkpoint.RequestUID,
		Connected: false, NextAction: "run_precheck",
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return setupExitNativeStore
	}
	if jsonOutput {
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprintf(stdout, "Setup 準備狀態已保存至 %s；下一步：執行環境 precheck。\n", value.PreparationState)
	}
	return 0
}

func farmV3SetupEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FARM_V3_SETUP_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func validSetupServerOrigin(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" &&
		parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" &&
		parsed.Fragment == "" && parsed.Opaque == ""
}

func validSetupNodeName(value string) bool {
	return value != "" && len(value) <= 100 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
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
	if err != nil || name == "" || len(name) > 100 || strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
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

func setupStorageError(code string, _ error, retryable bool) setupCommandError {
	return setupCommandError{
		Code: code, Stage: "USER_ROOTS",
		SafeMessage: "無法使用目前使用者的 Suite 資料目錄。",
		Remediation: "確認使用一般登入使用者執行，並檢查資料目錄權限。",
		Retryable:   retryable,
	}
}

func writeSetupError(writer io.Writer, jsonOutput bool, value setupCommandError) {
	if jsonOutput {
		encoded, _ := json.Marshal(value)
		fmt.Fprintln(writer, string(encoded))
		return
	}
	fmt.Fprintf(writer, "ant-farm-client: %s (%s)\n", value.SafeMessage, value.Code)
}
