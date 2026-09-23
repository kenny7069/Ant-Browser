// ant-farm-client is the Wails-free standalone Farm agent host.
package main

import (
	"ant-chrome/backend"
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

func main() {
	os.Exit(protectedMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func protectedMain(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	return protectedRun(stderr, func() int {
		return run(args, stdin, stdout, stderr)
	})
}

func protectedRun(stderr io.Writer, action func() int) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "ant-farm-client: unexpected failure")
			code = 1
		}
	}()
	return action()
}

func farmAgentControlledStopCompleted(requested bool, runErr, admissionErr, shutdownErr error) bool {
	return requested && (runErr == nil || runErr == context.Canceled) && admissionErr == nil && shutdownErr == nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// v3 subcommands own their FlagSet. Dispatch before the legacy global
	// parser, which intentionally stops at the first positional argument.
	if len(args) > 0 && args[0] == "setup" {
		return runSetupCommand(args[1:], stdin, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "suite" {
		roots, err := backend.ResolveSuiteUserRoots()
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: Suite roots unavailable")
			return 1
		}
		return runSuiteCommand(roots, args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "doctor" {
		return runTopLevelDoctor(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "service" {
		if len(args) != 2 || args[1] != "status" {
			fmt.Fprintln(stderr, "ant-farm-client: invalid service command")
			return 2
		}
		roots, err := backend.ResolveSuiteUserRoots()
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: Suite roots unavailable")
			return 5
		}
		return runSuiteCommand(roots, []string{"service", "status"}, stdout, stderr)
	}
	flags := flag.NewFlagSet("ant-farm-client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "absolute path to the strict Ant Farm client YAML/JSON config")
	showVersion := flags.Bool("version", false, "print version, GOOS and GOARCH")
	enroll := flags.Bool("enroll", false, "enroll once; reads the one-time code from stdin")
	diagnostics := flags.Bool("diagnostics", false, "print the secret-free diagnostics allowlist")
	farmAgent := flags.Bool("farm-agent", false, "internal supervised Agent process")
	updateHealthFile := flags.String("update-health-file", "", "internal signed-update health marker")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		value, _ := json.Marshal(backend.FarmClientVersionInfoValue())
		fmt.Fprintln(stdout, string(value))
		return 0
	}
	path := filepath.Clean(*configPath)
	if *configPath == "" || !filepath.IsAbs(path) {
		fmt.Fprintln(stderr, "ant-farm-client: -config must be an absolute path")
		return 2
	}
	if *diagnostics {
		config, err := backend.LoadFarmClientConfig(path)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: diagnostics unavailable")
			return 1
		}
		value, _ := json.Marshal(backend.FarmClientDiagnosticsValue(config))
		fmt.Fprintln(stdout, string(value))
		return 0
	}
	if *enroll {
		return runEnrollment(path, stdin, stdout, stderr)
	}
	if flags.NArg() > 0 {
		if flags.Arg(0) == "update" {
			return runUpdateCommand(path, flags.Args(), stdout, stderr)
		}
		if flags.Arg(0) == "autostart" {
			return runAutostartCommand(path, flags.Args(), stdout, stderr)
		}
		return runProfileCommand(path, flags.Args(), stdin, stdout, stderr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	executable, _ := os.Executable()
	if !*farmAgent {
		suiteRoots, suiteRootsErr := backend.ResolveSuiteUserRoots()
		if suiteRootsErr == nil {
			isSuite, classifyErr := backend.ClassifySuiteFarmClientLaunch(suiteRoots, path)
			if classifyErr != nil {
				fmt.Fprintln(stderr, "ant-farm-client: Suite launcher unavailable")
				return 1
			}
			if isSuite {
				if err := backend.RunSuiteFarmClientLauncher(ctx, suiteRoots, path, filepath.Clean(executable), stdout, stderr); err != nil && ctx.Err() == nil {
					fmt.Fprintln(stderr, "ant-farm-client: Suite launcher unavailable")
					return 1
				}
				return 0
			}
		}
		if err := backend.RunFarmClientLauncher(ctx, path, filepath.Clean(executable), stdout, stderr); err != nil && ctx.Err() == nil {
			if errors.Is(err, backend.ErrFarmClientAlreadyRun) {
				fmt.Fprintln(stderr, backend.ErrFarmClientAlreadyRun.Error())
				return 1
			}
			fmt.Fprintln(stderr, "ant-farm-client: launcher stopped")
			return 1
		}
		return 0
	}
	host, err := backend.NewFarmClientHost(path)
	if err != nil {
		fmt.Fprintf(stderr, "ant-farm-client: startup failed: %v\n", err)
		return 1
	}
	controlledStopRequest := make(chan struct{}, 1)
	ipcServer, err := backend.StartFarmClientIPCServerWithServiceStop(host, func() {
		select {
		case controlledStopRequest <- struct{}{}:
		default:
		}
	})
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: local IPC startup failed")
		_ = host.Shutdown()
		return 1
	}
	hostCtx, cancelHost := context.WithCancel(context.Background())
	defer cancelHost()
	var residentStop sync.Once
	var controlledStop bool
	var admissionErr error
	stopResident := func(preserve, controlled bool) {
		residentStop.Do(func() {
			admissionErr = ipcServer.Close()
			if preserve {
				_ = host.PrepareForUpdate()
			}
			if controlled {
				controlledStop = true
			}
			cancelHost()
		})
	}
	go func() {
		select {
		case <-controlledStopRequest:
			stopResident(false, true)
		case <-hostCtx.Done():
		}
	}()
	go func() {
		<-ctx.Done()
		stopResident(false, false)
	}()
	// The immutable launcher owns the write end of this anonymous pipe. A
	// deliberate service stop sends 'S'. Update rollback sends 'P', while EOF
	// means the parent died. Both preserve live Browser runtimes for recovery.
	go func() {
		stopResident(farmAgentControlPreservesRuntimes(stdin), false)
	}()
	go backend.RunFarmClientUpdateSupervisor(hostCtx, host, path, filepath.Clean(executable))
	var runErr error
	if *updateHealthFile != "" {
		runErr = host.RunWithUpdateHealth(hostCtx, filepath.Clean(*updateHealthFile), os.Getenv("ANT_FARM_CLIENT_UPDATE_HEALTH_NONCE"))
	} else {
		runErr = host.Run(hostCtx)
	}
	stopResident(false, false)
	shutdownErr := host.Shutdown()
	if controlledStop {
		if farmAgentControlledStopCompleted(true, runErr, admissionErr, shutdownErr) {
			return backend.FarmClientInternalControlledStopExitCode
		}
		fmt.Fprintln(stderr, "ant-farm-client: controlled stop failed")
		return 1
	}
	if runErr != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "ant-farm-client: stopped: %v\n", runErr)
		return 1
	}
	if admissionErr != nil {
		fmt.Fprintln(stderr, "ant-farm-client: local IPC shutdown failed")
		return 1
	}
	if shutdownErr != nil {
		fmt.Fprintf(stderr, "ant-farm-client: shutdown failed: %v\n", shutdownErr)
		return 1
	}
	return 0
}

func runTopLevelDoctor(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "absolute canonical Suite client config")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*jsonOutput || !filepath.IsAbs(*configPath) {
		fmt.Fprintln(stderr, "ant-farm-client: invalid doctor arguments")
		return 2
	}
	roots, err := backend.ResolveSuiteUserRoots()
	if err != nil || filepath.Clean(*configPath) != filepath.Join(roots.Config, backend.SuiteClientConfigName) {
		fmt.Fprintln(stderr, "ant-farm-client: doctor config is not canonical")
		return 2
	}
	return runSuiteCommand(roots, []string{"doctor"}, stdout, stderr)
}

func runSuiteCommand(roots backend.SuiteUserRoots, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "ant-farm-client: invalid Suite command")
		return 2
	}
	switch args[0] {
	case "doctor":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "ant-farm-client: invalid Suite doctor arguments")
			return 2
		}
		report := backend.DoctorSuite(context.Background(), roots)
		encoded, _ := json.Marshal(report)
		fmt.Fprintln(stdout, string(encoded))
		return backend.SuiteDoctorExitCode(report)
	case "service":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "ant-farm-client: invalid Suite service arguments")
			return 2
		}
		if args[1] == "status" {
			report := backend.SuiteServiceStatus(context.Background(), roots)
			encoded, _ := json.Marshal(report)
			fmt.Fprintln(stdout, string(encoded))
			return backend.SuiteDoctorExitCode(report)
		}
		// Activation is public only where its native lifecycle is proven
		// (macOS LaunchAgent); Windows stays internal until its matrix runs.
		if args[1] == "activate" && runtime.GOOS == "darwin" {
			if err := backend.ActivateSuiteService(context.Background(), roots); err != nil {
				encoded, _ := json.Marshal(map[string]string{"state": "SERVICE_ACTIVATION_FAILED", "next_action": "suite_doctor"})
				fmt.Fprintln(stdout, string(encoded))
				return 1
			}
			encoded, _ := json.Marshal(map[string]string{"state": string(backend.SetupServiceStarted)})
			fmt.Fprintln(stdout, string(encoded))
			return 0
		}
		fmt.Fprintln(stderr, "ant-farm-client: invalid Suite service command")
		return 2
	case "finalize-handoff":
		flags := flag.NewFlagSet("suite finalize-handoff", flag.ContinueOnError)
		flags.SetOutput(stderr)
		requestUID := flags.String("request-uid", "", "setup preparation request UID")
		suiteRoot := flags.String("suite-root", "", "absolute immutable Suite version root")
		guiPath := flags.String("gui", "", "absolute Ant GUI executable path")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*suiteRoot) || !filepath.IsAbs(*guiPath) {
			fmt.Fprintln(stderr, "ant-farm-client: invalid Suite handoff arguments")
			return 2
		}
		handoff, err := backend.FinalizeSuiteOwnershipHandoff(roots, *requestUID, filepath.Clean(*suiteRoot), filepath.Clean(*guiPath))
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: Suite handoff failed")
			return 1
		}
		encoded, _ := json.Marshal(map[string]string{"state": handoff.HandoffState, "request_uid": handoff.SetupRequestUID})
		fmt.Fprintln(stdout, string(encoded))
		return 0
	case "verify-release":
		return runSuiteReleaseVerification(args[1:], false, stdout, stderr)
	case "verify-release-embedded":
		return runSuiteReleaseVerification(args[1:], true, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "ant-farm-client: invalid Suite command")
		return 2
	}
}

func runSuiteReleaseVerification(args []string, embedded bool, stdout, stderr io.Writer) int {
	name := "suite verify-release"
	if embedded {
		name = "suite verify-release-embedded"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "absolute Suite release manifest path")
	envelopePath := flags.String("envelope", "", "absolute detached envelope path")
	var keyID, publicKeyValue *string
	if !embedded {
		keyID = flags.String("key-id", "", "caller-pinned release key ID")
		publicKeyValue = flags.String("public-key", "", "caller-pinned Ed25519 public key")
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*manifestPath) || !filepath.IsAbs(*envelopePath) {
		fmt.Fprintln(stderr, "ant-farm-client: invalid Suite release verification arguments")
		return 2
	}
	manifest, err := readSuiteReleaseVerificationFile(filepath.Clean(*manifestPath), 1<<20)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: Suite release verification failed")
		return 1
	}
	envelope, err := readSuiteReleaseVerificationFile(filepath.Clean(*envelopePath), 16<<10)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: Suite release verification failed")
		return 1
	}
	var release backend.VerifiedSuiteRelease
	if embedded {
		release, err = verifyEmbeddedSuiteRelease(manifest, envelope)
		if err == nil && release.Manifest().Version != backend.FarmClientVersion {
			err = backend.ErrSuiteReleaseManifest
		}
	} else {
		publicKey, decodeErr := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(*publicKeyValue))
		if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize {
			clearSetupBytes(publicKey)
			fmt.Fprintln(stderr, "ant-farm-client: Suite release verification failed")
			return 1
		}
		release, err = backend.VerifySuiteReleaseManifest(manifest, envelope, backend.SuiteReleaseTrustAnchor{KeyID: strings.TrimSpace(*keyID), PublicKey: ed25519.PublicKey(publicKey)})
		clearSetupBytes(publicKey)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: Suite release verification failed")
		return 1
	}
	_ = release
	fmt.Fprintln(stdout, `{"verified":true}`)
	return 0
}

func readSuiteReleaseVerificationFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, backend.ErrSuiteReleaseManifest
	}
	return os.ReadFile(path)
}

func farmAgentControlPreservesRuntimes(reader io.Reader) bool {
	var decision [1]byte
	_, err := io.ReadFull(reader, decision[:])
	return err != nil || decision[0] != 'S'
}

func runUpdateCommand(configPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || (args[1] != "check" && args[1] != "stage") {
		fmt.Fprintln(stderr, "ant-farm-client: invalid update command")
		return 2
	}
	config, err := backend.LoadFarmClientConfig(configPath)
	if err != nil || config.ValidateFarmClientConfig() != nil {
		fmt.Fprintln(stderr, "ant-farm-client: update configuration is invalid")
		return 1
	}
	status := "available"
	var version, target string
	if args[1] == "check" {
		candidate, checkErr := backend.CheckFarmClientUpdate(context.Background(), nil, config, backend.FarmClientVersion, time.Now())
		if checkErr != nil {
			fmt.Fprintln(stderr, "ant-farm-client: update check failed")
			return 1
		}
		version, target = candidate.Manifest.Version, candidate.Target
	} else {
		staged, stageErr := backend.FetchAndStageFarmClientUpdate(context.Background(), nil, config, backend.FarmClientVersion, time.Now())
		if stageErr != nil {
			fmt.Fprintln(stderr, "ant-farm-client: update stage failed")
			return 1
		}
		version, target, status = staged.Candidate.Manifest.Version, staged.Candidate.Target, "staged"
	}
	value, _ := json.Marshal(map[string]string{"status": status, "version": version, "target": target})
	fmt.Fprintln(stdout, string(value))
	return 0
}

func runAutostartCommand(configPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "ant-farm-client: invalid autostart command")
		return 2
	}
	config, err := backend.LoadFarmClientConfig(configPath)
	if err != nil || config.ValidateFarmClientConfig() != nil {
		fmt.Fprintln(stderr, "ant-farm-client: autostart configuration is invalid")
		return 1
	}
	switch args[1] {
	case "install":
		executable, err := os.Executable()
		if err != nil || backend.InstallFarmClientAutostart(executable, configPath) != nil {
			fmt.Fprintln(stderr, "ant-farm-client: autostart install failed")
			return 1
		}
	case "remove":
		if backend.RemoveFarmClientAutostartForConfig(configPath) != nil {
			fmt.Fprintln(stderr, "ant-farm-client: autostart remove failed")
			return 1
		}
	case "status":
		status, err := backend.FarmClientAutostartStatusForConfig(configPath)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: autostart status unavailable")
			return 1
		}
		encoded, _ := json.Marshal(status)
		fmt.Fprintln(stdout, string(encoded))
		return 0
	default:
		fmt.Fprintln(stderr, "ant-farm-client: invalid autostart command")
		return 2
	}
	status, err := backend.FarmClientAutostartStatusForConfig(configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: autostart status unavailable")
		return 1
	}
	encoded, _ := json.Marshal(status)
	if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
		return 1
	}
	return 0
}

func runProfileCommand(configPath string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	client, err := backend.NewFarmClientIPCClient(configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: profile command unavailable")
		return 1
	}
	ctx := context.Background()
	write := func(value any) int {
		encoded, err := json.Marshal(value)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: output failed")
			return 1
		}
		fmt.Fprintln(stdout, string(encoded))
		return 0
	}
	if len(args) == 2 && args[0] == "profiles" && args[1] == "list" {
		profiles, err := client.ProfileList(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile list failed")
			return 1
		}
		return write(profiles)
	}
	if len(args) > 1 && args[0] == "profiles" && args[1] == "create" {
		request, err := parseProfileCreateArguments(args[2:], stderr)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: invalid profile create arguments")
			return 2
		}
		result, err := client.ProfileCreate(ctx, request)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile create failed")
			return 1
		}
		return write(result)
	}
	if len(args) == 3 && args[0] == "profiles" && args[1] == "open" {
		profile, err := client.ProfileOpen(ctx, args[2])
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile open failed")
			return 1
		}
		return write(profile)
	}
	if len(args) == 3 && args[0] == "profiles" && args[1] == "stop" {
		profile, err := client.ProfileStop(ctx, args[2])
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile stop failed")
			return 1
		}
		return write(profile)
	}
	if len(args) == 3 && args[0] == "profiles" && args[1] == "status" {
		profile, err := client.ProfileStatus(ctx, args[2])
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile status failed")
			return 1
		}
		return write(profile)
	}
	if len(args) == 2 && args[0] == "pair" {
		pairingCode, err := readSecretLine(stdin, stderr, "Pairing code: ")
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: pairing code is required")
			return 1
		}
		result, err := client.PairProfile(ctx, args[1], pairingCode)
		pairingCode = ""
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: pairing failed")
			return 1
		}
		return write(result)
	}
	if len(args) == 2 && args[0] == "unpair" {
		result, err := client.UnpairProfile(ctx, args[1])
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: unpair failed")
			return 1
		}
		return write(result)
	}
	fmt.Fprintln(stderr, "ant-farm-client: invalid profile command")
	return 2
}

func parseProfileCreateArguments(args []string, stderr io.Writer) (backend.FarmProfileCreateRequest, error) {
	flags := flag.NewFlagSet("profiles create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	operationUID := flags.String("operation-uid", "", "canonical management operation UUID")
	requestUID := flags.String("request-uid", "", "canonical idempotency request UUID")
	displayName := flags.String("display-name", "", "profile display name")
	coreRef := flags.String("core-ref", "", "approved existing browser core ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return backend.FarmProfileCreateRequest{}, errors.New("invalid profile create flags")
	}
	return backend.NewFarmProfileCreateRequest(*operationUID, *requestUID, *displayName, *coreRef)
}

func runEnrollment(configPath string, stdin io.Reader, stdout, stderr io.Writer) int {
	config, err := backend.LoadFarmClientConfig(configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: enrollment configuration is invalid")
		return 1
	}
	if err := config.ValidateFarmClientConfig(); err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: enrollment configuration is invalid")
		return 1
	}
	stateRoot, err := backend.ValidateFarmClientStateRoot(config.StateRoot)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: secure identity storage is unavailable")
		return 1
	}
	lock, err := backend.AcquireFarmClientInstanceLock(stateRoot)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: enrollment is already running")
		return 1
	}
	defer lock.Release()
	store, err := backend.NewFarmClientIdentityStore(stateRoot)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: secure identity storage is unavailable")
		return 1
	}
	code, err := readEnrollmentCode(stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: enrollment code is required")
		return 1
	}
	result, err := backend.EnrollFarmClient(context.Background(), config, code, store, nil)
	code = ""
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: enrollment failed")
		return 1
	}
	value, _ := json.Marshal(result)
	code = ""
	if _, err := fmt.Fprintln(stdout, string(value)); err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: enrollment output failed")
		return 1
	}
	return 0
}

func readEnrollmentCode(input io.Reader, prompt io.Writer) (string, error) {
	return readSecretLine(input, prompt, "Enrollment code: ")
}

func readSecretLine(input io.Reader, prompt io.Writer, label string) (string, error) {
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(prompt, label)
		raw, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(prompt)
		if err != nil {
			return "", err
		}
		defer func() {
			for index := range raw {
				raw[index] = 0
			}
		}()
		return strings.TrimSpace(string(raw)), nil
	}
	line, err := bufio.NewReader(io.LimitReader(input, 4096)).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", io.EOF
	}
	return line, nil
}
