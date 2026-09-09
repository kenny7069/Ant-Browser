// ant-farm-client is the Wails-free standalone Farm agent host.
package main

import (
	"ant-chrome/backend"
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

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

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ant-farm-client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "absolute path to the strict Ant Farm client YAML/JSON config")
	showVersion := flags.Bool("version", false, "print version, GOOS and GOARCH")
	enroll := flags.Bool("enroll", false, "enroll once; reads the one-time code from stdin")
	diagnostics := flags.Bool("diagnostics", false, "print the secret-free diagnostics allowlist")
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
		if flags.Arg(0) == "autostart" {
			return runAutostartCommand(path, flags.Args(), stdout, stderr)
		}
		return runProfileCommand(path, flags.Args(), stdin, stdout, stderr)
	}
	host, err := backend.NewFarmClientHost(path)
	if err != nil {
		fmt.Fprintf(stderr, "ant-farm-client: startup failed: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := host.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "ant-farm-client: stopped: %v\n", err)
		_ = host.Shutdown()
		return 1
	}
	if err := host.Shutdown(); err != nil {
		fmt.Fprintf(stderr, "ant-farm-client: shutdown failed: %v\n", err)
		return 1
	}
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
		if backend.RemoveFarmClientAutostart() != nil {
			fmt.Fprintln(stderr, "ant-farm-client: autostart remove failed")
			return 1
		}
	case "status":
		status, err := backend.FarmClientAutostartStatusValue()
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
	status, err := backend.FarmClientAutostartStatusValue()
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
	host, err := backend.NewFarmClientHost(configPath)
	if err != nil {
		fmt.Fprintln(stderr, "ant-farm-client: profile command unavailable")
		return 1
	}
	defer host.Shutdown()
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
		profiles, err := host.ProfileList()
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile list failed")
			return 1
		}
		return write(profiles)
	}
	if len(args) == 3 && args[0] == "profiles" && args[1] == "create" {
		profile, err := host.ProfileCreate(args[2])
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile create failed")
			return 1
		}
		return write(profile)
	}
	if len(args) == 3 && args[0] == "profiles" && args[1] == "open" {
		profile, err := host.ProfileOpen(args[2])
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: profile open failed")
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
		result, err := host.PairProfile(context.Background(), args[1], pairingCode, nil)
		pairingCode = ""
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: pairing failed")
			return 1
		}
		return write(result)
	}
	if len(args) == 2 && args[0] == "unpair" {
		result, err := host.UnpairProfile(context.Background(), args[1], nil)
		if err != nil {
			fmt.Fprintln(stderr, "ant-farm-client: unpair failed")
			return 1
		}
		return write(result)
	}
	fmt.Fprintln(stderr, "ant-farm-client: invalid profile command")
	return 2
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
