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
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(prompt, "Enrollment code: ")
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
