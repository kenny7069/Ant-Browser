// ant-farm-client is the Wails-free standalone Farm agent host.
package main

import (
	"ant-chrome/backend"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var configPath = flag.String("config", "", "absolute path to the strict Ant Farm client YAML/JSON config")
var showVersion = flag.Bool("version", false, "print version, GOOS and GOARCH")

func main() {
	flag.Parse()
	if *showVersion {
		value, _ := json.Marshal(backend.FarmClientVersionInfoValue())
		fmt.Println(string(value))
		return
	}
	path := filepath.Clean(*configPath)
	if *configPath == "" || !filepath.IsAbs(path) {
		fmt.Fprintln(os.Stderr, "ant-farm-client: -config must be an absolute path")
		os.Exit(2)
	}
	host, err := backend.NewFarmClientHost(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ant-farm-client: startup failed: %v\n", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := host.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "ant-farm-client: stopped: %v\n", err)
		_ = host.Shutdown()
		os.Exit(1)
	}
	if err := host.Shutdown(); err != nil {
		fmt.Fprintf(os.Stderr, "ant-farm-client: shutdown failed: %v\n", err)
		os.Exit(1)
	}
}
