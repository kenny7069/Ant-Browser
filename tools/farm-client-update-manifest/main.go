package main

import (
	"ant-chrome/backend"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	manifestPath := flag.String("manifest", "", "path to the unsigned manifest JSON")
	privateKeyPath := flag.String("private-key-file", "", "path to an owner-only base64 Ed25519 private key")
	outputPath := flag.String("output", "", "path for the signed envelope JSON")
	flag.Parse()
	if err := run(*manifestPath, *privateKeyPath, *outputPath); err != nil {
		fmt.Fprintln(os.Stderr, "farm-client-update-manifest: signing failed")
		os.Exit(1)
	}
}

func run(manifestPath, privateKeyPath, outputPath string) error {
	manifestPath = filepath.Clean(strings.TrimSpace(manifestPath))
	privateKeyPath = filepath.Clean(strings.TrimSpace(privateKeyPath))
	outputPath = filepath.Clean(strings.TrimSpace(outputPath))
	if !filepath.IsAbs(manifestPath) || !filepath.IsAbs(privateKeyPath) || !filepath.IsAbs(outputPath) {
		return backend.ErrFarmClientUpdateInvalid
	}
	keyInfo, err := os.Lstat(privateKeyPath)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode()&os.ModeSymlink != 0 || keyInfo.Mode().Perm()&0o077 != 0 {
		return backend.ErrFarmClientUpdateSignature
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	envelope, err := backend.BuildFarmClientUpdateEnvelope(manifest, strings.TrimSpace(string(key)), time.Now())
	for index := range key {
		key[index] = 0
	}
	if err != nil {
		return err
	}
	directory := filepath.Dir(outputPath)
	temporary, err := os.CreateTemp(directory, ".farm-client-update-envelope-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(envelope); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, outputPath)
}
