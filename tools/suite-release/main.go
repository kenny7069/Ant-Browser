// suite-release builds and signs Ant Browser Suite release manifests.
//
//	suite-release keygen   -private-key-file ABS -key-id ID
//	suite-release manifest -payload ABS -version V -os darwin -arch arm64 \
//	    -commits ANT,AGENT,CONTROL -core chromium=V,xray=V,sing-box=V \
//	    -config-schema N -capabilities a,b -output ABS
//	suite-release sign     -manifest ABS -private-key-file ABS -key-id ID -output ABS
//
// The manifest covers every payload file (and, for macOS, every bundle
// symlink) except the manifest and envelope themselves.  Dependencies come
// from the payload LICENSES.json artifacts so the signed legal binding is
// exactly what ships.
package main

import (
	"ant-chrome/backend"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("command required: keygen | manifest | sign"))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "manifest":
		err = runManifest(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "suite-release:", err)
	os.Exit(1)
}

func absolute(value, name string) (string, error) {
	value = filepath.Clean(strings.TrimSpace(value))
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("-%s must be an absolute path", name)
	}
	return value, nil
}

func runKeygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	keyPath := flags.String("private-key-file", "", "absolute path for the new owner-only private key")
	keyID := flags.String("key-id", "", "release key identifier")
	if err := flags.Parse(args); err != nil {
		return err
	}
	path, err := absolute(*keyPath, "private-key-file")
	if err != nil || strings.TrimSpace(*keyID) == "" {
		return errors.New("keygen needs -private-key-file and -key-id")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(private.Seed()) + "\n"); err != nil {
		return err
	}
	encoded, _ := json.Marshal(map[string]string{"key_id": *keyID, "public_key": base64.StdEncoding.EncodeToString(public)})
	fmt.Println(string(encoded))
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must be an owner-only regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("private key is not a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

type licenseManifest struct {
	SchemaVersion int `json:"schema_version"`
	Artifacts     []struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		NoticeFile string `json:"notice_file"`
	} `json:"artifacts"`
}

func isMachO(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return false
	}
	for _, magic := range [][]byte{{0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca}} {
		if bytes.Equal(header, magic) {
			return true
		}
	}
	return false
}

// role classifies one payload file.  Executable Mach-O files are binaries
// (codesign-verified), other Mach-O images are libraries, notices are legal.
func role(relative, path string, info fs.FileInfo, goos string) (string, bool) {
	if relative == "LICENSES.json" || strings.HasPrefix(relative, "licenses/") {
		return backend.SuiteReleaseEntryLegal, false
	}
	executable := info.Mode().Perm()&0o111 != 0
	if isMachO(path) {
		if executable && !strings.HasSuffix(relative, ".dylib") && !strings.HasSuffix(relative, ".so") {
			return backend.SuiteReleaseEntryBinary, true
		}
		return backend.SuiteReleaseEntryLibrary, false
	}
	if goos != "darwin" && executable && !strings.Contains(relative, ".app/") && !strings.Contains(relative, ".framework/") {
		// Windows PE payloads carry no Mach-O magic but still ship executables.
		// On macOS only Mach-O is code: a script's signature lives in xattrs
		// that pkgbuild drops, so it is covered by its digest as an asset.
		return backend.SuiteReleaseEntryBinary, true
	}
	return backend.SuiteReleaseEntryAsset, false
}

func runManifest(args []string) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	payload := flags.String("payload", "", "absolute payload root")
	version := flags.String("version", "", "Suite SemVer")
	goos := flags.String("os", "", "target OS")
	arch := flags.String("arch", "", "target architecture")
	commits := flags.String("commits", "", "ant_browser,farm_agent,farm_control commit SHAs")
	core := flags.String("core", "", "name=version core versions")
	configSchema := flags.Int("config-schema", 0, "Ant config schema")
	capabilities := flags.String("capabilities", "", "comma-separated capabilities")
	output := flags.String("output", "", "absolute output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	root, err := absolute(*payload, "payload")
	if err != nil {
		return err
	}
	outputPath, err := absolute(*output, "output")
	if err != nil {
		return err
	}
	commitValues := strings.Split(*commits, ",")
	if len(commitValues) != 3 {
		return errors.New("-commits needs three SHAs")
	}
	manifest := backend.SuiteReleaseManifest{
		SchemaVersion: 1, Version: *version,
		Target:       backend.SuiteReleaseTarget{OS: *goos, Arch: *arch},
		Commits:      backend.SuiteReleaseCommits{AntBrowser: commitValues[0], FarmAgent: commitValues[1], FarmControl: commitValues[2]},
		ConfigSchema: *configSchema, Capabilities: []string{}, CoreVersions: map[string]string{},
		Dependencies: []backend.SuiteReleaseDependency{},
	}
	for _, capability := range strings.Split(*capabilities, ",") {
		if capability = strings.TrimSpace(capability); capability != "" {
			manifest.Capabilities = append(manifest.Capabilities, capability)
		}
	}
	for _, pair := range strings.Split(*core, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return fmt.Errorf("invalid -core entry %q", pair)
		}
		manifest.CoreVersions[name] = value
	}
	raw, err := os.ReadFile(filepath.Join(root, "LICENSES.json"))
	if err != nil {
		return errors.New("payload LICENSES.json is required")
	}
	var licenses licenseManifest
	if err := json.Unmarshal(raw, &licenses); err != nil || licenses.SchemaVersion != 1 {
		return errors.New("payload LICENSES.json is invalid")
	}
	for _, artifact := range licenses.Artifacts {
		manifest.Dependencies = append(manifest.Dependencies, backend.SuiteReleaseDependency{Name: artifact.Name, Version: artifact.Version, LicenseRef: artifact.NoticeFile})
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || relative == "release-manifest.json" || relative == "release-manifest.envelope.json" {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256([]byte(target))
			manifest.Entries = append(manifest.Entries, backend.SuiteReleaseEntry{Path: relative, Role: backend.SuiteReleaseEntrySymlink, SHA256: hex.EncodeToString(digest[:])})
			return nil
		case info.IsDir():
			return nil
		case !info.Mode().IsRegular():
			return fmt.Errorf("unsupported payload entry %s", relative)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		entryRole, executable := role(relative, path, info, *goos)
		manifest.Entries = append(manifest.Entries, backend.SuiteReleaseEntry{Path: relative, Role: entryRole, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Executable: executable})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	encoded, err := backend.MarshalSuiteReleaseManifest(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, encoded, 0o644)
}

func runSign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "", "absolute manifest path")
	keyPath := flags.String("private-key-file", "", "absolute owner-only private key")
	keyID := flags.String("key-id", "", "release key identifier")
	output := flags.String("output", "", "absolute envelope output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	manifestFile, err := absolute(*manifestPath, "manifest")
	if err != nil {
		return err
	}
	keyFile, err := absolute(*keyPath, "private-key-file")
	if err != nil {
		return err
	}
	outputPath, err := absolute(*output, "output")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(manifestFile)
	if err != nil {
		return err
	}
	key, err := loadPrivateKey(keyFile)
	if err != nil {
		return err
	}
	envelope, err := backend.SignSuiteReleaseManifest(raw, *keyID, key)
	if err != nil {
		return err
	}
	if _, err := backend.VerifySuiteReleaseManifest(raw, envelope, backend.SuiteReleaseTrustAnchor{KeyID: *keyID, PublicKey: key.Public().(ed25519.PublicKey)}); err != nil {
		return err
	}
	return os.WriteFile(outputPath, envelope, 0o644)
}
