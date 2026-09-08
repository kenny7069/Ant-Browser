//go:build windows

package proxy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsDACLE2EOptInEnv       = "BF_P1_WINDOWS_DACL_E2E"
	windowsDACLE2EParentEnv      = "BF_P1_WINDOWS_DACL_SHARED_PARENT"
	windowsDACLE2EAltUserEnv     = "BF_P1_WINDOWS_DACL_ALT_USERNAME"
	windowsDACLE2EAltDomainEnv   = "BF_P1_WINDOWS_DACL_ALT_DOMAIN"
	windowsDACLE2EAltPasswordEnv = "BF_P1_WINDOWS_DACL_ALT_PASSWORD"

	windowsLogon32LogonNetwork    = 3
	windowsLogon32ProviderDefault = 0
	windowsDACLE2EProbeName       = "bf-p1-public-probe.txt"
)

var (
	advapi32DLL                 = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW              = advapi32DLL.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32DLL.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = advapi32DLL.NewProc("RevertToSelf")
)

type windowsDACLE2EAlternateResults struct {
	probeData  []byte
	probeErr   error
	readErr    error
	writeErr   error
	removeErr  error
	cleanupErr error
}

// TestSecureRuntimeWindowsDACLE2E is deliberately opt-in because it requires
// credentials for a second, real Windows account. The runner must grant that
// account read/traverse access to the shared parent and probe file. That
// positive control prevents a parent-directory denial from masquerading as a
// successful owner-only DACL check.
func TestSecureRuntimeWindowsDACLE2E(t *testing.T) {
	if os.Getenv(windowsDACLE2EOptInEnv) != "1" {
		t.Skipf("set %s=1 on a real Windows runner to enable the DACL acceptance test", windowsDACLE2EOptInEnv)
	}

	parent := requireWindowsDACLE2EEnv(t, windowsDACLE2EParentEnv)
	altUser := requireWindowsDACLE2EEnv(t, windowsDACLE2EAltUserEnv)
	altDomain := requireWindowsDACLE2EEnv(t, windowsDACLE2EAltDomainEnv)
	altPassword := requireWindowsDACLE2EEnv(t, windowsDACLE2EAltPasswordEnv)
	parent, err := filepath.Abs(parent)
	if err != nil {
		t.Fatalf("resolve shared parent: %v", err)
	}
	if strings.ContainsAny(parent, "&|<>^\"") {
		t.Fatalf("%s contains a cmd.exe metacharacter", windowsDACLE2EParentEnv)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		t.Fatalf("shared parent is not an accessible directory: %v", err)
	}
	probePath := filepath.Join(parent, windowsDACLE2EProbeName)
	const probeContents = "BF-P1-WINDOWS-DACL-PUBLIC-PROBE\n"
	if got, err := os.ReadFile(probePath); err != nil || string(got) != probeContents {
		t.Fatalf("shared-parent positive-control probe is missing or invalid: %v", err)
	}

	altToken, err := windowsDACLLogon(altUser, altDomain, altPassword)
	altPassword = ""
	_ = os.Unsetenv(windowsDACLE2EAltPasswordEnv)
	if err != nil {
		t.Fatalf("authenticate alternate Windows account: %v", err)
	}
	defer altToken.Close()
	ownerUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("resolve owner Windows SID: %v", err)
	}
	altTokenUser, err := altToken.GetTokenUser()
	if err != nil {
		t.Fatalf("resolve alternate Windows SID: %v", err)
	}
	if windows.EqualSid(ownerUser.User.Sid, altTokenUser.User.Sid) {
		t.Fatal("alternate Windows account resolves to the owner SID")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("create runtime authenticity key: %v", err)
	}
	identity, err := secureRuntimeCurrentProcessIdentity()
	if err != nil {
		t.Fatalf("resolve runtime owner process: %v", err)
	}
	writer, err := newSecureRuntimeWriterWithOptions("xray", secureRuntimeWriterOptions{
		tempParent:      parent,
		key:             key,
		processIdentity: identity,
		processLiveness: secureRuntimeProcessLiveness,
		ownerCheck:      secureRuntimeCheckOwnerAndMode,
	})
	if err != nil {
		t.Fatalf("create secure runtime writer: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(writer.root, "junction-node"))
		_ = writer.cleanup("owner-node")
		_ = os.Remove(writer.root)
	})

	runtimeDir, err := writer.runtimeDir("owner-node")
	if err != nil {
		t.Fatalf("create secure runtime directory: %v", err)
	}
	configData := []byte("opaque-acceptance-payload\n")
	configPath, err := writer.writeAtomic("owner-node", "xray-config.json", configData)
	if err != nil {
		t.Fatalf("write secure runtime config: %v", err)
	}
	handle, err := writer.handle("owner-node")
	if err != nil {
		t.Fatalf("resolve secure runtime handle: %v", err)
	}
	if got, err := os.ReadFile(configPath); err != nil || string(got) != string(configData) {
		t.Fatalf("owner could not read the secure runtime config: %v", err)
	}
	ownerAppend, err := os.OpenFile(configPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("owner could not open the secure runtime config for writing: %v", err)
	}
	if err := ownerAppend.Close(); err != nil {
		t.Fatalf("close owner write handle: %v", err)
	}
	for _, item := range []struct {
		path      string
		directory bool
	}{{writer.root, true}, {runtimeDir, true}, {configPath, false}} {
		info, err := os.Lstat(item.path)
		if err != nil {
			t.Fatalf("inspect owner path before DACL validation: %v", err)
		}
		if err := secureRuntimeCheckOwnerAndMode(item.path, info.Mode(), item.directory); err != nil {
			t.Fatalf("owner-only protected DACL validation failed: %v", err)
		}
	}

	outsideDir, err := os.MkdirTemp(parent, "bf-p1-dacl-outside-")
	if err != nil {
		t.Fatalf("create outside junction target: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outsideDir) })
	sentinelPath := filepath.Join(outsideDir, "sentinel.txt")
	const sentinelContents = "outside-boundary-must-remain\n"
	if err := os.WriteFile(sentinelPath, []byte(sentinelContents), 0o600); err != nil {
		t.Fatalf("write outside sentinel: %v", err)
	}
	junctionPath := filepath.Join(writer.root, "junction-node")
	junctionCommand := fmt.Sprintf(`mklink /J "%s" "%s"`, junctionPath, outsideDir)
	if output, err := exec.Command("cmd.exe", "/d", "/s", "/c", junctionCommand).CombinedOutput(); err != nil {
		t.Fatalf("create real Windows directory junction: %v (output length %d)", err, len(output))
	}
	if _, err := writer.runtimeDir("junction-node"); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("runtimeDir accepted a Windows junction: %v", err)
	}
	if got := writer.runtimeDirIfExists("junction-node"); got != "" {
		t.Fatal("runtimeDirIfExists exposed a Windows junction")
	}
	if _, err := writer.handle("junction-node"); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("handle accepted a Windows junction: %v", err)
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || string(got) != sentinelContents {
		t.Fatalf("junction rejection crossed the ownership boundary: %v", err)
	}
	if err := os.Remove(junctionPath); err != nil {
		t.Fatalf("remove test junction without traversing it: %v", err)
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || string(got) != sentinelContents {
		t.Fatalf("junction removal changed the outside target: %v", err)
	}

	var alt windowsDACLE2EAlternateResults
	if err := windowsDACLWithImpersonation(altToken, func() {
		alt.probeData, alt.probeErr = os.ReadFile(probePath)
		_, alt.readErr = os.ReadFile(configPath)
		var file *os.File
		file, alt.writeErr = os.OpenFile(configPath, os.O_WRONLY|os.O_TRUNC, 0)
		if file != nil {
			_ = file.Close()
		}
		alt.removeErr = os.Remove(configPath)
		alt.cleanupErr = handle.cleanup()
	}); err != nil {
		t.Fatalf("alternate-account impersonation failed: %v", err)
	}
	if alt.probeErr != nil || string(alt.probeData) != probeContents {
		t.Fatalf("alternate account could not read the shared-parent positive control: %v", alt.probeErr)
	}
	requireWindowsDACLAccessDenied(t, "read", alt.readErr)
	requireWindowsDACLAccessDenied(t, "write", alt.writeErr)
	requireWindowsDACLAccessDenied(t, "remove", alt.removeErr)
	requireWindowsDACLAccessDenied(t, "cleanup", alt.cleanupErr)
	if handle.isCleaned() {
		t.Fatal("non-owner cleanup marked the owner handle cleaned")
	}
	if got, err := os.ReadFile(configPath); err != nil || string(got) != string(configData) {
		t.Fatalf("non-owner operations changed the secure runtime config: %v", err)
	}
	if err := handle.cleanup(); err != nil {
		t.Fatalf("owner cleanup failed: %v", err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("owner cleanup left the secure runtime config: %v", err)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("owner cleanup left the secure runtime directory: %v", err)
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || string(got) != sentinelContents {
		t.Fatalf("owner cleanup crossed the ownership boundary: %v", err)
	}
}

func requireWindowsDACLE2EEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("opted-in Windows DACL acceptance test requires environment variable %s", name)
	}
	return value
}

func requireWindowsDACLAccessDenied(t *testing.T, operation string, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("alternate-account %s result was not Windows access denied: %v", operation, err)
	}
}

func windowsDACLLogon(username string, domain string, password string) (windows.Token, error) {
	usernamePtr, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return 0, err
	}
	domainPtr, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return 0, err
	}
	passwordPtr, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}
	var token windows.Token
	result, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(usernamePtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passwordPtr)),
		uintptr(windowsLogon32LogonNetwork),
		uintptr(windowsLogon32ProviderDefault),
		uintptr(unsafe.Pointer(&token)),
	)
	runtime.KeepAlive(usernamePtr)
	runtime.KeepAlive(domainPtr)
	runtime.KeepAlive(passwordPtr)
	if result == 0 {
		return 0, callErr
	}
	return token, nil
}

func windowsDACLWithImpersonation(token windows.Token, action func()) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, callErr := procImpersonateLoggedOnUser.Call(uintptr(token))
	if result == 0 {
		return callErr
	}
	defer func() {
		result, _, callErr := procRevertToSelf.Call()
		if result == 0 && err == nil {
			err = callErr
		}
	}()
	action()
	return nil
}
