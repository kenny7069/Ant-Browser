package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ant-chrome/backend/internal/database"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// TestFarmClientInstalledArtifactNativeEnrollmentIdentity proves that the
// installed CLI, not the source test process, generates and saves the device
// identity through the native platform store. A second process boundary then
// loads that identity and verifies it is the private half of the public key
// sent to the enrollment endpoint.
func TestFarmClientInstalledArtifactNativeEnrollmentIdentity(t *testing.T) {
	if os.Getenv("C8_INSTALLED_NATIVE_IDENTITY_E2E") != "1" {
		t.Skip("set C8_INSTALLED_NATIVE_IDENTITY_E2E=1 on a native installed-artifact host")
	}
	executable := requireC8AbsolutePath(t, "C8_INSTALLED_CLIENT")
	installRoot := requireC8AbsolutePath(t, "C8_INSTALLED_ROOT")
	artifact := requireC8AbsolutePath(t, "C8_RELEASE_ARTIFACT")
	wantArtifactSHA := strings.ToLower(strings.TrimSpace(os.Getenv("C8_RELEASE_ARTIFACT_SHA256")))
	wantVersion := strings.TrimSpace(os.Getenv("C8_INSTALLED_VERSION"))
	if wantArtifactSHA == "" || wantVersion == "" || strings.Contains(wantVersion, "dev") {
		t.Fatal("C8 release artifact SHA-256 and non-development version are required")
	}
	assertC8InstalledPath(t, executable, installRoot)
	workingTree, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if c8PathWithin(executable, workingTree) {
		t.Fatalf("installed executable is inside source tree: %s", executable)
	}
	if got := c8FileSHA256(t, artifact); got != wantArtifactSHA {
		t.Fatalf("release artifact SHA-256=%s want=%s", got, wantArtifactSHA)
	}
	versionRaw, err := exec.Command(executable, "-version").Output()
	if err != nil {
		t.Fatalf("execute installed client version: %v", err)
	}
	var version FarmClientVersionInfo
	if err := json.Unmarshal(bytes.TrimSpace(versionRaw), &version); err != nil || version.Version != wantVersion || version.GOOS != runtime.GOOS || version.GOARCH != runtime.GOARCH {
		t.Fatalf("installed version=%+v decode_err=%v want=%s %s/%s", version, err, wantVersion, runtime.GOOS, runtime.GOARCH)
	}

	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	randomRef := make([]byte, 12)
	if _, err := rand.Read(randomRef); err != nil {
		t.Fatal(err)
	}
	ref, err := NewFarmClientIdentityKeyRef("c8-installed-native-" + runtime.GOOS + "-" + hex.EncodeToString(randomRef))
	if err != nil {
		t.Fatal(err)
	}
	codeRaw := bytes.Repeat([]byte{0x58}, farmClientEnrollmentCodeBytes)
	code := base64.StdEncoding.EncodeToString(codeRaw)
	clearBytes(codeRaw)
	const nodeUID = "c8-installed-native-identity-node"
	requests := make(chan farmClientEnrollmentWireRequest, 2)
	enrollmentServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload farmClientEnrollmentWireRequest
		if request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&payload) != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		requests <- payload
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(farmClientEnrollmentWireResponse{
			Success: true, EnrollmentID: 81, NodeID: 82, NodeUID: nodeUID, Status: "pending",
		})
	}))
	defer enrollmentServer.Close()
	trustRoot := filepath.Join(root, "enrollment-test-ca.pem")
	if err := os.WriteFile(trustRoot, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrollmentServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	controlEvidence := make(chan error, 1)
	var controlAccepted atomic.Bool
	var enrolledPublicKey ed25519.PublicKey
	controlServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		defer connection.Close()
		if !controlAccepted.CompareAndSwap(false, true) {
			return
		}
		controlEvidence <- verifyC8InstalledNativeIdentityWSS(connection, nodeUID, enrolledPublicKey)
	}))
	defer controlServer.Close()
	antConfigPath := filepath.Join(root, "ant.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	antConfig.Browser.UserDataRoot = root
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	profileDB, err := database.NewDB(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := profileDB.Migrate(); err != nil {
		_ = profileDB.Close()
		t.Fatal(err)
	}
	if err := profileDB.Close(); err != nil {
		t.Fatal(err)
	}
	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: stateRoot, AntConfigPath: antConfigPath,
		ControlURL: "ws" + strings.TrimPrefix(controlServer.URL, "http"), EnrollmentURL: enrollmentServer.URL,
		NodeName: "C8 installed native identity",
		Identity: FarmClientIdentityConfig{NodeUID: nodeUID, PrivateKeyRef: string(ref)},
	}
	configRaw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("native identity test ref: %s", ref)
	t.Cleanup(func() { cleanupC8NativeIdentity(t, stateRoot, ref) })
	var enrollmentStdout, enrollmentStderr bytes.Buffer
	for attempt := 0; attempt < 2; attempt++ {
		enrollmentCtx, cancelEnrollment := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(enrollmentCtx, executable, "-config", configPath, "-enroll")
		command.Env = append(os.Environ(), "SSL_CERT_FILE="+trustRoot, "GODEBUG=x509sslcertoverrideplatform=1")
		command.Stdin = strings.NewReader(code + "\n")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			cancelEnrollment()
			t.Fatalf("installed native enrollment attempt %d failed: %v stderr=%s", attempt+1, err, stderr.String())
		}
		cancelEnrollment()
		var result FarmClientEnrollmentResult
		if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); err != nil || result.NodeUID != nodeUID || result.EnrollmentID != 81 || result.NodeID != 82 || result.Status != "pending" {
			t.Fatalf("installed enrollment attempt %d result=%+v decode_err=%v stderr=%s", attempt+1, result, err, stderr.String())
		}
		enrollmentStdout.Write(stdout.Bytes())
		enrollmentStderr.Write(stderr.Bytes())
	}
	firstPayload, secondPayload := <-requests, <-requests
	for _, payload := range []farmClientEnrollmentWireRequest{firstPayload, secondPayload} {
		if payload.NodeUID != nodeUID || payload.DevicePublicKey == "" || payload.EnrollmentCode != code || payload.ClientVersion != wantVersion || payload.Platform != runtime.GOOS || payload.Architecture != runtime.GOARCH {
			t.Fatal("installed enrollment request identity metadata is incomplete")
		}
	}
	if firstPayload.DevicePublicKey != secondPayload.DevicePublicKey {
		t.Fatal("second installed enrollment process did not reuse the pending native identity")
	}
	publicKey, err := base64.StdEncoding.DecodeString(firstPayload.DevicePublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("installed enrollment sent an invalid public key")
	}
	enrolledPublicKey = append(ed25519.PublicKey(nil), publicKey...)
	assertC8NativeIdentityBackend(t, stateRoot, ref, enrolledPublicKey)

	clientCtx, cancelClient := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelClient()
	client := exec.CommandContext(clientCtx, executable, "-config", configPath)
	var clientStderr bytes.Buffer
	client.Stderr = &clientStderr
	if err := client.Start(); err != nil {
		t.Fatalf("start installed client with native identity ref: %v", err)
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Wait() }()
	select {
	case err := <-controlEvidence:
		if err != nil {
			t.Fatalf("installed client did not authenticate with enrolled native identity: %v stderr=%s", err, clientStderr.String())
		}
	case <-clientCtx.Done():
		t.Fatalf("installed native identity WSS authentication timed out: %v stderr=%s", clientCtx.Err(), clientStderr.String())
	}
	if client.Process != nil {
		if runtime.GOOS == "windows" {
			_ = client.Process.Kill()
		} else {
			_ = client.Process.Signal(os.Interrupt)
		}
	}
	select {
	case <-clientDone:
	case <-time.After(10 * time.Second):
		if client.Process != nil {
			_ = client.Process.Kill()
		}
		<-clientDone
	}
	combinedStderr := append(append([]byte(nil), enrollmentStderr.Bytes()...), clientStderr.Bytes()...)
	for label, raw := range map[string][]byte{"config": configRaw, "stdout": enrollmentStdout.Bytes(), "stderr": combinedStderr} {
		value := string(raw)
		if strings.Contains(value, code) {
			t.Fatalf("%s leaked enrollment secret", label)
		}
	}
}

func verifyC8InstalledNativeIdentityWSS(connection *websocket.Conn, nodeUID string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrFarmClientIdentityKeyCorrupt
	}
	var begin farmControlAuthBegin
	if err := connection.ReadJSON(&begin); err != nil {
		return err
	}
	deviceKey, err := base64.StdEncoding.DecodeString(begin.DevicePubKey)
	if err != nil || begin.Type != "auth_begin" || begin.NodeUID != nodeUID || !bytes.Equal(deviceKey, publicKey) {
		return ErrFarmClientIdentity
	}
	challengeRaw := make([]byte, 32)
	if _, err := rand.Read(challengeRaw); err != nil {
		return err
	}
	challenge := base64.StdEncoding.EncodeToString(challengeRaw)
	if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: nodeUID, Challenge: challenge}); err != nil {
		return err
	}
	var prove farmControlAuthProve
	if err := connection.ReadJSON(&prove); err != nil {
		return err
	}
	message, err := farmControlAuthMessage(nodeUID, challenge)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(prove.Signature)
	if err != nil || prove.Type != "auth_prove" || prove.Protocol != farmControlProtocolVersion || prove.NodeUID != nodeUID || prove.DevicePubKey != begin.DevicePubKey || prove.Challenge != challenge || !ed25519.Verify(publicKey, message, signature) {
		return ErrFarmClientIdentity
	}
	if err := connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: nodeUID, ControllerID: "c8-native-identity-controller", ControllerGeneration: 1}); err != nil {
		return err
	}
	_, err = readFarmClientFixtureHeartbeat(connection)
	return err
}
