package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func signedFarmClientUpdateFixture(t *testing.T, mutate func(*FarmClientUpdateManifest)) ([]byte, string, []byte) {
	t.Helper()
	artifact := []byte("verified update artifact")
	digest := sha256.Sum256(artifact)
	now := time.Now().UTC()
	entry := FarmClientUpdateArtifact{URL: "https://updates.example.invalid/client.bin", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))}
	manifest := FarmClientUpdateManifest{
		Version: "1.1.0", ProtocolVersion: FarmClientControlProtocolVersion,
		MinimumProtocolVersion: FarmClientControlProtocolVersion, Channel: "stable",
		PublishedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Artifacts: map[string]FarmClientUpdateArtifact{},
	}
	for target := range farmClientUpdateTargets {
		manifest.Artifacts[target] = entry
	}
	if mutate != nil {
		mutate(&manifest)
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(FarmClientUpdateEnvelope{
		Version:   FarmClientUpdateEnvelopeVersion,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope, base64.StdEncoding.EncodeToString(publicKey), artifact
}

func verifyFarmClientUpdateFixture(t *testing.T, raw []byte, key string, allowDowngrade bool) (FarmClientUpdateCandidate, error) {
	t.Helper()
	return VerifyFarmClientUpdateEnvelope(raw, key, "1.0.0", FarmClientControlProtocolVersion, "stable", runtime.GOOS, runtime.GOARCH, allowDowngrade, time.Now())
}

func TestFarmClientUpdateVerifiesSignedTarget(t *testing.T) {
	raw, key, _ := signedFarmClientUpdateFixture(t, nil)
	candidate, err := verifyFarmClientUpdateFixture(t, raw, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Manifest.Version != "1.1.0" || candidate.Target != runtime.GOOS+"-"+runtime.GOARCH {
		t.Fatalf("candidate=%+v", candidate)
	}
}

func TestFarmClientUpdateOfflineSignerProducesVerifiableEnvelope(t *testing.T) {
	_, _, _ = signedFarmClientUpdateFixture(t, nil)
	artifact := []byte("artifact")
	digest := sha256.Sum256(artifact)
	now := time.Now().UTC()
	manifest := FarmClientUpdateManifest{
		Version: "1.2.0", ProtocolVersion: FarmClientControlProtocolVersion,
		MinimumProtocolVersion: FarmClientControlProtocolVersion, Channel: "stable",
		PublishedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Artifacts: map[string]FarmClientUpdateArtifact{},
	}
	for target := range farmClientUpdateTargets {
		manifest.Artifacts[target] = FarmClientUpdateArtifact{URL: "https://updates.example.invalid/" + target, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))}
	}
	manifestRaw, _ := json.Marshal(manifest)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := BuildFarmClientUpdateEnvelope(manifestRaw, base64.StdEncoding.EncodeToString(privateKey), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFarmClientUpdateEnvelope(envelope, base64.StdEncoding.EncodeToString(publicKey), "1.0.0", FarmClientControlProtocolVersion, "stable", runtime.GOOS, runtime.GOARCH, false, now); err != nil {
		t.Fatal(err)
	}
}

func TestFarmClientUpdateRejectsSignatureAndStrictJSONFailures(t *testing.T) {
	raw, key, _ := signedFarmClientUpdateFixture(t, nil)
	var envelope map[string]any
	_ = json.Unmarshal(raw, &envelope)
	envelope["signature"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tampered, _ := json.Marshal(envelope)
	if _, err := verifyFarmClientUpdateFixture(t, tampered, key, false); !errors.Is(err, ErrFarmClientUpdateSignature) {
		t.Fatalf("signature err=%v", err)
	}
	duplicate := []byte(`{"version":1,"version":1,"payload":"x","signature":"x"}`)
	if _, err := verifyFarmClientUpdateFixture(t, duplicate, key, false); !errors.Is(err, ErrFarmClientUpdateInvalid) {
		t.Fatalf("duplicate err=%v", err)
	}
}

func TestFarmClientUpdateRejectsTargetProtocolChannelExpiryAndIncompleteManifest(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*FarmClientUpdateManifest)
		expected error
	}{
		{"minimum protocol", func(value *FarmClientUpdateManifest) {
			value.ProtocolVersion = "bf-p1.7"
			value.MinimumProtocolVersion = "bf-p1.7"
		}, ErrFarmClientUpdateTarget},
		{"channel", func(value *FarmClientUpdateManifest) { value.Channel = "beta" }, ErrFarmClientUpdatePolicy},
		{"expiry", func(value *FarmClientUpdateManifest) {
			value.PublishedAt = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
			value.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		}, ErrFarmClientUpdatePolicy},
		{"missing target", func(value *FarmClientUpdateManifest) { delete(value.Artifacts, "windows-amd64") }, ErrFarmClientUpdateInvalid},
		{"wrong scheme", func(value *FarmClientUpdateManifest) {
			item := value.Artifacts["linux-amd64"]
			item.URL = "http://updates.example.invalid/client"
			value.Artifacts["linux-amd64"] = item
		}, ErrFarmClientUpdateInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw, key, _ := signedFarmClientUpdateFixture(t, test.mutate)
			if _, err := verifyFarmClientUpdateFixture(t, raw, key, false); !errors.Is(err, test.expected) {
				t.Fatalf("err=%v want=%v", err, test.expected)
			}
		})
	}
}

func TestFarmClientUpdateDowngradeRequiresBothPolicies(t *testing.T) {
	raw, key, _ := signedFarmClientUpdateFixture(t, func(value *FarmClientUpdateManifest) { value.Version = "0.9.0"; value.AllowDowngrade = true })
	if _, err := verifyFarmClientUpdateFixture(t, raw, key, false); !errors.Is(err, ErrFarmClientUpdatePolicy) {
		t.Fatalf("local policy err=%v", err)
	}
	if _, err := verifyFarmClientUpdateFixture(t, raw, key, true); err != nil {
		t.Fatal(err)
	}
	raw, key, _ = signedFarmClientUpdateFixture(t, func(value *FarmClientUpdateManifest) { value.Version = "0.9.0" })
	if _, err := verifyFarmClientUpdateFixture(t, raw, key, true); !errors.Is(err, ErrFarmClientUpdatePolicy) {
		t.Fatalf("manifest policy err=%v", err)
	}
}

func TestFarmClientUpdateSameVersionIsNotExecutableWork(t *testing.T) {
	raw, key, _ := signedFarmClientUpdateFixture(t, func(value *FarmClientUpdateManifest) { value.Version = "1.0.0" })
	if _, err := verifyFarmClientUpdateFixture(t, raw, key, false); !errors.Is(err, ErrFarmClientUpdateNoChange) {
		t.Fatalf("err=%v", err)
	}
}

func TestFarmClientUpdateStagesVerifiedArtifactWithoutExecutePermission(t *testing.T) {
	artifact := []byte("verified update artifact")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(artifact) }))
	defer server.Close()
	raw, key, _ := signedFarmClientUpdateFixture(t, func(value *FarmClientUpdateManifest) {
		for target, item := range value.Artifacts {
			item.URL = server.URL
			value.Artifacts[target] = item
		}
	})
	candidate, err := verifyFarmClientUpdateFixture(t, raw, key, false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageFarmClientUpdate(context.Background(), server.Client(), t.TempDir(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(staged.Path)
	if err != nil || string(value) != string(artifact) {
		t.Fatalf("read err=%v value=%q", err, value)
	}
	info, err := os.Stat(staged.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	if filepath.Ext(staged.Path) != ".bin" {
		t.Fatalf("path=%q", staged.Path)
	}
}

func TestFarmClientUpdateFetchesManifestThenStagesArtifact(t *testing.T) {
	artifact := []byte("verified update artifact")
	var envelope []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/manifest":
			_, _ = writer.Write(envelope)
		case "/artifact":
			_, _ = writer.Write(artifact)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	raw, key, _ := signedFarmClientUpdateFixture(t, func(value *FarmClientUpdateManifest) {
		for target, item := range value.Artifacts {
			item.URL = server.URL + "/artifact"
			value.Artifacts[target] = item
		}
	})
	envelope = raw
	config := FarmClientConfig{
		StateRoot: t.TempDir(), UpdateManifestURL: server.URL + "/manifest",
		UpdatePublicKey: key, UpdateChannel: "stable",
	}
	staged, err := FetchAndStageFarmClientUpdate(
		context.Background(), server.Client(), config, "1.0.0", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(staged.Path); err != nil || string(value) != string(artifact) {
		t.Fatalf("staged value=%q err=%v", value, err)
	}
}

func TestFarmClientUpdateConfigPinsKeyAndHTTPSAsOnePolicy(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := func() FarmClientConfig {
		return FarmClientConfig{
			ApplicationRoot: "/tmp/app", StateRoot: "/tmp/state",
			ControlURL: "wss://control.example.invalid/ws",
			Identity:   FarmClientIdentityConfig{NodeUID: "node-a", PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))},
		}
	}
	missingKey := base()
	missingKey.UpdateManifestURL = "https://updates.example.invalid/manifest"
	if err := missingKey.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("missing key err=%v", err)
	}
	httpURL := base()
	httpURL.UpdateManifestURL = "http://updates.example.invalid/manifest"
	httpURL.UpdatePublicKey = base64.StdEncoding.EncodeToString(publicKey)
	if err := httpURL.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("http URL err=%v", err)
	}
	valid := base()
	valid.UpdateManifestURL = "https://updates.example.invalid/manifest"
	valid.UpdatePublicKey = base64.StdEncoding.EncodeToString(publicKey)
	if err := valid.ValidateFarmClientConfig(); err != nil {
		t.Fatal(err)
	}
	if valid.UpdateChannel != "stable" {
		t.Fatalf("default channel=%q", valid.UpdateChannel)
	}
}

func TestFarmClientUpdateStageRejectsDigestMismatchAndRedirect(t *testing.T) {
	artifact := []byte("verified update artifact")
	redirectTargetReached := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect-target" {
			redirectTargetReached = true
		}
		_, _ = writer.Write(artifact)
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+"/redirect-target", http.StatusFound)
	}))
	defer redirect.Close()
	for _, test := range []struct {
		name     string
		url      string
		digest   string
		expected error
	}{
		{"digest", target.URL, strings.Repeat("0", 64), ErrFarmClientUpdateIntegrity},
		{"redirect", redirect.URL, hex.EncodeToString(sha256.New().Sum(nil)), ErrFarmClientUpdateUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, key, _ := signedFarmClientUpdateFixture(t, func(value *FarmClientUpdateManifest) {
				for targetName, item := range value.Artifacts {
					item.URL = test.url
					item.SHA256 = test.digest
					value.Artifacts[targetName] = item
				}
			})
			candidate, err := verifyFarmClientUpdateFixture(t, raw, key, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := StageFarmClientUpdate(context.Background(), target.Client(), t.TempDir(), candidate); !errors.Is(err, test.expected) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if redirectTargetReached {
		t.Fatal("redirect target was reached")
	}
}
