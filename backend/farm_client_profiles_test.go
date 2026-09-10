package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/database"
)

func TestFarmClientProfileProjectionIsAllowlistedAndABAFenced(t *testing.T) {
	profile := &BrowserProfile{
		ProfileId: "same-id", ProfileName: "Safe name", CreatedAt: "2026-09-09T00:00:00Z",
		IncarnationID: "first-generation",
		UserDataDir:   "/secret/path", FingerprintArgs: []string{"fingerprint-secret"},
		ProxyConfig: "http://user:proxy-secret@example", LaunchArgs: []string{"--secret"},
	}
	first, err := farmClientProjection(profile)
	if err != nil {
		t.Fatal(err)
	}
	replacement := *profile
	replacement.IncarnationID = "replacement-generation"
	second, err := farmClientProjection(&replacement)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProfileIncarnation == second.ProfileIncarnation {
		t.Fatal("same-ID replacement inherited the old pairing incarnation")
	}
	raw, _ := json.Marshal(first)
	for _, forbidden := range []string{"secret/path", "fingerprint-secret", "proxy-secret", "--secret", "userDataDir", "proxyConfig", "launchArgs"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("projection leaked %q: %s", forbidden, raw)
		}
	}
}

func TestFarmClientProfileCreatePersistsInCanonicalSQLite(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "app.db")
	seed, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Database.SQLite.Path = dbPath
	db, manager, err := loadFarmClientProfiles(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	host := &FarmClientHost{db: db, manager: manager}
	created, err := host.ProfileCreate("Created by Farm Client")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	check, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	stored, err := browser.NewSQLiteProfileDAO(check.GetConn()).GetById(created.ProfileID)
	if err != nil || stored.ProfileName != "Created by Farm Client" {
		t.Fatalf("canonical SQLite row=%+v err=%v", stored, err)
	}
}

func TestCanonicalSQLiteIncarnationChangesOnSameIDDeleteRecreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := database.NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	insert := func() string {
		_, err := db.GetConn().Exec(`INSERT INTO browser_profiles
			(profile_id, profile_name, created_at, updated_at)
			VALUES ('same-id', 'same', '2026-09-09T00:00:00Z', '2026-09-09T00:00:00Z')`)
		if err != nil {
			t.Fatal(err)
		}
		var incarnation string
		if err := db.GetConn().QueryRow(`SELECT incarnation_id FROM browser_profiles WHERE profile_id='same-id'`).Scan(&incarnation); err != nil {
			t.Fatal(err)
		}
		if incarnation == "" {
			t.Fatal("insert trigger did not assign an incarnation")
		}
		return incarnation
	}
	first := insert()
	if _, err := db.GetConn().Exec(`DELETE FROM browser_profiles WHERE profile_id='same-id'`); err != nil {
		t.Fatal(err)
	}
	second := insert()
	if first == second {
		t.Fatal("same-ID recreation inherited the deleted profile incarnation")
	}
}

func TestFarmClientPairProfileSignsSafeProjection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	codeRaw := make([]byte, farmClientPairingCodeBytes)
	_, _ = rand.Read(codeRaw)
	code := base64.StdEncoding.EncodeToString(codeRaw)
	manager := browser.NewManager(DefaultConfig(), t.TempDir())
	manager.Profiles["local-profile"] = &browser.Profile{
		ProfileId: "local-profile", ProfileName: "Safe display", CreatedAt: "2026-09-09T00:00:00Z",
		IncarnationID: "pair-test-generation",
		UserDataDir:   "/private/user-data", ProxyConfig: "proxy-password", FingerprintArgs: []string{"raw-fingerprint"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload farmClientPairWireRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if payload.DevicePublicKey != base64.StdEncoding.EncodeToString(publicKey) || payload.PairingCode != code {
			t.Error("identity/code mismatch")
		}
		message := farmClientPairingMessage("pair", payload.NodeUID, payload.RequestID, payload.IssuedAt, payload.PairingCode,
			payload.AntProfileID, payload.ProfileIncarnation, payload.SafeDisplayName, payload.LoginReadiness, "ant")
		signature, decodeErr := base64.StdEncoding.DecodeString(payload.Signature)
		if decodeErr != nil || !ed25519.Verify(publicKey, message, signature) {
			t.Error("pairing signature invalid")
		}
		raw, _ := json.Marshal(payload)
		for _, forbidden := range []string{"private/user-data", "proxy-password", "raw-fingerprint"} {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("wire leaked %q", forbidden)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"node_uid":"node-a","profile_id":"local-profile","server_profile_id":7,"status":"assigned"}`))
	}))
	defer server.Close()
	host := &FarmClientHost{
		config:   FarmClientConfig{PairingURL: server.URL + "/api/farm/pair"},
		identity: FarmClientIdentity{NodeUID: "node-a", PrivateKey: privateKey}, manager: manager,
	}
	result, err := host.PairProfile(context.Background(), "local-profile", code, server.Client())
	if err != nil || !result.Success || result.ServerProfileID != 7 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestFarmClientPairProfileRejectsServerIdentityContradiction(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	codeRaw := make([]byte, farmClientPairingCodeBytes)
	_, _ = rand.Read(codeRaw)
	code := base64.StdEncoding.EncodeToString(codeRaw)
	manager := browser.NewManager(DefaultConfig(), t.TempDir())
	manager.Profiles["local-profile"] = &browser.Profile{
		ProfileId: "local-profile", ProfileName: "Safe display", IncarnationID: "generation",
	}
	for name, response := range map[string]string{
		"wrong profile": `{"success":true,"node_uid":"node-a","profile_id":"other-profile","server_profile_id":7,"status":"assigned"}`,
		"wrong status":  `{"success":true,"node_uid":"node-a","profile_id":"local-profile","server_profile_id":7,"status":"disabled"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			host := &FarmClientHost{
				config:   FarmClientConfig{PairingURL: server.URL + "/api/farm/pair"},
				identity: FarmClientIdentity{NodeUID: "node-a", PrivateKey: privateKey}, manager: manager,
			}
			if _, err := host.PairProfile(context.Background(), "local-profile", code, server.Client()); !errors.Is(err, ErrFarmClientPairing) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestFarmClientPairingVerifierRejectsSameIDReplacement(t *testing.T) {
	manager := browser.NewManager(DefaultConfig(), t.TempDir())
	manager.Profiles["same"] = &browser.Profile{ProfileId: "same", CreatedAt: "same-second", IncarnationID: "first"}
	incarnation, _ := farmClientProfileIncarnation("same", "first")
	if err := farmClientValidateProfilePairing(manager, "same", incarnation); err != nil {
		t.Fatal(err)
	}
	manager.Profiles["same"].IncarnationID = "replacement"
	if err := farmClientValidateProfilePairing(manager, "same", incarnation); !errors.Is(err, ErrFarmClientPairingRejected) {
		t.Fatalf("replacement error=%v", err)
	}
}

func TestFarmCommandRejectsStalePairingBeforeRuntimeObservation(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "paired-profile")
	fixture.manager.Profiles["paired-profile"].IncarnationID = "current-generation"
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: fixture.runtime,
		NodeUID:               "node-test", ProviderInstanceID: "provider-test", FencingEpoch: 7,
		ProfilePairingVerifier: func(profileID, incarnation string) error {
			return farmClientValidateProfilePairing(fixture.manager, profileID, incarnation)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := farm.HandleCommand(FarmRuntimeCommand{
		Type: "command", NodeUID: "node-test", CorrelationID: "c3-stale",
		Command: "ensure_runtime", Payload: FarmRuntimeEnsureRequest{
			ProfileID: "paired-profile", PairingIncarnation: strings.Repeat("0", 64),
			NodeUID: "node-test", ProviderInstanceID: "provider-test", FencingEpoch: 7,
			ConfigHash: "hash", LaunchMode: FarmRuntimeLaunchModeDirectNoProxy,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Error != ErrFarmRuntimeStale.Error() {
		t.Fatalf("stale pairing response=%+v", response)
	}
	if fixture.detectCalls.Load() != 0 || fixture.startCalls.Load() != 0 {
		t.Fatal("stale pairing reached runtime observation or launch")
	}
}
