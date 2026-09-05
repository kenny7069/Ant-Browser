package backend

import (
	"ant-chrome/backend/internal/browser"
	"errors"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newRuntimeStatusServiceTest(t *testing.T, host BrowserRuntimeHost) (*BrowserRuntimeService, *browser.Manager) {
	t.Helper()
	service, manager := newRuntimeServiceTest(t)
	for _, profileID := range []string{"profile-1", "profile-2"} {
		manager.Profiles[profileID].UserDataDir = filepath.Join(t.TempDir(), profileID)
	}
	service.SetHost(host)
	return service, manager
}

func TestBrowserRuntimeStatusAdoptsDetectedReadyProfile(t *testing.T) {
	var detectCalls atomic.Int32
	var ensureCalls atomic.Int32
	var activeCalls atomic.Int32
	var startedCalls atomic.Int32
	var detectedDir string
	host := BrowserRuntimeHost{
		EnsureLaunchCode: func(profile *browser.Profile) {
			ensureCalls.Add(1)
			profile.LaunchCode = "status-code"
		},
		ResolveUserDataDir: func(profile *browser.Profile) string { return profile.UserDataDir },
		DetectRuntime: func(userDataDir string) (BrowserRuntimeDetection, bool) {
			detectCalls.Add(1)
			detectedDir = userDataDir
			return BrowserRuntimeDetection{PID: 4101, DebugPort: 9411, DebugReady: true}, true
		},
		SetActiveProfile: func(*browser.Profile) { activeCalls.Add(1) },
		EmitStarted:      func(*browser.Profile, bool) { startedCalls.Add(1) },
	}
	service, manager := newRuntimeStatusServiceTest(t, host)
	expectedDir := manager.Profiles["profile-1"].UserDataDir

	got, err := service.Status("profile-1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got == nil || !got.Running || !got.DebugReady || got.Pid != 4101 || got.DebugPort != 9411 || got.LastStartAt == "" {
		t.Fatalf("adopted status = %+v", got)
	}
	if got.LaunchCode != "status-code" {
		t.Fatalf("launch code = %q, want status-code", got.LaunchCode)
	}
	if detectCalls.Load() != 1 || ensureCalls.Load() != 1 || detectedDir != expectedDir {
		t.Fatalf("status host calls = detect:%d ensure:%d dir:%q, want one and %q", detectCalls.Load(), ensureCalls.Load(), detectedDir, expectedDir)
	}
	if activeCalls.Load() != 1 {
		t.Fatalf("SetActiveProfile calls = %d, want 1", activeCalls.Load())
	}
	if startedCalls.Load() != 0 {
		t.Fatalf("Status emitted started events = %d, want 0", startedCalls.Load())
	}
	if generation := service.Generation("profile-1"); generation == 0 {
		t.Fatal("Status adoption did not publish a generation")
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	_, tracked := manager.BrowserProcesses["profile-1"]
	manager.Mutex.Unlock()
	if current.Pid != got.Pid || current.DebugPort != got.DebugPort || tracked {
		t.Fatalf("manager status = %+v, tracked process = %v", current, tracked)
	}
}

func TestBrowserRuntimeStatusNotReadyPreservesStoppedProfile(t *testing.T) {
	for _, test := range []struct {
		name string
		ok   bool
	}{
		{name: "not found", ok: false},
		{name: "not ready", ok: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var detectCalls atomic.Int32
			host := BrowserRuntimeHost{
				DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
					detectCalls.Add(1)
					if !test.ok {
						return BrowserRuntimeDetection{}, false
					}
					return BrowserRuntimeDetection{PID: 4102, DebugPort: 9412, DebugReady: false}, true
				},
			}
			service, manager := newRuntimeStatusServiceTest(t, host)
			got, err := service.Status("profile-1")
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if got == nil || got.Running || got.DebugReady || got.Pid != 0 || got.DebugPort != 0 {
				t.Fatalf("not-ready status = %+v", got)
			}
			if detectCalls.Load() != 1 || service.Generation("profile-1") != 0 {
				t.Fatalf("not-ready detection/generation = %d/%d", detectCalls.Load(), service.Generation("profile-1"))
			}
			manager.Mutex.Lock()
			current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
			manager.Mutex.Unlock()
			if current.Running || current.DebugReady {
				t.Fatalf("manager profile became running: %+v", current)
			}
		})
	}
}

func TestBrowserRuntimeStatusAlreadyRunningDoesNotReAdopt(t *testing.T) {
	var detectCalls atomic.Int32
	var activeCalls atomic.Int32
	var startedCalls atomic.Int32
	host := BrowserRuntimeHost{
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			detectCalls.Add(1)
			return BrowserRuntimeDetection{}, false
		},
		SetActiveProfile: func(*browser.Profile) { activeCalls.Add(1) },
		EmitStarted:      func(*browser.Profile, bool) { startedCalls.Add(1) },
	}
	service, manager := newRuntimeStatusServiceTest(t, host)
	profile := manager.Profiles["profile-1"]
	identity := service.markRunning("profile-1", profile, nil, 4201, 9421, true, "")

	first, err := service.Status("profile-1")
	if err != nil {
		t.Fatalf("first Status: %v", err)
	}
	second, err := service.Status("profile-1")
	if err != nil {
		t.Fatalf("second Status: %v", err)
	}
	if detectCalls.Load() != 0 || activeCalls.Load() != 0 || startedCalls.Load() != 0 {
		t.Fatalf("already-running callbacks = detect:%d active:%d started:%d", detectCalls.Load(), activeCalls.Load(), startedCalls.Load())
	}
	if got := service.Generation("profile-1"); got != identity.generation {
		t.Fatalf("generation changed from %d to %d", identity.generation, got)
	}
	if first.Pid != 4201 || second.DebugPort != 9421 || !second.Running {
		t.Fatalf("already-running snapshots = first:%+v second:%+v", first, second)
	}
}

func TestBrowserRuntimeStatusDetectionCASRejectsManagerUpdate(t *testing.T) {
	detectEntered := make(chan struct{})
	releaseDetect := make(chan struct{})
	host := BrowserRuntimeHost{
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			close(detectEntered)
			<-releaseDetect
			return BrowserRuntimeDetection{PID: 4301, DebugPort: 9431, DebugReady: true}, true
		},
		SetActiveProfile: func(*browser.Profile) { t.Fatal("stale detection adopted after Manager.Update") },
	}
	service, manager := newRuntimeStatusServiceTest(t, host)
	result := make(chan struct {
		profile *browser.Profile
		err     error
	}, 1)
	go func() {
		profile, err := service.Status("profile-1")
		result <- struct {
			profile *browser.Profile
			err     error
		}{profile: profile, err: err}
	}()
	select {
	case <-detectEntered:
	case <-time.After(time.Second):
		t.Fatal("Status did not reach detection")
	}
	if _, err := manager.Update("profile-1", browser.ProfileInput{
		ProfileName:        "updated during status",
		UserDataDir:        manager.Profiles["profile-1"].UserDataDir,
		CoreId:             manager.Profiles["profile-1"].CoreId,
		RestoreLastSession: "never",
	}); err != nil {
		t.Fatalf("Manager.Update: %v", err)
	}
	close(releaseDetect)
	select {
	case outcome := <-result:
		if outcome.err != nil {
			t.Fatalf("Status: %v", outcome.err)
		}
		if outcome.profile == nil || outcome.profile.Running || outcome.profile.ProfileName != "updated during status" {
			t.Fatalf("stale Status result = %+v", outcome.profile)
		}
	case <-time.After(time.Second):
		t.Fatal("Status did not finish after detection release")
	}
	if service.Generation("profile-1") != 0 {
		t.Fatal("stale detection published a generation")
	}
}

func TestBrowserRuntimeStatusDetectionCASRejectsDeleteRecreateSameValue(t *testing.T) {
	detectEntered := make(chan struct{})
	releaseDetect := make(chan struct{})
	host := BrowserRuntimeHost{
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			close(detectEntered)
			<-releaseDetect
			return BrowserRuntimeDetection{PID: 4401, DebugPort: 9441, DebugReady: true}, true
		},
		SetActiveProfile: func(*browser.Profile) { t.Fatal("stale detection adopted replacement profile") },
	}
	service, manager := newRuntimeStatusServiceTest(t, host)
	manager.Mutex.Lock()
	original := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	manager.Mutex.Unlock()
	result := make(chan error, 1)
	go func() {
		_, err := service.Status("profile-1")
		result <- err
	}()
	select {
	case <-detectEntered:
	case <-time.After(time.Second):
		t.Fatal("Status did not reach detection")
	}
	manager.Mutex.Lock()
	delete(manager.Profiles, "profile-1")
	manager.Profiles["profile-1"] = copyBrowserProfileSnapshot(original)
	manager.Mutex.Unlock()
	close(releaseDetect)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Status did not finish after detection release")
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	manager.Mutex.Unlock()
	if current.Running || service.Generation("profile-1") != 0 {
		t.Fatalf("replacement profile was changed by stale Status: profile=%+v generation=%d", current, service.Generation("profile-1"))
	}
}

func TestBrowserRuntimeStatusAndStartSameProfileDoNotDoubleAdopt(t *testing.T) {
	detectEntered := make(chan struct{})
	releaseDetect := make(chan struct{})
	var detectCalls atomic.Int32
	var startCalls atomic.Int32
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			return nil, errors.New("StartProcess must not run after Status adoption")
		},
		StopProcess: func(*exec.Cmd) error { return nil },
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			if detectCalls.Add(1) == 1 {
				close(detectEntered)
				<-releaseDetect
			}
			return BrowserRuntimeDetection{PID: 4501, DebugPort: 9451, DebugReady: true}, true
		},
	}
	service, _ := newRuntimeStatusServiceTest(t, host)
	statusResult := make(chan error, 1)
	go func() {
		_, err := service.Status("profile-1")
		statusResult <- err
	}()
	select {
	case <-detectEntered:
	case <-time.After(time.Second):
		t.Fatal("Status did not reach detection")
	}
	startResult := make(chan error, 1)
	go func() {
		_, err := service.Start("profile-1")
		startResult <- err
	}()
	close(releaseDetect)
	for name, result := range map[string]chan error{"Status": statusResult, "Start": startResult} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}
	if detectCalls.Load() != 1 || startCalls.Load() != 0 {
		t.Fatalf("Status/Start host calls = detect:%d start:%d", detectCalls.Load(), startCalls.Load())
	}
	if generation := service.Generation("profile-1"); generation == 0 {
		t.Fatal("Status/Start did not retain adopted generation")
	}
}

func TestBrowserRuntimeStatusDetectionDifferentProfilesParallel(t *testing.T) {
	var entered atomic.Int32
	enteredProfiles := make(chan string, 2)
	releaseDetect := make(chan struct{})
	host := BrowserRuntimeHost{
		DetectRuntime: func(userDataDir string) (BrowserRuntimeDetection, bool) {
			entered.Add(1)
			enteredProfiles <- userDataDir
			<-releaseDetect
			return BrowserRuntimeDetection{PID: 4600 + int(entered.Load()), DebugPort: 9460 + int(entered.Load()), DebugReady: true}, true
		},
	}
	service, manager := newRuntimeStatusServiceTest(t, host)
	results := make(chan error, 2)
	for _, profileID := range []string{"profile-1", "profile-2"} {
		profileID := profileID
		go func() {
			_, err := service.Status(profileID)
			results <- err
		}()
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case userDataDir := <-enteredProfiles:
			seen[userDataDir] = true
		case <-time.After(time.Second):
			t.Fatalf("different-profile Status detection was serialized; entered=%d", entered.Load())
		}
	}
	close(releaseDetect)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("parallel Status: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("parallel Status did not finish")
		}
	}
	if len(seen) != 2 || service.Generation("profile-1") == 0 || service.Generation("profile-2") == 0 {
		t.Fatalf("parallel Status identities = seen:%v generations:%d/%d", seen, service.Generation("profile-1"), service.Generation("profile-2"))
	}
	manager.Mutex.Lock()
	for _, profileID := range []string{"profile-1", "profile-2"} {
		if !manager.Profiles[profileID].Running {
			t.Errorf("profile %s did not become running", profileID)
		}
	}
	manager.Mutex.Unlock()
}
