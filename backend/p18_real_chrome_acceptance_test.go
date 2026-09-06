package backend

import (
	"ant-chrome/backend/internal/browser"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestP18RealChromeAcceptance launches only fresh temporary profiles.
// Run explicitly with P18_REAL_CHROME=1; this is not a mock-CDP test.
func TestP18RealChromeAcceptance(t *testing.T) {
	if os.Getenv("P18_REAL_CHROME") != "1" {
		t.Skip("explicit real Chrome opt-in required")
	}
	for _, facade := range []bool{false, true} {
		t.Run(fmt.Sprint("app=", facade), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Browser.UserDataRoot = t.TempDir()
			cfg.Browser.StartReadyTimeoutMs = 10000
			cfg.Browser.StartStableWindowMs = 100
			cfg.Browser.DefaultStartURLs = []string{}
			coreRoot := os.Getenv("P18_REAL_CHROME_CORE")
			if coreRoot == "" {
				coreRoot = "/Applications"
			}
			cfg.Browser.Cores = []BrowserCore{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
			userDataDir := filepath.Join(t.TempDir(), "P1.8 中文 profile")
			if err := os.Mkdir(userDataDir, 0700); err != nil {
				t.Fatal(err)
			}
			p := BrowserProfile{ProfileId: "p18-isolated", ProfileName: "P18 isolated", CoreId: "chrome", UserDataDir: userDataDir, ProxyConfig: "direct://", RestoreLastSession: "never", LaunchArgs: []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking"}}
			var s *BrowserRuntimeService
			var a *App
			var err error
			if facade {
				a = NewApp(t.TempDir())
				a.config = cfg
				a.browserMgr = browser.NewManager(cfg, a.appRoot)
				a.browserMgr.Profiles[p.ProfileId] = &p
				s, err = a.browserRuntimeService()
			} else {
				s, err = NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{p}, Host: BrowserRuntimeHost{
					StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
						return NewBrowserRuntimeLocalProcess(plan.Spec)
					},
					StopProcess: func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
					CanConnect:  canConnectDebugPort, TryCloseCDP: tryCloseBrowserViaCDP,
					CreateTarget: createBrowserStartTarget,
				}})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, e := s.Stop(p.ProfileId); e != nil {
					t.Errorf("cleanup: %v", e)
				}
			}()
			start := s.Start
			stop := s.Stop
			status := s.Status
			if facade {
				start = a.BrowserInstanceStart
				stop = a.BrowserInstanceStop
				status = a.BrowserInstanceStatus
			}
			first, e := start(p.ProfileId)
			if e != nil {
				t.Fatal(e)
			}
			if !first.Running || !first.DebugReady || first.Pid <= 0 || first.DebugPort <= 0 {
				t.Fatalf("not ready: %+v", first)
			}
			oldPID, oldPort, oldGen := first.Pid, first.DebugPort, s.Generation(p.ProfileId)
			if !facade {
				observer, e := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{p}, Host: BrowserRuntimeHost{
					StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
						return nil, fmt.Errorf("recovery must not launch")
					},
					StopProcess: func(*exec.Cmd) error { return fmt.Errorf("observer does not own a process") },
					DetectRuntime: func(dir string) (BrowserRuntimeDetection, bool) {
						d, ok := detectBrowserRuntimeByUserDataDir(dir)
						return BrowserRuntimeDetection{PID: d.PID, DebugPort: d.DebugPort, DebugReady: d.DebugReady}, ok
					},
					CanConnect: canConnectDebugPort,
				}})
				if e != nil {
					t.Fatal(e)
				}
				recovered, e := observer.Status(p.ProfileId)
				if e != nil || !recovered.Running || !recovered.DebugReady || recovered.DebugPort != oldPort {
					t.Fatalf("real recovery: %+v %v", recovered, e)
				}
				if e := observer.Shutdown(); e != nil {
					t.Fatalf("observer shutdown: %v", e)
				}
				if !canConnectDebugPort(oldPort, 200*time.Millisecond) {
					t.Fatal("observer Shutdown terminated unowned recovered Chrome")
				}
			}

			client := &http.Client{Timeout: 3 * time.Second}
			resp, e := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", oldPort))
			if e != nil {
				t.Fatal(e)
			}
			var ver map[string]interface{}
			e = json.NewDecoder(resp.Body).Decode(&ver)
			resp.Body.Close()
			if e != nil {
				t.Fatal(e)
			}
			t.Logf("real browser=%v pid=%d port=%d", ver["Browser"], oldPID, oldPort)
			wsURL, ok := ver["webSocketDebuggerUrl"].(string)
			if !ok {
				t.Fatal("no browser CDP endpoint")
			}
			conn, _, e := websocket.DefaultDialer.Dial(wsURL, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			e = conn.WriteJSON(map[string]interface{}{"id": 1, "method": "Browser.getVersion"})
			if e != nil {
				t.Fatal(e)
			}
			var reply map[string]interface{}
			e = conn.ReadJSON(&reply)
			conn.Close()
			if e != nil || reply["result"] == nil {
				t.Fatalf("real CDP: %v %v", reply, e)
			}
			again, e := start(p.ProfileId)
			if e != nil || again.Pid != oldPID || s.Generation(p.ProfileId) != oldGen {
				t.Fatalf("reuse: %+v %v", again, e)
			}
			current, e := status(p.ProfileId)
			if e != nil || current.Pid != oldPID || !current.DebugReady {
				t.Fatalf("status: %+v %v", current, e)
			}
			if facade {
				if ok, e := a.BrowserInstanceOpenUrl(p.ProfileId, "about:blank"); !ok || e != nil {
					t.Fatalf("OpenUrl: %v", e)
				}
			}
			stopped, e := stop(p.ProfileId)
			if e != nil || stopped.Running {
				t.Fatalf("stop: %+v %v", stopped, e)
			}
			if canConnectDebugPort(oldPort, 200*time.Millisecond) {
				t.Fatal("old endpoint alive after Stop")
			}
			restarted, e := start(p.ProfileId)
			if e != nil || !restarted.DebugReady || restarted.Pid == oldPID || s.Generation(p.ProfileId) <= oldGen {
				t.Fatalf("restart: %+v %v", restarted, e)
			}
			if !facade {
				if e := s.Shutdown(); e != nil {
					t.Fatal(e)
				}
				current, e := s.Status(p.ProfileId)
				if e != nil {
					t.Fatal(e)
				}
				if current.Running || canConnectDebugPort(restarted.DebugPort, 200*time.Millisecond) {
					t.Fatal("Shutdown returned success while service-owned Chrome remains alive")
				}
			}
			if facade {
				pid := restarted.Pid
				restarted, e = a.BrowserInstanceRestart(p.ProfileId)
				if e != nil || !restarted.DebugReady || restarted.Pid == pid {
					t.Fatalf("App Restart: %+v %v", restarted, e)
				}
			}
		})
	}
}
