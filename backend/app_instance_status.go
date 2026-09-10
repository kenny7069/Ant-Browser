package backend

import (
	"fmt"
	"strings"
	"time"

	"ant-chrome/backend/internal/logger"
)

func (a *App) BrowserInstanceStatus(profileId string) (*BrowserProfile, error) {
	service, err := a.browserRuntimeService()
	if err != nil {
		return nil, err
	}
	return service.Status(profileId)
}

func (a *App) BrowserInstanceOpenUrl(profileId string, targetUrl string) (bool, error) {
	profileId = strings.TrimSpace(profileId)
	normalizedTargetURL := strings.TrimSpace(targetUrl)
	if normalizedTargetURL == "" {
		return false, fmt.Errorf("打开地址失败：目标地址不能为空")
	}

	log := logger.New("Browser")
	service, serviceErr := a.browserRuntimeService()
	serviceIdentity := browserRuntimeIdentity{}
	serviceProcess := (*BrowserRuntimeProcess)(nil)
	if service != nil {
		serviceIdentity = service.identity(profileId)
		serviceProcess = service.processFor(profileId)
	}

	a.browserMgr.Mutex.Lock()
	profile, exists := a.browserMgr.Profiles[profileId]
	if !exists {
		a.browserMgr.Mutex.Unlock()
		return false, fmt.Errorf("打开地址失败：未找到实例配置（ID=%s）。请刷新列表后重试。", profileId)
	}
	a.ensureProfileLaunchCode(profile)
	trackedCmd := a.browserMgr.BrowserProcesses[profileId]
	if !profile.Running {
		userDataDir := a.browserMgr.ResolveUserDataDir(profile)
		if detection, ok := detectBrowserRuntimeByUserDataDir(userDataDir); ok && detection.DebugReady {
			a.markProfileRunningLocked(profileId, profile, nil, detection.PID, detection.DebugPort, true, "")
			log.Warn("打开地址前发现同一用户数据目录浏览器已运行，已同步实例状态",
				logger.F("profile_id", profileId),
				logger.F("user_data_dir", userDataDir),
				logger.F("pid", detection.PID),
				logger.F("debug_port", detection.DebugPort),
			)
		} else {
			a.browserMgr.Mutex.Unlock()
			return false, fmt.Errorf("打开地址失败：实例当前未运行，请先启动实例后再试。")
		}
	}
	live := isBrowserProfileLive(profile, trackedCmd)
	// ProcessState is written by exec.Cmd.Wait. The service exposes the
	// owner's Done channel as the only completion fence; reading ProcessState
	// here would race the sole reaper during a concurrent OpenUrl/status call.
	if live && serviceProcess != nil && serviceProcess.owner != nil &&
		serviceProcess.owner.Done() != nil && serviceIdentity.cmd == serviceProcess.cmd &&
		serviceIdentity.profile == profile && (trackedCmd == nil || trackedCmd == serviceProcess.cmd) &&
		browserRuntimeDone(serviceProcess.owner.Done()) {
		// A reaped launcher can still leave a detached Chrome endpoint alive;
		// retain that runtime when CDP answers, but treat an exited owner plus a
		// dead endpoint as stale even on platforms where Signal(0) reports a
		// zombie PID as present.
		live = profile.DebugPort > 0 && canConnectDebugPort(profile.DebugPort, 250*time.Millisecond)
	}
	if !live {
		staleDebugPort := profile.DebugPort
		stalePID := profile.Pid
		a.browserMgr.Mutex.Unlock()

		staleError := "打开地址失败：检测到实例运行状态已失效，请先重新启动实例。"
		if serviceErr == nil {
			// Carry the exact observation into the service gate. A fresh Start may
			// win the gate after this Manager snapshot is released; the strict
			// transition then becomes a no-op instead of stopping that replacement.
			if _, transitioned, transitionErr := service.markStaleRuntimeStoppedIfCurrent(profileId, serviceIdentity, profile, staleError); transitionErr != nil {
				return false, fmt.Errorf("打开地址失败：检测到实例运行状态已失效，清理运行态失败：%w", transitionErr)
			} else if !transitioned {
				return false, fmt.Errorf("%s", staleError)
			}
		} else {
			// Keep the legacy fallback only for an App whose shared service could
			// not be constructed. It still runs under Manager.Mutex and is never
			// used by the normal service-backed path.
			a.browserMgr.Mutex.Lock()
			if current := a.browserMgr.Profiles[profileId]; current != nil {
				a.markProfileStoppedLocked(profileId, current)
			}
			a.browserMgr.Mutex.Unlock()
			a.browserMgr.Mutex.Lock()
			if current := a.browserMgr.Profiles[profileId]; current != nil {
				current.LastError = staleError
			}
			a.browserMgr.Mutex.Unlock()
		}

		log.Warn("检测到实例运行状态已失效，取消复用打开地址",
			logger.F("profile_id", profileId),
			logger.F("debug_port", staleDebugPort),
			logger.F("pid", stalePID),
		)
		a.emitRuntimeEvent("browser:instance:stopped", profileId)
		return false, fmt.Errorf("%s", staleError)
	}

	snapshot := copyBrowserProfileSnapshot(profile)
	a.browserMgr.Mutex.Unlock()
	fingerprintExpectedArgs := a.fingerprintCheckExpectedArgsFromProfile(snapshot)
	normalizedTargetURL = a.resolveFingerprintCheckStartURLForExpectedArgsAndProfile(snapshot.ProfileId, fingerprintExpectedArgs, snapshot, normalizedTargetURL)

	if snapshot.DebugReady && snapshot.DebugPort > 0 {
		if err := createBrowserStartTarget(snapshot.DebugPort, normalizedTargetURL); err == nil {
			log.Info("复用运行中实例通过 CDP 打开地址",
				logger.F("profile_id", profileId),
				logger.F("debug_port", snapshot.DebugPort),
				logger.F("target_url", normalizedTargetURL),
			)
			return true, nil
		} else {
			log.Warn("运行中实例通过 CDP 打开地址失败，回退到浏览器进程唤起",
				logger.F("profile_id", profileId),
				logger.F("debug_port", snapshot.DebugPort),
				logger.F("target_url", normalizedTargetURL),
				logger.F("error", err.Error()),
			)
		}
	}

	if err := a.openBrowserWindowForRunningProfile(snapshot, nil, []string{normalizedTargetURL}); err != nil {
		openErr := fmt.Errorf("打开地址失败：实例运行中，但复用现有会话打开页面失败：%w", err)
		log.Error("运行中实例打开地址失败",
			logger.F("profile_id", profileId),
			logger.F("debug_ready", snapshot.DebugReady),
			logger.F("debug_port", snapshot.DebugPort),
			logger.F("target_url", normalizedTargetURL),
			logger.F("error", err.Error()),
			logger.F("reason", openErr.Error()),
		)
		return false, openErr
	}

	log.Info("复用运行中实例通过浏览器进程打开地址",
		logger.F("profile_id", profileId),
		logger.F("debug_ready", snapshot.DebugReady),
		logger.F("debug_port", snapshot.DebugPort),
		logger.F("target_url", normalizedTargetURL),
	)
	return true, nil
}

func (a *App) BrowserInstanceGetTabs(profileId string) []BrowserTab {
	return []BrowserTab{
		{TabId: "tab-1", Title: "新标签页", Url: "about:blank", Active: true},
		{TabId: "tab-2", Title: "示例站点", Url: "https://example.com", Active: false},
	}
}
