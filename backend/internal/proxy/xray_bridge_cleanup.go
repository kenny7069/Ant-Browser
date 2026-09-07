package proxy

import (
	"ant-chrome/backend/internal/logger"
	"time"
)

func (m *XrayManager) cleanupLoop() {
	ticker := time.NewTicker(xrayBridgeCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.recycleIdleBridges()
		case <-m.stopCh:
			return
		}
	}
}

func (m *XrayManager) recycleIdleBridges() {
	now := time.Now()
	var stale []*XrayBridge

	m.mu.Lock()
	for key, bridge := range m.Bridges {
		if bridge == nil {
			delete(m.Bridges, key)
			continue
		}
		if bridge.RefCount > 0 {
			continue
		}
		if now.Sub(bridge.LastUsedAt) < xrayBridgeIdleTTL {
			continue
		}

		bridge.Stopping = true
		stale = append(stale, bridge)
		delete(m.Bridges, key)
	}
	m.mu.Unlock()

	if len(stale) == 0 {
		return
	}

	log := logger.New("Xray")
	for _, bridge := range stale {
		log.Info("回收空闲桥接进程", logger.F("key", bridge.NodeKey), logger.F("pid", bridge.Pid))
		m.stopBridgeProcess(bridge)
	}
}

// StopReleasedBridges immediately tears down only bridges with no active
// browser reference. It keeps the manager itself reusable (unlike StopAll),
// which is required when an isolated Farm runtime is strict-stopped and later
// recreated with a new fenced identity.
func (m *XrayManager) StopReleasedBridges() {
	if m == nil {
		return
	}
	var released []*XrayBridge
	m.mu.Lock()
	for key, bridge := range m.Bridges {
		if bridge == nil {
			delete(m.Bridges, key)
			continue
		}
		if bridge.RefCount > 0 {
			continue
		}
		bridge.Stopping = true
		released = append(released, bridge)
		delete(m.Bridges, key)
	}
	m.mu.Unlock()
	for _, bridge := range released {
		m.stopBridgeProcess(bridge)
	}
}

func (m *XrayManager) stopBridgeProcess(bridge *XrayBridge) {
	if bridge == nil || bridge.Cmd == nil || bridge.Cmd.Process == nil {
		return
	}
	_ = bridge.Cmd.Process.Kill()
	go m.cleanupRuntimeWhenTerminated(bridge)
}

func (m *XrayManager) cleanupRuntimeWhenTerminated(bridge *XrayBridge) {
	if bridge == nil {
		return
	}
	if bridge.ExitDone != nil {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-bridge.ExitDone:
		case <-timer.C:
			return
		}
	} else if bridge.Cmd != nil && bridge.Cmd.ProcessState == nil {
		return
	}
	bridge.Runtime.markProcessTerminated(bridge.RuntimeToken)
	_ = bridge.Runtime.cleanup()
}
