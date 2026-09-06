package backend

import (
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/logger"
	"ant-chrome/backend/internal/proxy"
	"fmt"
	"strings"
)

const temporaryDirectProxyID = "__direct__"

func (a *App) resolveBrowserStartProxy(input browserStartInput, profile *BrowserProfile) (string, profileProxyBridgeRef, bool, error) {
	log := logger.New("Browser")
	proxies := a.getLatestProxies()
	profileID := input.ProfileID

	if input.ForceDirectProxy {
		log.Warn("按请求直连启动实例",
			logger.F("profile_id", profileID),
			logger.F("proxy_id", profile.ProxyId),
		)
		return "direct://", profileProxyBridgeRef{}, false, nil
	}

	resolvedProxyID := strings.TrimSpace(profile.ProxyId)
	resolvedProxyConfig := strings.TrimSpace(profile.ProxyConfig)
	usingTemporaryProxy := input.hasTemporaryProxy()
	if usingTemporaryProxy {
		var err error
		resolvedProxyID, resolvedProxyConfig, err = resolveTemporaryBrowserStartProxy(input.TemporaryProxyID, input.TemporaryProxyConfig, proxies)
		if err != nil {
			safeErr := proxy.MaskProxySensitiveText(err.Error())
			startErr := fmt.Errorf("实例启动失败：%s", safeErr)
			profile.LastError = startErr.Error()
			log.Error("一次性代理配置无效",
				logger.F("profile_id", profileID),
				logger.F("temporary_proxy_id", input.TemporaryProxyID),
				logger.F("error", safeErr),
				logger.F("reason", proxy.MaskProxySensitiveText(startErr.Error())),
			)
			return "", profileProxyBridgeRef{}, false, startErr
		}
	} else if resolvedProxyID != "" {
		for _, item := range proxies {
			if strings.EqualFold(item.ProxyId, resolvedProxyID) {
				resolvedProxyID = strings.TrimSpace(item.ProxyId)
				resolvedProxyConfig = strings.TrimSpace(item.ProxyConfig)
				break
			}
		}
	}

	log.Info("代理配置检查",
		logger.F("profile_id", profileID),
		logger.F("proxy_id", profile.ProxyId),
		logger.F("profile_proxy_config", proxy.MaskProxySensitiveText(profile.ProxyConfig)),
		logger.F("temporary_proxy", usingTemporaryProxy),
		logger.F("temporary_proxy_id", input.TemporaryProxyID),
		logger.F("temporary_proxy_config", proxy.MaskProxySensitiveText(input.TemporaryProxyConfig)),
		logger.F("resolved_proxy_config", proxy.MaskProxySensitiveText(resolvedProxyConfig)),
	)
	if supported, errorMsg := proxy.ValidateProxyConfig(resolvedProxyConfig, proxies, resolvedProxyID); !supported {
		safeErrorMsg := proxy.MaskProxySensitiveText(errorMsg)
		startErr := fmt.Errorf("实例启动失败：%s", safeErrorMsg)
		profile.LastError = startErr.Error()
		log.Error("代理配置无效",
			logger.F("profile_id", profileID),
			logger.F("proxy_id", resolvedProxyID),
			logger.F("error", safeErrorMsg),
			logger.F("reason", proxy.MaskProxySensitiveText(startErr.Error())),
		)
		return "", profileProxyBridgeRef{}, false, startErr
	}

	connectorType := config.BrowserConnectorXray
	if a.config != nil {
		connectorType = config.NormalizeBrowserConnectorType(a.config.Browser.DefaultConnectorType)
	}
	resolution, err := proxy.ResolveProxyKernelForConnector(resolvedProxyConfig, proxies, resolvedProxyID, connectorType)
	if err != nil {
		safeErr := proxy.MaskProxySensitiveText(err.Error())
		startErr := fmt.Errorf("实例启动失败：%s", safeErr)
		profile.LastError = startErr.Error()
		log.Error("代理内核选择失败",
			logger.F("profile_id", profileID),
			logger.F("proxy_id", resolvedProxyID),
			logger.F("error", safeErr),
			logger.F("reason", proxy.MaskProxySensitiveText(startErr.Error())),
		)
		return "", profileProxyBridgeRef{}, false, startErr
	}
	log.Info("实际代理内核", logger.F("profile_id", profileID), logger.F("engine", resolution.Kernel), logger.F("protocol", resolution.Protocol), logger.F("proxy_id", resolvedProxyID), logger.F("reason", resolution.Reason))

	switch resolution.Kernel {
	case proxy.ProxyKernelMihomo:
		if a.clashMgr == nil {
			startErr := fmt.Errorf("实例启动失败：mihomo 管理器未初始化，无法启动该协议代理。请先下载 Mihomo 内核。")
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		proxyURL, bridgeKey, bridgeErr := a.clashMgr.AcquireNodeBridge(resolvedProxyConfig, proxies, resolvedProxyID)
		if bridgeErr != nil {
			safeBridgeErr := proxy.MaskProxySensitiveText(bridgeErr.Error())
			startErr := fmt.Errorf("实例启动失败：mihomo 代理桥接失败：%s", safeBridgeErr)
			log.Error("代理桥接失败(mihomo)", logger.F("error", safeBridgeErr), logger.F("reason", proxy.MaskProxySensitiveText(startErr.Error())))
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		return proxyURL, newProfileProxyBridgeRef(profileProxyBridgeEngineMihomo, bridgeKey), bridgeKey != "", nil
	case proxy.ProxyKernelSingBox:
		if a.singboxMgr == nil {
			startErr := fmt.Errorf("实例启动失败：sing-box 管理器未初始化，无法启动该协议代理。请检查 sing-box 内核配置。")
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		socksURL, bridgeKey, bridgeErr := a.singboxMgr.AcquireBridge(resolvedProxyConfig, proxies, resolvedProxyID)
		if bridgeErr != nil {
			safeBridgeErr := proxy.MaskProxySensitiveText(bridgeErr.Error())
			startErr := fmt.Errorf("实例启动失败：sing-box 代理桥接失败：%s", safeBridgeErr)
			log.Error("代理桥接失败(sing-box)", logger.F("error", safeBridgeErr), logger.F("reason", proxy.MaskProxySensitiveText(startErr.Error())))
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		return socksURL, newProfileProxyBridgeRef(profileProxyBridgeEngineSingBox, bridgeKey), bridgeKey != "", nil
	case proxy.ProxyKernelXray:
		if a.xrayMgr == nil {
			startErr := fmt.Errorf("实例启动失败：xray 管理器未初始化，无法启动该协议代理。")
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		socksURL, bridgeKey, bridgeErr := a.xrayMgr.AcquireBridge(resolvedProxyConfig, proxies, resolvedProxyID)
		if bridgeErr != nil {
			safeBridgeErr := proxy.MaskProxySensitiveText(bridgeErr.Error())
			startErr := fmt.Errorf("实例启动失败：Xray 代理桥接失败：%s", safeBridgeErr)
			log.Error("代理桥接失败(xray)", logger.F("error", safeBridgeErr), logger.F("reason", proxy.MaskProxySensitiveText(startErr.Error())))
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		return socksURL, newProfileProxyBridgeRef(profileProxyBridgeEngineXray, bridgeKey), bridgeKey != "", nil
	case proxy.ProxyKernelNative:
		return resolvedProxyConfig, profileProxyBridgeRef{}, false, nil
	default:
		startErr := fmt.Errorf("实例启动失败：无法为协议 %s 选择代理内核", resolution.Protocol)
		profile.LastError = startErr.Error()
		return "", profileProxyBridgeRef{}, false, startErr
	}
}

func resolveTemporaryBrowserStartProxy(proxyID string, proxyConfig string, proxies []BrowserProxy) (string, string, error) {
	proxyID = strings.TrimSpace(proxyID)
	proxyConfig = strings.TrimSpace(proxyConfig)
	if proxyID == "" {
		return "", proxyConfig, nil
	}

	for _, item := range proxies {
		if strings.EqualFold(item.ProxyId, proxyID) {
			return strings.TrimSpace(item.ProxyId), strings.TrimSpace(item.ProxyConfig), nil
		}
	}
	if strings.EqualFold(proxyID, temporaryDirectProxyID) {
		return temporaryDirectProxyID, "direct://", nil
	}
	if proxyConfig != "" {
		return "", proxyConfig, nil
	}
	return "", "", fmt.Errorf("代理ID不存在（proxy id not found: %s），且未提供 proxyConfig", proxyID)
}
