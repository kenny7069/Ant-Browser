package backend

func (a *App) BrowserInstanceStart(profileId string) (*BrowserProfile, error) {
	service, err := a.browserRuntimeService()
	if err != nil {
		return nil, err
	}
	return service.Start(profileId)
}

func shouldPreferVisibleWindowForStartWithParams(startURLs []string) bool {
	return len(normalizeNonEmptyStrings(startURLs)) > 0
}

// BrowserInstanceStartDirect 仅本次启动走直连，不落库修改实例代理配置。
func (a *App) BrowserInstanceStartDirect(profileId string) (*BrowserProfile, error) {
	service, err := a.browserRuntimeService()
	if err != nil {
		return nil, err
	}
	return service.StartWithOptions(profileId, BrowserRuntimeStartOptions{ForceDirectProxy: true})
}

// BrowserInstanceStartWithParams 通过额外参数启动实例（仅本次启动生效，不落库）
func (a *App) BrowserInstanceStartWithParams(profileId string, extraLaunchArgs []string, startURLs []string, skipDefaultStartURLs bool) (*BrowserProfile, error) {
	preferVisibleWindow := shouldPreferVisibleWindowForStartWithParams(startURLs)
	return a.browserInstanceStartWithRuntimeOptions(profileId, BrowserRuntimeStartOptions{
		ExtraLaunchArgs:      extraLaunchArgs,
		StartURLs:            startURLs,
		SkipDefaultStartURLs: skipDefaultStartURLs,
		PreferVisibleWindow:  preferVisibleWindow,
	})
}

func (a *App) browserInstanceStartInternal(profileId string, extraLaunchArgs []string, startURLs []string, skipDefaultStartURLs bool, preferVisibleWindow bool, forceDirectProxy bool, proxyId string, proxyConfig string) (*BrowserProfile, error) {
	return a.browserInstanceStartWithRuntimeOptions(profileId, BrowserRuntimeStartOptions{
		ExtraLaunchArgs:      extraLaunchArgs,
		StartURLs:            startURLs,
		SkipDefaultStartURLs: skipDefaultStartURLs,
		PreferVisibleWindow:  preferVisibleWindow,
		ForceDirectProxy:     forceDirectProxy,
		ProxyID:              proxyId,
		ProxyConfig:          proxyConfig,
	})
}

func (a *App) browserInstanceStartWithRuntimeOptions(profileID string, options BrowserRuntimeStartOptions) (*BrowserProfile, error) {
	service, err := a.browserRuntimeService()
	if err != nil {
		return nil, err
	}
	return service.StartWithOptions(profileID, options)
}
