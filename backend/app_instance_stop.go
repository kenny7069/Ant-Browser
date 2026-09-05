package backend

func (a *App) BrowserInstanceStop(profileId string) (*BrowserProfile, error) {
	service, err := a.browserRuntimeService()
	if err != nil {
		return nil, err
	}
	return service.Stop(profileId)
}

func (a *App) BrowserInstanceRestart(profileId string) (*BrowserProfile, error) {
	service, err := a.browserRuntimeService()
	if err != nil {
		return nil, err
	}
	if _, err := service.Stop(profileId); err != nil {
		return nil, err
	}
	return service.Start(profileId)
}
