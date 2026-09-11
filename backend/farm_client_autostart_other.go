//go:build !windows && !darwin && !linux

package backend

type farmClientUnsupportedAutostart struct{}

func newFarmClientAutostartManager() farmClientAutostartManager {
	return farmClientUnsupportedAutostart{}
}

func (farmClientUnsupportedAutostart) Install(string, string) error { return ErrFarmClientAutostart }
func (farmClientUnsupportedAutostart) Remove() error                { return ErrFarmClientAutostart }
func (farmClientUnsupportedAutostart) Status() (FarmClientAutostartStatus, error) {
	return FarmClientAutostartStatus{Method: "unsupported"}, ErrFarmClientAutostart
}
