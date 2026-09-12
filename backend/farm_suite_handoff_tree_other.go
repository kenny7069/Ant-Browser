//go:build !windows

package backend

func suitePathIsReparsePoint(string) (bool, error) {
	return false, nil
}
