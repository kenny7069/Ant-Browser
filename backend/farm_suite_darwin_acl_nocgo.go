//go:build darwin && !cgo

package backend

// Without cgo the ACL of the install tree cannot be inspected: fail closed.
func suiteDarwinHasExtendedACL(string) (bool, error) { return false, ErrSuiteServiceActivation }
