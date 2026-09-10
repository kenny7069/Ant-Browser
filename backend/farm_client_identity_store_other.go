//go:build !windows && !darwin && !linux

package backend

func NewFarmClientIdentityStore(root string) (FarmClientIdentityStore, error) {
	return nil, ErrFarmClientIdentityStoreUnavailable
}
