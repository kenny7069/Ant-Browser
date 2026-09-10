//go:build darwin && !cgo

package backend

func NewFarmClientIdentityStore(root string) (FarmClientIdentityStore, error) {
	return nil, ErrFarmClientIdentityStoreUnavailable
}
