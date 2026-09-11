//go:build !linux && !darwin && !windows

package backend

func openFarmClientPinnedPayload(string, string, FarmClientUpdateSlot) (*farmClientPinnedPayload, error) {
	return nil, ErrFarmClientUpdateApply
}
