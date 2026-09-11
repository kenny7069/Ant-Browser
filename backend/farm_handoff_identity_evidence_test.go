package backend

// p118HandoffIdentity is shared by portable evidence validators and the
// Unix-only cross-repository process runner. Keep the wire projection in a
// platform-neutral file so native Windows source tests still compile.
type p118HandoffIdentity struct {
	RuntimeUID           string `json:"runtime_uid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	ProfileIncarnation   string `json:"profile_incarnation"`
	Generation           uint64 `json:"generation"`
	PID                  int    `json:"pid"`
}
