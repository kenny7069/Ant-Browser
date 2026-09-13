package browser

import (
	"errors"
	"testing"
)

func TestAdoptPersistedProfileExactNoClobber(t *testing.T) {
	m := &Manager{Profiles: map[string]*Profile{}}
	p := &Profile{ProfileId: "profile-a", IncarnationID: "inc-a", ProfileName: "A", UserDataDir: "profile-a", CoreId: "core-a"}
	if err := m.AdoptPersistedProfileExact(p); err != nil {
		t.Fatal(err)
	}
	if err := m.AdoptPersistedProfileExact(p); err != nil {
		t.Fatalf("exact replay failed: %v", err)
	}
	drift := *p
	drift.IncarnationID = "inc-b"
	if err := m.AdoptPersistedProfileExact(&drift); !errors.Is(err, ErrProfileExactConflict) {
		t.Fatalf("expected exact conflict, got %v", err)
	}
}
