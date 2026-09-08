package backend

import (
	"testing"
	"time"
)

type p118TimeBudgets struct {
	server           time.Duration
	playwright       time.Duration
	fixtureSeconds   int
	successorSeconds int
}

func p118ScenarioBudgets(scenario string) p118TimeBudgets {
	// Production execv fences for the full 120-second handoff deadline.
	// Allow bounded startup/polling/CDP/cleanup margins without changing
	// the independent 20-second old-CDP disconnection requirement.
	if scenario == "execv" {
		return p118TimeBudgets{210 * time.Second, 180 * time.Second, 180, 150}
	}
	return p118TimeBudgets{server: 120 * time.Second, playwright: 60 * time.Second}
}

func TestP118ScenarioTimeBudgets(t *testing.T) {
	for _, scenario := range []string{"", "graceful", "crash_watcher"} {
		got := p118ScenarioBudgets(scenario)
		if got.server != 120*time.Second || got.playwright != 60*time.Second || got.fixtureSeconds != 0 || got.successorSeconds != 0 {
			t.Fatalf("existing scenario %q budget changed: %+v", scenario, got)
		}
	}
	got := p118ScenarioBudgets("execv")
	if got.server != 210*time.Second || got.playwright != 180*time.Second || got.fixtureSeconds != 180 || got.successorSeconds != 150 {
		t.Fatalf("execv bounded budget mismatch: %+v", got)
	}
}
