//go:build !windows
// +build !windows

package backend

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserProcessCandidateMatchesExactUnicodeUserDataDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "P1.8 中文 profile")

	cases := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "spaces and unicode",
			args: []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--user-data-dir=" + target, "--remote-debugging-port=43123"},
			want: true,
		},
		{
			name: "separate flag value",
			args: []string{"/usr/bin/chrome", "--user-data-dir", target, "--remote-debugging-port", "43124"},
			want: true,
		},
		{
			name: "prefix is not a match",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + target + "-other", "--remote-debugging-port=43125"},
			want: false,
		},
		{
			name: "other profile is not a match",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + filepath.Join(root, "other"), "--remote-debugging-port=43126"},
			want: false,
		},
		{
			name: "trailing space remains part of path",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + filepath.Join(root, "profile "), "--remote-debugging-port=43126"},
			want: false,
		},
		{
			name: "relative path is fail closed",
			args: []string{"/usr/bin/chrome", "--user-data-dir=relative-profile", "--remote-debugging-port=43126"},
			want: false,
		},
		{
			name: "helper is ignored",
			args: []string{"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper", "--type=renderer", "--user-data-dir=" + target, "--remote-debugging-port=43127"},
			want: false,
		},
		{
			name: "main without debug port is ignored",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + target},
			want: false,
		},
		{
			name: "zero port is ignored",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + target, "--remote-debugging-port=0"},
			want: false,
		},
		{
			name: "out of range port is ignored",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + target, "--remote-debugging-port=65536"},
			want: false,
		},
		{
			name: "duplicate user-data-dir flags are ignored",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + target, "--user-data-dir=" + target, "--remote-debugging-port=43128"},
			want: false,
		},
		{
			name: "duplicate debug port flags are ignored",
			args: []string{"/usr/bin/chrome", "--user-data-dir=" + target, "--remote-debugging-port=43128", "--remote-debugging-port=43129"},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate, ok := browserProcessCandidateFromArgs(12345, tc.args, target)
			if ok != tc.want {
				t.Fatalf("candidate = %#v, ok=%v, want %v", candidate, ok, tc.want)
			}
			if !tc.want {
				return
			}
			if candidate.PID != 12345 || candidate.DebugPort <= 0 {
				t.Fatalf("candidate identity = %#v", candidate)
			}
			if !strings.Contains(candidate.CommandLine, target) {
				t.Fatalf("command line did not preserve path with spaces: %q", candidate.CommandLine)
			}
		})
	}

	trailingTarget := filepath.Join(root, "profile ")
	if _, ok := browserProcessCandidateFromArgs(12345, []string{"/usr/bin/chrome", "--user-data-dir=" + trailingTarget, "--remote-debugging-port=43130"}, trailingTarget); !ok {
		t.Fatal("a trailing space in the exact user-data directory was discarded")
	}
}

func TestBrowserProcessCandidateRejectsInvalidPID(t *testing.T) {
	target := filepath.Join(t.TempDir(), "profile")
	args := []string{"/usr/bin/chrome", "--user-data-dir=" + target, "--remote-debugging-port=43123"}
	if _, ok := browserProcessCandidateFromArgs(0, args, target); ok {
		t.Fatal("invalid pid was accepted")
	}
}

func TestFindBrowserUserDataProcessesOSDoesNotInspectProfileContents(t *testing.T) {
	target := filepath.Join(t.TempDir(), "P1.8 中文 profile")
	processes, err := findBrowserUserDataProcessesOS(target)
	if err != nil {
		t.Fatalf("find browser processes: %v", err)
	}
	if len(processes) != 0 {
		t.Fatalf("unexpected process match for fresh temporary directory: %#v", processes)
	}
}
