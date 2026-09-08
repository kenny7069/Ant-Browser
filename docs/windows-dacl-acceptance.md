# Windows DACL acceptance

This is the required real-Windows acceptance path for the Browser Farm secure
runtime writer. Cross-compilation is useful as a static check, but it is not a
substitute for this test.

## Runner prerequisites

- A real Windows amd64 host with a Go toolchain that supports `go test -race`.
- The repository checked out on a local NTFS volume.
- Two distinct Windows accounts: the process owner and a pre-provisioned
  alternate account. The script does not create or delete users.
- The alternate account must be enabled for network logon on the runner.

Run PowerShell as the ordinary owner account from the repository root:

```powershell
.\scripts\run_windows_dacl_acceptance.ps1 -AlternateUsername dacl-reader
```

For a domain account, also pass `-AlternateDomain CONTOSO`. For a local account,
the default domain `.` is correct. The script prompts for the alternate
password as a secure string. CI may instead provide
`BF_P1_WINDOWS_DACL_ALT_PASSWORD` through its masked secret store; never place
the password in a command argument, source file, or test artifact.

`-SkipRace` is only for diagnosing a runner whose race toolchain is not yet
installed. A run with that switch does not satisfy final acceptance.

## Required assertions

The opt-in Go test fails unless all of these are observed on the live NTFS
filesystem:

1. The owner can read and open the generated config for writing.
2. The runtime root, per-node directory, and config have a protected DACL with
   exactly one full-control ACE for the owner SID.
3. A different authenticated Windows SID can read the shared positive-control
   probe, but receives `ERROR_ACCESS_DENIED` for config read, write, removal,
   and handle cleanup.
4. A real directory junction is rejected by all runtime resolution paths, and
   neither rejection nor cleanup changes its external sentinel.
5. Owner cleanup removes only the owned runtime config and directory.

The script creates a unique shared parent, grants only the traversal/read access
needed for the positive control, runs both ordinary and race acceptance, clears
its temporary environment, zeroes the prompted password buffer, and removes
only that unique parent. Retain the command result as the acceptance artifact;
do not retain environment dumps.

## Hosted runner

The `Windows DACL acceptance` GitHub Actions workflow provides the same ordinary
and race run on `windows-2022`. Before the workflow reaches the default branch,
it runs only when `codex/browser-farm-p1-handoff-agent` is pushed with a relevant
harness change; `workflow_dispatch` is also available once GitHub exposes it
from the default branch. It creates a uniquely named local
alternate account using an in-memory random masked password, passes the password
only through the step process environment, and deletes that exact account in a
`finally` block. A local commit alone does not satisfy acceptance: retain a
successful workflow run tied to the tested commit.
