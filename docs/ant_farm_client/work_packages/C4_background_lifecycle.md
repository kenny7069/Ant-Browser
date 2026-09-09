# Work Package C4 — Per-user Background Lifecycle

## Objective

Start the standalone Client automatically after an interactive user signs in,
without running headed Chrome as a machine service or as `LocalSystem`.
Preserve the existing ownership-aware shutdown path and never terminate
processes by global executable name.

## Platform contracts

- Windows: one interactive, limited-privilege Scheduled Task triggered at
  logon for the current user. Binaries belong under Program Files while state
  remains under that user's Local AppData.
- macOS: `~/Library/LaunchAgents/com.antfarm.client.plist`, with explicit
  `ProgramArguments`, `RunAtLoad`, `KeepAlive`, throttling and interactive
  process type. A LaunchDaemon is prohibited.
- Linux: `systemd --user` unit preferred. If no user manager is available,
  install an XDG autostart desktop entry so DISPLAY/Wayland/keyring remain in
  the desktop session.

The CLI owns `autostart install|remove|status`. It validates that the absolute
executable and config files exist, emits only a safe status projection, and
does not place keys, enrollment/pairing codes, URLs, profile IDs or local paths
in diagnostics.

## Lifecycle ordering

On SIGINT/SIGTERM or service stop:

1. the root context stops new work;
2. Control WSS and reconnect admission close;
3. CDP sessions close through the existing Control adapter;
4. ownership state remains persisted by the existing Farm service;
5. `BrowserRuntimeService.Shutdown` stops only processes tracked/owned by this
   Client and cleans only its connector runtimes;
6. SQLite, logs and the per-user process lock close.

No platform registration or removal command calls `taskkill`, `killall`,
`pkill`, or any process-name based cleanup.

## Production controller fence

The Server acquires its existing controller lease before starting Control WSS.
Every authenticated acknowledgement receives the exact active controller ID
and generation from that same factory. If the lease is unavailable, invalid or
expired, authentication fails closed and the node is returned offline. This
makes a login-started Client compatible with the existing Agent connection
fence instead of using a fixture/static generation.

## Acceptance

- Generated registrations contain an argument vector or platform-native
  quoting; no shell wrapper or interpolated command is used.
- macOS and Linux registration files are atomic and owner-only; a symlinked
  destination directory is rejected.
- install failures remove partially published registration files.
- remove is idempotent and affects only the named Ant Farm Client registration.
- active controller identity is included in a real authenticated WSS exchange;
  provider failure rejects authentication without leaking its exception.
- SIGTERM remains bounded, releases the instance lock and reaps only the
  Client-owned runtime.
- native source compiles for Windows amd64, Linux amd64/arm64 and macOS
  amd64/arm64. Installed-artifact and login/reboot execution repeats at C8.

## Verification

- focused unit tests for validation, atomic/symlink protection and platform
  descriptor contents;
- real Control WSS tests for controller fence success/failure/offline cleanup;
- existing CLI SIGTERM/process-lock and real WSS reconnect tests;
- full Go tests, focused race, vet, cross-builds and Server farm/control suites.
