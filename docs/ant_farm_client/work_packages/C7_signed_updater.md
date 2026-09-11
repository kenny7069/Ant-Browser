# Work Package C7 — Signed Updater

## Objective

Update the standalone Farm Agent without turning a download into an execution
primitive and without treating persistent Chrome runtimes as disposable.

## Manifest and staging contract

- The offline Ed25519 signer emits one strict envelope containing version,
  protocol/minimum protocol, channel, publication/expiry times, downgrade
  policy and all five supported target artifacts.
- The Client verifies signature, HTTPS URL, expiry, channel, protocol, OS,
  architecture, size and SHA-256 before staging. A downgrade needs explicit
  permission in both manifest and local policy.
- Staging is non-executable. Promotion copies the artifact into a private,
  content-addressed version directory and retains the exact signed envelope.
  No downloaded helper or caller-supplied executable path is accepted.

## Activation and recovery contract

- The immutable installed launcher owns autostart and supervises Agent
  children for its complete lifetime. `activation.json` is the single atomic
  `stable`/`staged`/`probation` state record with active, previous and pending
  slots.
- A staged crash returns to the old slot. Probation starts only after the old
  Agent has drained admitted commands, closed Control WSS and durably
  authorized activation.
- The successor must reconnect, receive a heartbeat, publish the digest-bound
  active inventory and receive Server completion after an authoritative
  transaction checks controller/runtime leases, Node, live runtime rows and
  profile affinity. Health must remain continuous throughout probation.
- WSS/health loss stops the candidate using preserve semantics, rolls back and
  reconnects the previous Agent. EOF from a crashed launcher also preserves
  runtime ownership. Only an ordinary service stop performs normal Browser
  shutdown; there is no process-name/global Chrome or connector kill.
- Terminal Agent history is excluded from handoff inventory. Live inventory is
  an exact set; empty is a no-op only when the authoritative live set is empty.

## Local execution boundary

Linux uses a verified open fd and `/proc/self/fd/3`; Windows holds protected
DACL/no-reparse/no-share-write-delete handles through process creation; macOS
uses component-by-component no-follow fds and a final identity recheck. All
platforms reject hardlinked payloads. The precise threat model and Darwin
same-login-user limitation are recorded in `architecture.md`.

## Verification

- Full Go normal/race suites and vet pass on macOS arm64.
- Five target Client builds pass; release workflows run the backend suite on
  native Windows 2022, Ubuntu amd64/arm64 and macOS Intel/Apple Silicon.
- Native tests cover repeated launcher boundaries, control stop/preserve
  semantics, WSS-loss runtime preservation, continuous probation, symlink and
  hardlink rejection; Linux additionally proves path replacement still
  executes the pinned fd, and Windows proves held handles block replacement.
- Server Control WSS and Fleet suites pass, including exact/empty/missing/
  extra/mismatched inventory, lease expiry, partial state and DB-race cases.
- Installed upgrade/rollback and native two-account assertions remain C8;
  release code signing/notarization remains C10 and is not inferred here.

Fresh independent SOL-MID review returned C7 PASS with no remaining
P0/P1/P2/P3 findings. The final review included the fail-closed terminal-state
authority checks and current-time pending-envelope expiry regressions.
