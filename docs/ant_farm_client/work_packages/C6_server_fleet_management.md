# Work Package C6 — Server Fleet Management

## Objective

Provide an admin-only operational surface for enrolled Farm Clients without
turning the Control plane into a remote shell or changing persistent browser
runtimes into disposable processes.

## Surface contract

- The Fleet inventory displays Node name/UID, durable and live status, OS,
  architecture, Client and protocol versions, last seen, RTT, memory, runtime
  count, update channel/status and diagnostics.
- Separate modal flows issue enrollment codes, apply short named Node actions
  and unpair profiles. Runtime, version, pairing, update and diagnostic details
  remain read-only views.
- Every page and endpoint is admin-only. Mutations require the existing CSRF
  request marker, reject unknown fields and return stable validation/not-found
  errors.
- Enrollment secrets are delivered with no-store headers and are erased from
  the DOM on expiry, close, page hide and backgrounding.

## State and concurrency contract

- Rename, drain, resume, disable, enable, revoke, update-channel and unpair are
  named transactional operations; there is no generic execution endpoint.
- Drain preserves the authenticated Control session and telemetry but rejects
  commands that could create or reconcile new runtime work. A per-Node lane
  serializes its durable transition against command authorization/envelopes.
- Resume, disable and revoke fence new authentication/commands, disconnect the
  exact Control session, close its tracked CDP tunnels, and then persist state.
  They do not kill Chrome or connector processes.
- CDP registration is identity-safe across replacement, ready-write failure,
  registry capacity failure, cancellation, disconnect and Server shutdown.
- Admin unpair locks the Node/affinity and trusted tenant database tuple, moves
  the tenant profile back to `local`, clears `farm_storage_key`, disables its
  affinity and revokes an unused pairing grant in one MySQL transaction.
  `farm_storage_key` is never interpreted as an Ant local Profile ID.

## Protocol boundary

The Server allowlist exactly matches the existing Agent protocol commands.
Fleet management does not add `execute_command`, `run_shell`, `powershell`,
`bash`, `upload_and_run`, arbitrary argv, file upload or terminal access.

## Verification

- 19 focused C6 API/state/concurrency/UI tests.
- 25 Control WSS tests with one existing environment skip and 9 CDP gateway
  tests, including transition races and all accepted-tunnel cancellation paths.
- Auth, schema, enrollment, pairing, runtime-control, authority, attestation,
  resource telemetry, live-monitor and Queue integration regressions.
- Python compilation, HTML parser, inline JavaScript syntax and whitespace.
- Desktop inventory and enrollment-modal visual inspection.
- Independent SOL review: PASS with no remaining P1/P2 findings.

The implementation is pinned to auto-scraper commit
`d476370e804ff3ac852f4fe0d22ba9914a5b6249`. Live MySQL migration and
installed-fleet reconnect validation remain explicit C8 work.
