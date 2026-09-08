# Ant Farm Client File Ownership

Only one writer may modify a listed area during a work package.

## Frozen Farm core

Changes require an architecture review, a minimal-extension decision, and full
regression evidence:

- `backend/browser_runtime_service*.go`
- `backend/farm_runtime_service.go`
- `backend/farm_attestation.go`
- `backend/farm_cdp_tunnel.go`
- `backend/farm_control_wss_client.go`
- `backend/farm_control_wss_cdp.go`
- `backend/farm_runtime_handoff.go`
- `backend/farm_runtime_ownership_store.go`
- `backend/farm_resource_telemetry.go`
- `backend/internal/proxy/**`

## Existing profile persistence

Owned by the Ant Browser profile subsystem; Client work may consume it but not
fork it:

- `backend/internal/browser/profile_store.go`
- `backend/internal/browser/profile_dao.go`
- `backend/internal/browser/profile_*.go`
- `backend/internal/database/**`
- `backend/app_startup.go`
- `backend/app_browser_profile_api.go`

## New Client-owned area

- `backend/cmd/ant-farm-client/**`
- `backend/farm_client_*.go`
- `publish/farm-client/**`
- `docs/ant_farm_client/**`

The C1 implementer is the sole writer for the new Client-owned Go files. The
reviewer owns architecture and Gate verdicts and must independently inspect the
diff and rerun the required tests.

## Server-owned area

Enrollment, pairing records, fleet operations, and update policy live in
auto-scraper. The Ant client must not grow a control-plane database or remote
shell surface.

