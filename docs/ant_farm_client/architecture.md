# Ant Farm Client Architecture

## Boundary

Ant Farm Client is a thin, outbound-only host around the existing Farm core:

```text
auto-scraper Control Plane
        | HTTPS / authenticated WSS
        v
Ant Farm Client bootstrap and supervision
        v
FarmControlWSSClient
        v
FarmRuntimeControlAdapter
        v
FarmRuntimeService
        v
BrowserRuntimeService
        v
Ant Chromium + selected connector stack
```

The client owns configuration, local identity, profile catalogue loading,
service composition, single-instance enforcement, logging, signals,
diagnostics, autostart, packaging, and updates. It does not implement a second
browser lifecycle, WSS protocol, CDP tunnel, handoff mechanism, runtime
identity, or proxy engine.

## Connector boundary

`browser.default_connector_type=xray` selects the combined Xray + sing-box
stack: Xray handles vmess/vless/trojan/shadowsocks/chained proxies and sing-box
handles hysteria2/tuic/anytls. `browser.default_connector_type=mihomo` selects
the independent Mihomo stack. Startup, health checks, warm-up, downloads, and
real connectivity must remain within the selected stack.

## Profile store boundary

The desktop application loads profiles through `browser.Manager.InitData()`:
SQLite `ProfileDAO` first, then `config.yaml` fallback. The public standalone
factory currently accepts caller-provided `[]BrowserProfile` and does not load
SQLite. C1 may add only a narrow read-only profile-loading facade that reuses
the existing database and DAO implementation; it must not create another
profile database.

`farm_storage_key`, server profile ID, local Ant Profile ID, UserDataDir,
runtime UID, generation, and profile incarnation are distinct identities.
Pairing must be explicit and must not expose raw fingerprints, proxy secrets,
local paths, cookies, or Chrome arguments.

## Runtime ownership

Restart recovery uses `FarmRuntimeOwnershipStore`. The store is authenticated
with a distinct 32-byte key derived from enrolled device material. No separate
`running.json` is permitted. In-memory profile incarnation fences same-ID ABA;
durable recovery additionally verifies profile creation time and OS process
start identity.

