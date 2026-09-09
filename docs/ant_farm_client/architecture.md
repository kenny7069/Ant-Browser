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

## Signed-update boundary

The installed executable is an immutable launcher. Downloaded Agents are
stored below the per-user `updates/versions/<version>-<sha256>` tree and one
atomically replaced `activation.json` selects `active`, `previous` and
`pending` slots. The launcher is the only autostart target and remains alive
across any number of Agent handoffs.

A successor becomes active only after signed-manifest and artifact
verification, command drain, authenticated WSS reconnect, active-runtime
inventory and Server-side transactional reconciliation. The Server compares
the complete Agent live set with controller lease, Node, runtime rows, runtime
leases and profile affinity before returning the digest-bound completion that
allows the health probation to commit. Failure rolls back the pending slot;
normal service stop is distinct from update/parent-loss shutdown so rollback
preserves owned Chrome and connector processes.

Updated payload execution is pinned to the verified filesystem object:

- Linux walks owner-only directories with `openat`/`O_NOFOLLOW` and executes
  the verified fd through `/proc/self/fd/3`; a host without usable `/proc`
  fails closed.
- Windows applies and verifies a protected user/SYSTEM/Administrators DACL,
  rejects reparse points and hardlinks, and holds no-share-write/delete file
  and directory handles until process creation fixes the image.
- macOS walks each component using pinned directory fds, rejects symlinks and
  hardlinks, hashes the open fd, and rechecks device/inode/size/ctime
  immediately before absolute-path process creation. Darwin has no supported
  `fexecve` or `/proc/self/fd` equivalent, so this is not claimed to resist an
  attacker already executing arbitrary code as the same login user.

The updater threat model includes malicious networks/CDNs, forged, replayed
or expired manifests, artifact corruption, another non-administrator OS
account, pre-positioned symlink/reparse/hardlink objects, update crashes and
concurrent launchers. Administrator/root, kernel or filesystem-filter
compromise, arbitrary code execution as the Client's own login user, and an
attacker who already owns that user's device key/WSS session are outside this
boundary. If same-login-user adversaries become required, the macOS design
must move to a privileged broker or an Apple-supported privileged updater;
additional pathname checks are not a substitute.
