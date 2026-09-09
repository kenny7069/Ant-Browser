# Ant Farm Client (Linux)

Signed payload updates and the offline manifest format are documented in
`../UPDATE-MANIFEST.md`; `.update.bin` is the versioned Agent payload.

This is the standalone Wails-free Ant Farm Client. The archive and Debian
package include `ant-farm-client`, the pinned `xray` and `sing-box` runtimes,
and `config.example.yaml`.

The Debian package installs under `/opt/ant-farm-client`. It intentionally has
no maintainer scripts and does not install or register a machine daemon. Use
the client's explicit per-user `autostart install` command only after providing
an absolute, validated configuration path.

The `/opt` executable is the immutable user-session launcher. Signed Client
payloads run from an owner-only, content-addressed directory below the state
root; self-update never writes `/opt`.

`application_root` and `ant_config_path` must point to the existing Ant
installation and its canonical config. They must not point to this package.
