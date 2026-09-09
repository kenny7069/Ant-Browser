# Ant Farm Client (macOS)

This is a standalone unsigned `Ant Farm Client.app` containing the Wails-free
CLI host, pinned `xray` and `sing-box` runtimes, and `config.example.yaml`.
The bundle is an `LSUIElement`/background CLI app and does not install a
LaunchDaemon or any machine-level service.

Use the explicit per-user `autostart install` command only after providing an
absolute, validated configuration path. Signing and notarization are release
gates documented in `SIGNING-NOTARIZATION.md` inside the app resources.

`application_root` and `ant_config_path` must point to the existing Ant
installation and its canonical config. They must not point to this app bundle.
