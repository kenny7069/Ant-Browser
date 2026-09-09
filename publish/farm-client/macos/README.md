# Ant Farm Client (macOS)

Signed raw-binary updates and the offline manifest format are documented in
`../UPDATE-MANIFEST.md`. C10 code-signing/notarization remains mandatory.

This is a standalone unsigned `Ant Farm Client.app` containing the Wails-free
CLI host, pinned `xray` and `sing-box` runtimes, and `config.example.yaml`.
The bundle is an `LSUIElement`/background CLI app and does not install a
LaunchDaemon or any machine-level service.

The signed outer app and its launcher are never modified by self-update.
Versioned Agent payloads run outside the bundle from the current user's
owner-only state tree, so launchd `KeepAlive` supervises only one stable
launcher and cannot race a replacement child.

Use the explicit per-user `autostart install` command only after providing an
absolute, validated configuration path. Signing and notarization are release
gates documented in `SIGNING-NOTARIZATION.md` inside the app resources.

`application_root` and `ant_config_path` must point to the existing Ant
installation and its canonical config. They must not point to this app bundle.
