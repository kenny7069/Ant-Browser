# Ant Farm Client (Windows)

The setup and zip install the standalone Wails-free client plus pinned `xray`
and `sing-box` runtimes under `C:\Program Files\Ant Farm Client`. Mutable
identity, ownership and profile state stays under the current user's
`%LOCALAPPDATA%\AntFarmClient` tree and is preserved by uninstall.

Copy `config.example.yaml` into that state tree and replace every placeholder.
`application_root` and `ant_config_path` must point to the existing Ant
installation and its canonical config, not the Farm Client install directory.
Autostart is an explicit per-user CLI operation; the installer does not create
a machine service.
