# Ant Farm Client Compatibility Manifest

This manifest pins the development compatibility pair. A release must replace
the development entries with immutable release artifact hashes.

| Component | Revision / version |
|---|---|
| Ant-Browser | `f24f9c5` (C8 installed signed update/rollback local gate passes and five-platform jobs are wired; native results pending; harness introduced at `fd31252`; basic gates passed at `0841cd5`; full C8 remains in progress; C7 `4f5ba88`; baseline `e83fc37ad5271034aba35f4d6b5a8b7ee3d394c1`) |
| auto-scraper | `48f67271f9cb3fee8653b0e0d394f32795d9a89d` (C7 authoritative update reconcile; coordinator `ba977e1`; C6 `d476370e804ff3ac852f4fe0d22ba9914a5b6249`; C4 `063105a`; C3 `d45d877`; production baseline `2ca94b58c7d2ca95849c5f75495950b301f6bd49`) |
| Control protocol | `bf-p1.6` plus `profile-pairing/v1` |
| Ant Farm Client | `0.1.0-dev` source default; C5 artifacts inject an explicit release version through Go linker metadata |

The Ant-Browser integration branch is `farm-client-dev`. `master` is an
upstream/legacy desktop baseline and must not be merged wholesale into this
branch. Any synchronization requires symbol-level classification and selective
integration.
