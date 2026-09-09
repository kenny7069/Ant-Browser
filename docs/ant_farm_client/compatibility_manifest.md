# Ant Farm Client Compatibility Manifest

This manifest pins the development compatibility pair. A release must replace
the development entries with immutable release artifact hashes.

| Component | Revision / version |
|---|---|
| Ant-Browser | `aa153814a3d760947626cbfe6d756cff0b6dbad8` (C4 per-user background lifecycle; C3 `7d3cc72`; baseline `e83fc37ad5271034aba35f4d6b5a8b7ee3d394c1`) |
| auto-scraper | `063105a475f205531730fbf7b821244f7ee81587` (C4 production controller-fenced WSS auth; C3 `d45d877`; production baseline `2ca94b58c7d2ca95849c5f75495950b301f6bd49`) |
| Control protocol | `bf-p1.6` plus `profile-pairing/v1` |
| Ant Farm Client | `0.1.0-dev` |

The Ant-Browser integration branch is `farm-client-dev`. `master` is an
upstream/legacy desktop baseline and must not be merged wholesale into this
branch. Any synchronization requires symbol-level classification and selective
integration.
