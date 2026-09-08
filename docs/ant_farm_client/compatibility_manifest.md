# Ant Farm Client Compatibility Manifest

This manifest pins the development compatibility pair. A release must replace
the development entries with immutable release artifact hashes.

| Component | Revision / version |
|---|---|
| Ant-Browser | `e83fc37ad5271034aba35f4d6b5a8b7ee3d394c1` |
| auto-scraper | `2ca94b58c7d2ca95849c5f75495950b301f6bd49` |
| Control protocol | `bf-p1.6` |
| Ant Farm Client | `0.1.0-dev` |

The Ant-Browser integration branch is `farm-client-dev`. `master` is an
upstream/legacy desktop baseline and must not be merged wholesale into this
branch. Any synchronization requires symbol-level classification and selective
integration.

