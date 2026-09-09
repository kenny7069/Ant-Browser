# Signing and notarization gate

The C5 packaging script deliberately produces an unsigned app and zip. Before
distribution, the release workflow must:

1. Sign `Ant Farm Client.app` with the approved Developer ID Application
   identity and hardened-runtime entitlements.
2. Verify the nested client and runtime binaries with `codesign --verify`.
3. Submit the signed zip or app with `xcrun notarytool submit --wait`.
4. Staple the ticket with `xcrun stapler staple` and run `spctl --assess`.

The signing identity, entitlements, Apple team credentials, and notarization
submission are intentionally not embedded in this unsigned packaging script.
