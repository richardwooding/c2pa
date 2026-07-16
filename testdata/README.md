# testdata

## c2pa_signed.jpg

A real C2PA-signed JPEG used as the parser fixture. It is `CA.jpg` from the
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs) project's test
assets (`sdk/tests/fixtures/`), licensed under Apache-2.0 / MIT (the c2pa-rs
dual license).

It carries a manifest with claim_generator `make_test_images/0.33.1
c2pa-rs/0.33.1`, title `CA.jpg`, a COSE_Sign1 signature whose leaf certificate
subject CN is `C2PA Signer`, and an RFC 3161 timestamp of
`2024-08-06T21:53:37Z`. It is an *edited* image, not AI-generated.

## c2pa_signed_video.mp4, video_no_manifest.mp4, legacy_bmff_v1.mp4

BMFF fixtures from [contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs)'s
test assets (`sdk/tests/fixtures/`), licensed under Apache-2.0 / MIT (the c2pa-rs
dual license):

- `c2pa_signed_video.mp4` (`video1.mp4` upstream) — a signed MP4 whose active
  manifest carries a `c2pa.hash.bmff.v2` hard binding (claim_generator
  `TestApp c2patool/0.6.2 c2pa-rs/0.28.2`) plus an embedded ingredient manifest
  whose only hard binding is a v1 `c2pa.hash.bmff`. Its COSE x5chain lives in
  the *unprotected* header under the text key `"x5chain"` (pre-1.3 c2pa-rs).
- `video_no_manifest.mp4` (`video1_no_manifest.mp4` upstream) — the unsigned
  twin; negative fixture.
- `legacy_bmff_v1.mp4` (`legacy.mp4` upstream) — a 1.0-era manifest whose only
  hard binding is a v1 `c2pa.hash.bmff` assertion, which validators must
  ignore (spec §18.6.1); exercises the v1-ignore → `hardBinding.missing` path.

No pre-signed HEIC fixture exists upstream; HEIC-specific parsing (the `meta`
FullBox container) is covered by synthetic fixtures in `bmff_test.go`.
