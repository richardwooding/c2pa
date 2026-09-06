# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/richardwooding/c2pa` is a flat (single Go package, no subpackages) **pure-Go** library
for C2PA / Content Credentials provenance manifests in JPEG, PNG, BMFF (MP4/MOV/HEIC/HEIF/
AVIF), RIFF (WebP/WAV/AVI), TIFF (and DNG), GIF, MP3, SVG and PDF, with **three modes**:

- **`Read(ctx, container, r) Info`** — the fast, *unverified* reader. Surfaces what a file CLAIMS
  (generator, title, signer CN, signing time, AI flag) like EXIF or an unverified `From:` header. It
  never fails, never does crypto, and is tuned for triage/indexing. Lives in `c2pa.go`.
- **`Validate(ctx, container, r, opts...) ValidationResult`** — the full, opt-in *verifier*. Checks
  the COSE signature, the certificate chain + C2PA cert profile against the trust list, assertion and
  hard-binding hashes, the RFC 3161 timestamp, revocation, and ingredients — reporting C2PA §15 status
  codes. Pure Go, no cgo.
- **`NewSigner(key, chain, opts...)` / `(*Signer).Sign(ctx, container, in, out, m)`** — the *writer*.
  Builds a `c2pa.claim.v2` manifest with the container's hard binding, signs it once with COSE_Sign1
  into an envelope of reserved size, embeds it, and validates its own output before writing a byte.
  Every container's output is checked against c2pa-rs's c2patool in CI (`sign_interop_test.go`).
  All nine containers: JPEG, PNG, GIF, RIFF (WebP/WAV/AVI), TIFF/DNG, MP3, SVG, non-fragmented BMFF
  (MP4/MOV/HEIC/AVIF) and PDF. Lives in `sign.go`.

The package stays one `package c2pa` but is split across topic files — flat *import surface*, not
one file:

- **containers** (find and extract the JUMBF store): `c2pa.go` (JPEG + PNG, and the `Read` path),
  `bmff.go`, `riff.go`, `tiff.go`, `gif.go`, `mp3.go`, `svg.go`, `pdf.go`
- **JUMBF** (parse the store): `boxes.go`
- **validation**: `validate.go`, `cose_verify.go`, `chain.go`, `trust.go`, `revocation.go`,
  `timestamp.go`, `ingredient.go`, `statuscodes.go`
- **hard bindings**: `hashbinding.go` (dispatch + `c2pa.hash.data`), `bmffhash.go` (BMFF and
  Merkle — everything one file can settle), `fragmented.go` (`ValidateFragmented` — Merkle across an
  initialization segment and separate fragment files), `boxmap.go` + `boxeshash.go`
  (`c2pa.hash.boxes`)
- **signing**: `sign.go` (`Signer`, `Sign`, the size-stabilising pipeline), `jumbfwrite.go` (JUMBF
  box writers — promoted from the test corpus, which still uses them), `claimwrite.go`
  (deterministic CBOR `encMode`, claim/assertion builders), `cosesign.go` (COSE_Sign1 with x5chain
  in the PROTECTED header and exact-size `pad`), `tsaclient.go` (the RFC 3161 client behind
  `WithTimestampAuthority`), `embed.go` (the embedder contract, `applyEdits`,
  and the JPEG/PNG embedders; the other containers' embedders live beside their readers in
  `gif.go`, `riff.go`, `tiff.go`, `mp3.go`, `svg.go`), `bmffembed.go` (the C2PA uuid box after
  `ftyp` and the `stco`/`co64`/`saio`/`iloc` offset rewrite), `pdfwrite.go` (the incremental update:
  embedded file stream, file specification, redefined catalog, cross-reference table or stream)

Don't introduce subpackages; that would force exporting internal helpers.

Public surface:

- `Read` / `Info` — fields Present, Attribution, ClaimGenerator, Title, Format, AIGenerated,
  SoftwareAgent, SignedBy, SignedAt. `Attribution` / `AttributionAsset` / `AttributionEmbedded` /
  `AttributionUnknown` say whether the manifest is a claim about the asset, about something it
  carries, or about something nothing could place.
- `Validate` / `ValidationResult` / `StatusEntry` / `StatusCode` / `Severity` — the verifier and its
  result. `ValidateOption` (`WithSigningTrust`, `WithTimestampTrust`, `WithOnlineRevocation`,
  `WithClock`, `WithMaxIngredientDepth`, `WithMaxScan`, `WithHTTPClient`).
- `ValidateFragmented(ctx, init, fragments, opts...)` — `Validate`'s whole pipeline over a
  fragmented BMFF asset's initialization segment (DASH/CMAF: `ftyp` + `moov` in one file, `.m4s`
  fragments in others), with the hard binding checked against each fragment's merkle box. Same
  `ValidateOption`s; the container is BMFF by definition, so there is no parameter for it.
  Fragments are read one at a time under the scan cap, so memory is init + one fragment. The
  roll-up is `assertion.bmffHash.match` only on complete §15.12.2 coverage (every `location`
  `0..count-1` of every merkle-map THAT BINDS THIS INITIALIZATION SEGMENT); otherwise ONE informational
  `general.unsupported` names the locations not verified. A map whose `initHash` is another init's is
  another rendition's — c2pa-rs signs several renditions into one manifest, one map each, the same
  store in every init — and is named as not evaluated (informational), while a supplied fragment that
  claims such a map is a mismatch; an init that matches NO map is tampered (mismatch per map). Per-fragment FAILURES carry the URI suffix `#fragment=<i>` (i = the
  caller's slice index; the location is in the explanation); there are deliberately NO per-fragment
  match entries, so `Has(StatusAssertionBMFFHashMatch)` keeps meaning "fully bound".
- `Signer` / `NewSigner(key crypto.Signer, chain []*x509.Certificate, opts...)` /
  `(*Signer).Sign(ctx, container, in io.Reader, out io.Writer, m Manifest) error` — the writer.
  `Manifest{Title, Actions, Assertions}`, `Action`, `GeneratorInfo`, `Assertion`; `ActionCreated` /
  `ActionOpened` and the `DigitalSourceType*` constants; `SignerOption` (`WithClaimGenerator`,
  `WithVendor`, `WithHashAlgorithm`, `WithTimestampAuthority`, `WithTimestampHTTPClient` — NOT
  `WithHTTPClient`/`WithClock`, which are `ValidateOption`s);
  the `Err*` sentinels (`errors.Is`). The COSE algorithm is inferred from the key (P-256/384/521 →
  ES256/384/512, RSA ≥ 2048 → PS256, Ed25519 → EdDSA). A manifest must open with `ActionCreated`
  or `ActionOpened` (c2pa-rs rejects the output otherwise — our validator does not check this, which
  is why the corpus never noticed); `ActionCreated` on an already-signed asset is refused, since a
  prior manifest proves something preceded it. Re-signing carries every prior manifest verbatim and
  names the previous active one as a `parentOf` ingredient with `activeManifest`, `claimSignature`
  and the `validationResults` c2pa-rs requires. Nothing is written unless the output passes
  `Validate` (`WithMaxIngredientDepth(0)` so a foreign prior signer cannot fail our own output).
- **Embedders** (`embed.go` + the container files) are pure functions of `(asset, store)`: every
  existing store removed, the new one at Annex A's canonical position — deterministic, not c2pa-rs's
  replace-in-place — and `out` depends on the store only through its LENGTH and the bytes inside the
  returned exclusions, which is what lets the pipeline converge a layout with a placeholder store.
  `embedStore` checks the store reads back through `extractJUMBF` before returning. Per container:
  JPEG APP11 run after the last APP0 (64000-byte segments, `En 0x0211`, the layout the signed
  fixture has — re-embedding the fixtures' own stores reproduces them byte for byte); PNG one `caBX`
  after `IHDR`; GIF the application extension after the colour table, version forced to `89a`;
  RIFF the `C2PA` chunk LAST, RIFF size rewritten, a simple-format WebP gains a synthesised `VP8X`
  (with the VP8L alpha bit — c2pa-rs drops it), pad byte outside the exclusion; TIFF a NEW last IFD
  holding only the `0xCD41` entry (§A.3.5), relinked from the previous last IFD, an existing entry
  unlinked (its own IFD) or removed in place (shared IFD), and TWO exclusions — the entry's count
  field and the store (c2pa-rs parity); MP3 a `GEOB` frame last in a rebuilt tag whose other frames
  are copied verbatim and whose major version is PRESERVED (c2pa-rs always emits v2.4 only because
  its `id3` crate re-models v2.3 frames on read; copying v2.3 bytes under a v2.4 header would
  mis-declare every frame size), exclusion = the object bytes only; SVG byte-exact splicing at the
  strict tokenizer's offsets — `xmlns:c2pa` on the root when absent, the element first inside an
  existing direct-child `<metadata>` or a new one first under `<svg>`, exclusion = the base64 text.
  Refused: ID3v2.2, a c2pa prefix bound elsewhere, a RIFF whose size does not fit the file, a GIF
  without a trailer, a JPEG without SOS.
- **BMFF signing** (`bmffembed.go`) binds with `c2pa.hash.bmff.v3` — the offset-marker walk with the
  §A.5.6 exclusions (`/uuid` by usertype at offset 8, `/ftyp`, `/mfra`), written by
  `bmffStandardExclusions` and hashed by `bmffHashDigest`, which DECODES that same CBOR shape so
  writer and verifier cannot drift — and the layout fixpoint converges on the output's LENGTH (there
  are no byte-range offsets to converge). The C2PA uuid box (32-bit size, version/flags 0,
  `"manifest\0"`, an 8-byte zero merkle offset, the store) goes IMMEDIATELY AFTER `ftyp` (§A.5.3),
  which moves everything behind it, so every absolute file offset is rewritten through the same
  `remap` the edits produced: `stco` (u32) / `co64` (u64) entries, `saio` (CENC aux-info offsets),
  and `iloc` extents (versions 0–2; base_offset alone when it exists and every extent shifts alike,
  else each extent_offset; items with a data reference or construction method ≠ 0 are skipped). A
  value that pointed into a removed C2PA box is malformed; a u32 that would overflow is unsupported
  (stco→co64 conversion is out of scope). **Nothing else checks those offsets** — neither validator
  hashes them — so `TestEmbedBMFFOffsets` / `FuzzBMFFEmbed` assert that every offset still
  addresses the same eight bytes, and `TestEmbedBMFFOracle` reproduces `c2pa_signed_video.mp4`
  byte for byte from `video_no_manifest.mp4` plus its store (the two fixtures differ by exactly one
  30662-byte box and a 30662 shift of every `stco` entry). Refused with `ErrFragmentedBMFF`: any
  top-level `moof`, `mfra`, `sidx` or `styp`, or a merkle-purpose C2PA box — a fragmented file's
  binding is a Merkle tree per fragment, which this release does not author. Also refused: trailing
  bytes outside any box, no `ftyp`, nothing after `ftyp`. Every existing C2PA uuid box (any purpose)
  is removed; the core carries the lineage in the new store.
- **Timestamping** (`tsaclient.go`) is opt-in via `WithTimestampAuthority(url)` and is the one thing
  that makes `Sign` touch the network. Sign FIRST, then timestamp the signature (`sigTst2`, §13.2):
  the TBS is `coseCountersignData(cbor.Marshal(signature), protected)` — `coseTimestampTBS`, the
  same bytes `verifyTimestamp` recomputes — hashed with SHA-256 whatever the signing algorithm (as
  c2pa-rs does), sent as a `TimeStampReq` with an 8-byte random nonce and `certReq TRUE`, POSTed as
  `application/timestamp-query`; the reply must be 200 + `application/timestamp-reply`, ≤ 1 MiB, a
  granted `TimeStampResp`. Its token is verified with the validator's OWN checks before it goes
  anywhere near the file: `checkTimestampToken` is the cryptographic half of `verifyTimestampToken`
  (imprint, signer lookup, signed attributes, CMS signature), factored out so the client and the
  validator cannot disagree; plus `id-kp-timeStamping` and the nonce echo, which ties this reply to
  this request. What lands in `sigTst2.tstTokens[0].val` is the DER `TimeStampToken`
  (`ContentInfo`) — NOT the `TimeStampResp` — per §13.2. Trust in the TSA is not judged at sign
  time (the caller chose it; validators decide), but the self-check anchors the token's own
  certificates so `timeStamp.validated` is required of the output. Any failure → `ErrTimestamp`,
  nothing written. **The nonce lives after `genTime` in TSTInfo, among optional fields a struct
  field cannot capture** — Go's decoder matches a trailing `[]asn1.RawValue` against ONE element
  (it silently held a real token's `accuracy` children), so `parseTSTInfo` walks the SEQUENCE's
  elements and takes the first universal INTEGER after the five fixed ones. The envelope reserve
  grows by 10000 bytes (c2pa-rs's allowance) when a TSA is configured, since the token's size is the
  one thing not known before signing; a token that would not fit is an error, never a truncation.
  The test TSA (`newTestTSA`) issues with `tsRawImprint`/`tsNonce` from an `httptest` handler; for
  c2patool the TSA certificates must be valid around the wall clock (`liveTSA`) because a timestamp
  makes c2pa-rs check the signing certificate at the token's time.
- **Message signers.** A key that can only sign whole messages (WebCrypto's `SubtleCrypto.sign`, some
  HSM/KMS APIs) implements the standard `crypto.MessageSigner` (Go 1.25+), and `newSign1` then builds
  its own `cose.Signer` (`messageSigner`) instead of calling `cose.NewSigner`: go-cose only knows
  `crypto.Signer` — for ECDSA it hashes the Sig_structure and calls `Sign(rand, digest, nil)`, opts
  literally nil — which such a key cannot serve. The opts and the encoding contract deliberately mirror
  `x509.CreateCertificate` (which goes through `crypto.SignMessage`): the hash for ES*,
  `rsa.PSSOptions{SaltLength: PSSSaltLengthEqualsHash}` for PS256, `crypto.Hash(0)` for EdDSA; DER back
  for ECDSA — converted to COSE's raw r‖s by `ecdsaRawFromDER`, which pads to the curve width and
  refuses anything else — raw for RSA-PSS and Ed25519. One key type therefore serves both the
  certificate minting and the COSE signature, which is what lets c2pa-inspector sign with a
  non-extractable browser key. `Sign` is never called on such a key (`TestSignMessageSigner` counts);
  no standard-library key implements `SignMessage`, so ordinary keys still go through go-cose.
- **PDF signing** (`pdfwrite.go`) is an INCREMENTAL UPDATE appended after the last `%%EOF` — nothing
  before it changes, so a previous update section's store stays exactly where it was (§A.4.2.1) and
  `pdfCatalogStores`/`storeWithPriorSections` still find it; the new store also carries the prior
  manifests verbatim, because c2pa-rs's PDF reader does no section merge and must resolve the
  `parentOf` from the active store alone. The catalog is resolved the way the reader resolves it —
  the newest `startxref` whose `/Prev` chain PLACES `/Root` at a definition that is a catalog
  (`pdfResolveForWrite` mirrors `pdfXrefRoot`); a document whose catalog is only reachable by
  lexical guessing is refused rather than built on. The update writes: the embedded file stream
  (`/Type /EmbeddedFile /Subtype /application#2Fc2pa /Length n`, unfiltered, `stream\n…\nendstream`
  so `streamPayload` finds it), the file specification (`/Type /Filespec /F /UF /Desc (Content
  Credentials) /AFRelationship /C2PA_Manifest /EF << /F n 0 R >>`), a NEW definition of the catalog
  with the SAME object number AND generation as `/Root` (the ChatGPT fixture's producer redefines
  `12 1 obj`, and the reader's placement check needs the header to match) whose entries are copied
  verbatim except `/AF` — earlier C2PA file specifications dropped so one section associates one
  store (§15.5.2.2, `pdfTallyStores.perSection`), ours appended — and `/Names`, which gains
  `EmbeddedFiles` in place when that is possible (absent, a direct dictionary without it, or a flat
  direct `/Names` array, rebuilt in byte order minus any C2PA entry); an indirect `/Names` or a
  `Kids` tree is copied untouched and the association rests on `/AF` alone, the normative one (ISO
  32000-2 §14.13) and the only one either reader consults. Then a classic `xref` table (20-byte
  entries, `/Prev` = the resolving section's `startxref`, `/Info` and `/ID` carried) when the
  document uses tables, or an uncompressed cross-reference stream (`/W [1 4 2] /Index [R 1 S 3]`,
  exactly what `pdfXrefStream` decodes) when it uses streams; `startxref`; `%%EOF`. New object
  numbers start at `/Size` (or past the highest object seen). Exclusion = the stream payload only —
  the dictionary and `/Length` stay hashed, as the corpus and Adobe's reference do. Refused:
  `/Encrypt` anywhere in the chain, `/Perms` in the catalog (a certifying signature a later update
  would invalidate), an unresolvable catalog. c2pa-rs has NO PDF writer, so there is no reference
  layout; its reader wants only the current catalog's `/AF`, and c2patool reads the update section
  as `Valid`/`Trusted` and chains the ChatGPT fixture's OpenAI manifest as a `parentOf` ingredient.
  `TestEmbedProperties` exempts PDF from re-embed idempotence: appending is the point.
- `ReadAll(ctx, container, r)` — one Info per store: asset's own first (AttributionAsset), then
  object-level ones (AttributionEmbedded), then marker-found unplaced ones (AttributionUnknown).
  Only PDF returns >1 today (§A.4.3).
- `ExtractStore(ctx, container, r)` — the raw JUMBF store as embedded; nil means none found. It
  reads up to `ValidateMaxScan`, NOT Read's 16 MiB `MaxScan`: a store can sit at the very end of a
  large asset (a PDF's incremental update, a BMFF box after `mdat`), and a viewer or a signer
  deciding created/opened must find whatever `Validate` finds — c2pa-mcp's `sign` misjudged a
  >16 MiB PDF as unsigned through `Read` before this. `Read` keeps the triage cap by design.
- `WalkBoxes(ctx, jumbf, fn)` — lower-level JUMBF box-tree walker. Paired with ExtractStore
  this is what a manifest viewer uses to show assertions `Info` doesn't model.
- `ValidationResult.VerifiedSigner()` — the signer's CN/Organization, but only when the ACTIVE
  manifest's signature validated AND its chain reached a trust anchor; "" otherwise. `SignerChain`
  is the chain as PRESENTED and is populated even when it fails to verify, so reading a name
  straight off it is a claim, not a fact — the same trap `Info.SignedBy` carries. `SignedAt` and
  `SignerChain` are guarded to `depth == 0`: `validateManifest` recurses into ingredients after
  assigning them, so without the guard an ingredient's signer and timestamp overwrite the asset's
  (c2pa_signed_video.mp4 reported "Bob" instead of "C2PA Signer").
- `MaxScan` (Read's 16 MiB cap) / `ValidateMaxScan` (Validate's larger cap).

## Commands

```sh
go test ./...                                  # all tests + fuzz seed corpus
go test -run TestRead_SignedJPEG               # single test by name
go test -race -timeout 120s ./...              # what CI runs
go test -run='^$' -fuzz=FuzzWalkBoxes -fuzztime=30s   # mutate one fuzz target
go vet ./...
golangci-lint run
```

CI (`.github/workflows/ci.yml`) runs build + vet + race tests on Go `1.26` and `stable` plus
golangci-lint. `.github/workflows/fuzz.yml` mutates the fuzz targets nightly.

## Read vs Validate — keep them honest and separate

The two modes are the whole point, and the line between them must stay sharp:

- **`Read` reads claims; it does not validate them.** It surfaces unverified metadata and must never
  do crypto, fail, or slow down. Every `Read`-path doc comment leans on the EXIF / unverified
  `From:` framing — keep it. `SignedBy` is who the file *claims* signed it.
- **`Validate` is the honest verifier.** It must either fully check a step or report it as
  informational/unsupported — never half-check and imply trust. `Valid` is true **iff** no
  `SeverityFailure` status was recorded. "Required but absent" (no claim, no signature, no hard
  binding) is encoded as a *failure* status so the roll-up stays a single predicate.

Don't entangle the paths: `Read` builds `Info` via `parseManifest`, which resolves the store with
`parseStore` (in `boxes.go`) and reads ONLY the active manifest — walking every box let an
ingredient's AI flag or signer leak into the summary. `Validate` uses `parseStore` directly for the
raw box bytes + offsets that hashing needs. `Read` still does no crypto; its contract, tests, and
fuzz targets stay green. The x5chain lookup is shared (`x5chainCandidates`): label 33 AND the
pre-1.3 text key "x5chain", both headers — `leafCert` reading only the int label left `SignedBy`
empty for that whole generation of files.

## Things to know before editing

- **Go 1.26 is the floor**, set by `golang.org/x/crypto`'s own `go` directive (pulled in for OCSP).
  It was 1.25 until x/crypto v0.56.0 raised it; that is the second time, so expect a third.
  Use the normal `go mod tidy` workflow; if it raises the floor again, bump the CI matrix's lower
  bound in `.github/workflows/ci.yml` to match `go.mod` in the same change. (The code itself only
  needs Go 1.22+ — `reflect.TypeFor` — so the floor is dependency-driven, not language-driven.)
- **CBOR maps must decode to `map[string]any`.** `decMode` configures fxamacker/cbor with
  `DefaultMapType: map[string]any` — otherwise nested maps come back as `map[any]any` and every
  text-key lookup (`claim["dc:title"]`, etc.) silently misses. This was the original integration bug.
- **The x5chain header key is an `int64`.** go-cose keys protected/unprotected headers with its
  `cose.HeaderLabelX5Chain` constant, which is `int64(33)`. Looking it up with a bare `int(33)`
  literal misses the map entry and yields an empty `SignedBy`. Always use the constant.
- **AI detection is case-folded substring match.** `compositeWithTrainedAlgorithmicMedia` has a
  capital "T", so `isAIDigitalSourceType` lowercases before `strings.Contains(…, "trainedalgorithmicmedia")`.
  It checks both the action's top-level `digitalSourceType` and its `parameters`.
- **`maxJUMBFDepth` (64) caps recursion.** JUMBF `jumb` superboxes nest, and a chain of nested boxes
  (each stripping only an 8-byte header) could otherwise nest ~MaxScan/8 levels and blow the stack on
  adversarial input. Real manifests nest ~4 deep. Don't remove the cap.
- **Everything is best-effort and must never panic.** Malformed/truncated/cancelled input returns
  zero values. The RFC 3161 ASN.1 descent (`rfc3161GenTime`) is deliberately defensive at every
  `asn1.Unmarshal` step. This contract is enforced by the fuzz targets — keep them green.
- **`pdf.go` finds objects lexically, then resolves the document the way a reader does.** The store
  is an embedded file whose file specification carries `/AFRelationship /C2PA_Manifest`, referenced
  from the catalog's `/AF` (spec §A.4.1/§A.4.2.1). It is not a general PDF library — no page tree,
  no content streams, no encryption — but it is well past a scanner: it decodes cross-reference
  streams (`/W` rows, `/Index` ranges, type 2 entries), inflates visible `/Type /ObjStm` streams and
  tracks which objects came out of one. PDF 32000-1 §7.5.7 forbids a stream object inside an object
  stream but permits that file specification dictionary, so **the store's bytes being visible does
  not make the store identifiable** — do not reach for that argument, it is false, and the marker
  fallback is not a substitute for the chain. The catalog is resolved through `startxref`, newest
  first, taking the last section that actually places its own `/Root`: taking the last `/Root` in
  the file lets bytes appended after `%%EOF` redirect the document, and taking only the last
  `startxref` lets them hide the genuine table instead. `/Length` is a hint, verified against
  `endstream` and never trusted; an indirect one resolves only once the object index is complete,
  which is what `repairIndirectLengths` re-cuts those objects for. **An object ends past its stream,
  not at the payload's first `endobj`** — the store is arbitrary binary and can spell that keyword,
  which silently lost the whole manifest. Inflation is capped by `maxPDFInflate`.
  **§A.4.2.1's cross-section merge IS implemented**: `pdfCatalogStores` collects every store the
  document's own catalogs associate, oldest update section first, and `storeWithPriorSections`
  folds their manifests in ahead of the active store's — so an ingredient defined in an earlier
  section resolves, and one that resolves nowhere is a real `ingredient.manifest.mismatch` again.
  The active store's manifests stay LAST so `active()` still picks the current section's, and a
  label the active store redefines wins (that is what an incremental update leaves behind). The
  active store is found through the trailer chain and appended by the caller, never ranked by
  section order: bytes appended after `%%EOF` can place a catalog the section walk would rank ahead
  of the real one. `pdfOtherStores` widens that to what §A.4.2.1
  literally asks ("all C2PA Manifests in all C2PA Manifest Stores as if they were contained in a
  single C2PA Manifest Store"): earlier sections' stores, object-level stores AND marker-found ones
  are all resolved against as one. `partialStores` is gone with it — folding a store in only puts
  its manifests within reach of a reference, it grants them nothing, since anything resolved that
  way is still validated in full and the active store's manifests stay last.
  **§A.4.3 object-level manifests ARE attributed.** The spec puts the association on the object
  itself — "adding an AF entry to the object's stream or dictionary" — so `pdfObjectStores` runs the
  same `/AF` walk the catalog gets, rooted at any other object, and `pdfScan` reports
  `pdfStoreObject` → **`Info.Attribution = AttributionEmbedded`**. That is a resolved fact, not the
  guess `AttributionUnknown` was; `AttributionUnknown` now means only that nothing placed the store
  at all. Consequently `verifyHardBinding` REFUSES to hash the carrier's bytes against an
  object-level manifest: its binding covers the image or font stream it is attached to (§A.4.3 —
  "attached as closely as possible to the object that actually stores the data resource described"),
  so hashing the document produced a false `assertion.dataHash.mismatch`. It is reported
  informational instead: the binding is not absent, its subject is one this extractor does not yet
  isolate. Never report the signer or generator of an embedded or unknown store as the asset's.
- **Update Manifests (§11.2.3) are recognised by their JUMBF type UUID**, `c2um`
  (`updateManifestUUID`) — the labels and box structure are identical to a standard manifest's, so
  `parseJumd` surfacing that UUID is the ONLY thing that can tell one apart. An update manifest
  records assertions added without changing content, so §11.2.3 forbids it a hard binding: treating
  the absence as `hardBinding.missing` failed every correctly formed one. What binds the content is
  the manifest it updates, named by the single `parentOf` ingredient §11.2.3 requires — and that
  manifest describes THESE bytes, unlike an ordinary ingredient's, so `verifyUpdateManifest` runs
  `verifyHardBinding` on it against the asset. `v.hardBound` records that, or the ingredient walk
  reaching the same manifest at depth > 0 would also call it unevaluated. The forbidden set is
  hard bindings, thumbnails, and any action outside `c2pa.edited.metadata` / `c2pa.opened` /
  `c2pa.published` / `c2pa.redacted` → `manifest.update.invalid`; zero or several parents →
  `manifest.update.wrongParents`. **The four allowed actions are a deliberate divergence**:
  c2pa-rs's own status-code doc describes ANY actions assertion in an update manifest as invalid,
  which would reject files §11.2.3 permits — the spec text is followed here.
- **BMFF purpose decides which store is active** (§A.5.3). Ordinarily one box has purpose
  `manifest`; once the asset is updated the store being updated is relabelled `original` and a new
  `update` box is appended as the LAST box of the file, and the update store is then active.
  `bmffJUMBF` prefers update → manifest → original; preferring `manifest` reported the pre-update
  claim, generator and signer as current. The `original` store goes into `v.priorStores` so the
  update's `parentOf` reference resolves into it — the same machinery PDF's cross-section merge
  uses. There is no `bmffHasUpdateManifest` any more; `bmffStores` returns the stores by purpose.
- **`signedAt` lives in an RFC 3161 timestamp.** `sigTst` (1.x) and `sigTst2` (2.x), both COSE
  unprotected headers, hold `tstTokens[].val`, each a `TimeStampResp` → CMS `SignedData` →
  `TSTInfo.genTime`. The walk handles both a full `TimeStampResp` and a bare `ContentInfo`. **Read
  both headers**: a `c2pa.claim.v2` signature carries its timestamp only in `sigTst2`, so looking at
  `sigTst` alone leaves `SignedAt` zero for every 2.x file.

### Validation-specific gotchas

- **The COSE payload is detached.** Real C2PA v2 signatures have `msg.Payload == nil`; the signed
  bytes are the claim box's raw CBOR (`parsedManifest.claimBytes`). `cose_verify.go` injects them
  (`msg.Payload = claimBytes`) before `msg.Verify(nil, verifier)`; `external_aad` is empty. Read the
  `alg` **only from the protected header** — an unprotected-header fallback is a downgrade vector. The
  fixture is **PS256** (RSA-PSS); allowed algs are ES256/384/512, PS256/384/512, EdDSA.
- **Blank-import the hash packages.** go-cose calls `crypto.Hash.New()` at verify time, which panics
  if the hash isn't registered. `cose_verify.go` must `import _ "crypto/sha256"` and `_ "crypto/sha512"`
  or an adversarial alg selection breaks the never-panic guarantee.
- **C2PA RSA certs use an `id-RSASSA-PSS` SPKI that Go won't parse.** Both fixture certs encode their
  SubjectPublicKeyInfo with OID `1.2.840.113549.1.1.10` (not `rsaEncryption`), so `x509.ParseCertificate`
  leaves `cert.PublicKey == nil` — which silently breaks COSE verify *and* chain building. `parseCert`
  in `chain.go` repairs this by extracting the RSA key from the SPKI and assigning the exported
  `cert.PublicKey` field (which `x509.Verify`'s `CheckSignature` and `cose.NewVerifier` both read). Do
  NOT "fix" it by rewriting the SPKI OID in the DER — that changes the signed TBS bytes and invalidates
  the certificate's own signature. Always parse chain certs via `parseCert`, never bare
  `x509.ParseCertificate`.
- **`x509.Verify` does NOT enforce the C2PA cert profile.** `chain.go` manually checks: leaf
  `KeyUsageDigitalSignature`; EKU present and constrained, **rejecting `ExtKeyUsageAny`** and missing
  EKU (fixture EKU is `emailProtection`); leaf `IsCA == false`; no SHA-1/MD5 sig algs; RSA ≥ 2048. Use
  the *verified* timestamp time as `CurrentTime` (so a cert valid at signing but now expired passes);
  fall back to the clock only when no trusted timestamp exists.
- **Timestamp verification = full CMS, not just `genTime`.** `timestamp.go` extends the
  `rfc3161GenTime` descent to verify the SignedData signature and chain the TSA cert to the embedded
  TSA pool. **The signedAttrs re-encoding gotcha:** the signature covers the attrs as a universal
  `SET OF` (`0x31`), but on the wire they're `[0] IMPLICIT` (`0xA0`) — copy `raw.FullBytes` and
  overwrite byte 0 from `0xA0` to `0x31` (same length octets); do **not** re-sort.
- **What the timestamp's `messageImprint` covers is non-obvious** (verified empirically against the
  fixture + c2pa-rs `sigtst.rs`): it is `SHA(cose_countersign_data(payload, protected))`, where
  `cose_countersign_data` is the CBOR array `["CounterSignature", <protected-header bstr>, <empty
  external_aad>, payload]`. For **V1 (`sigTst`)** the `payload` is the **claim bytes** (the COSE
  payload); for **V2 (`sigTst2`)** it is the **CBOR-bstr-encoded COSE signature value**. It is NOT a
  bare hash of the signature — `coseCountersignData` in `timestamp.go` builds this exactly. The
  fixture's TSA is real DigiCert (chains to a cross-signed "DigiCert Trusted Root G4", which is *not*
  self-signed), so tests anchor the TSA pool at the token's top cert (issuer absent from the token),
  not a self-signed root.
- **Hard-binding hashes need the whole asset; `MaxScan` truncation is not a mismatch.** `c2pa.hash.data`
  exclusions are *file* byte ranges (fixture: exclude `[20, 117293)`). If the asset exceeds the scan
  cap the hash can't be computed — emit an **informational** status, never a false `dataHash.mismatch`.
  Hash assertions over `rawAssertion.boxContent` (the superbox PAYLOAD — everything after its 8-byte
  header: jumd + data box) for `hashed_uri`, which is what `hashedURI` writes and c2pa-rs's
  `calc_manifest_box_hash` reads; sub-slice, never re-encode. BMFF hard bindings (`c2pa.hash.bmff.v2`/`.v3`) ARE verified (`bmffhash.go`): a single
  ascending pass where each top-level box not wholly excluded contributes its absolute offset as an
  8-byte big-endian integer followed by its bytes minus exclusion ranges. v1 `c2pa.hash.bmff` must be
  IGNORED per spec §18.6.1 (v1-only manifests → `hardBinding.missing`);
  a BMFF binding on a non-BMFF container → `hardBinding.missing` (not
  informational — see verifyHardBinding). Assertion CBOR encodes absent exclusion fields as explicit
  nulls — every optional-field decode must be nil-tolerant. The standard `/uuid` exclusion relies on
  its `data` predicate (offset 8 == the C2PA usertype) to exclude only the C2PA box. Exclusion `flags`
  with `exact=false` use spec bits-set semantics — deliberately NOT c2pa-rs's inverted subset test.
- **Merkle BMFF (`merkle` array) is verified in full wherever the bytes are in hand.** Three
  arrangements exist. (a) A **non-fragmented** asset whose `mdat` is hashed piecewise — leaves are
  cut from the box, the tree is rebuilt (`merkleLayers`), and it is checked in FULL. (b) A
  **fragmented asset in one flat file** — `initHash` covers everything before the first `moof`;
  each chunk (a `moof` and the boxes up to the next one, `bmffChunks`) is hashed with the same
  offset-marker walk over just its boxes and checked against the proof in the C2PA `merkle` box
  preceding it (`merkleProve`, c2pa-rs's `check_merkle_tree`). Chunk count, merkle-box count and
  the map's `count` must all agree; boxes pair with chunks **positionally**, as in c2pa-rs; and box
  `k` must say `location` `k` (§15.12.2 — otherwise two chunks could swap places along with their
  proofs; c2pa-rs does not check this). (c) **Fragmented across files** (.m4s) —
  `ValidateFragmented` (`fragmented.go`): `initHash` is checked over the whole initialization
  segment once per map (c2pa-rs recomputes it per fragment), and each fragment is hashed from ITS
  OWN offset 0 with the exclusions re-resolved against its own boxes (so `/uuid` removes the
  fragment's own merkle box), paired to its map by `(uniqueId, localId)` — not position — and folded
  up its proof from the `location` the box states. `Validate` alone on an initialization segment
  (no `moof`) still checks `initHash` and reports an informational pointing at `ValidateFragmented`.
  A wrong `initHash` is a `mismatch` wherever it is seen: the file in hand disproves it.
  Split-file rules, which `ValidateFragmented(ctx, init, nil)` enforces and `Validate(ctx, BMFF,
  init)` does not: a flat `hash` is `malformed` (as in c2pa-rs — it says nothing about the
  fragments); `initHash` is REQUIRED on every map (**deliberate divergence** — c2pa-rs silently
  accepts a map without one, leaving the segment that carries the manifest bound by nothing);
  structural defects in a supplied fragment (unparseable, no merkle box, `location >= count`, a box
  naming a tree the manifest lacks) are FAILURES, not informational — the caller asserted these are
  this asset's fragments, the same reasoning that makes a BMFF binding on a JPEG
  `hardBinding.missing`; a `c2pa.hash.data`-only manifest on the init is `hardBinding.missing` and
  the fragments are never read; a fragment that hits the scan cap is informational and its location
  shows up as "not verified"; cancellation mid-fragment is `general.error` at that fragment, so an
  aborted run never comes out `Valid`.
  Things that are easy to get wrong: a Merkle leaf starts **16 bytes** into the `mdat` box
  (`mdatBlockPrefix`) regardless of whether the box uses an 8- or 16-byte header, so it is NOT the
  box's header length; the tree carries an **unpaired last node up UNCHANGED** rather than
  duplicating and re-hashing it, which is what makes it C2PA's tree and not the Bitcoin-style one
  (`merkleLayout` and `merkleLayers` describe the same shape, and `TestMerkleLayout` pins that);
  `hashes` is **any one row** — leaf-most, root, or intermediate — and its LENGTH is what says
  which, so a rebuilt tree is matched on length and a proof is folded until it reaches that length;
  `initHash` uses the same offset-marker walk as the flat hash (`hashBMFFTopLevel`), not a plain
  byte hash — c2pa-rs reaches it through the same `hash_stream_by_alg` path, with `[first moof,
  EOF)` added to the exclusions; a merkle box's CBOR is followed by **zero padding** to a fixed box
  size (§A.5.4.1.3), so it is decoded with `UnmarshalFirst`, never `Unmarshal`; a merkle box has NO
  8-byte merkle-offset field — only the store-carrying purposes do (`c2paMerklePayload`); the proof
  in a box is **optional** (absent when the leaf row is stored) and its LENGTH must fit the climb
  exactly — too short, too long, or a stored row no tree of that `count` has, is `malformed`
  rather than a mismatch, because nothing was compared; and a chunk's hash is anchored at
  **file-absolute** offsets, which is exactly why concatenating `.m4s` files is NOT a flat
  fragmented file (§A.5.4.1.2) — the test that pins it uses fragments without `styp`, so anchoring
  is the ONLY thing that differs. `maxMerkleLeaves` caps the leaf count because `fixedBlockSize`
  is attacker-controlled and is what turns an assertion's size into our allocation;
  `maxMerkleProof` caps a box's proof for the same reason. Merkle maps pair with `mdat` boxes
  **positionally**, so a count mismatch is reported rather than guessed around.
- **`c2pa.hash.boxes` binds structurally, not by byte range** (`boxeshash.go` over `boxmap.go`). The
  assertion is an ordered list of entries, each naming one or more CONSECUTIVE boxes and hashing the
  span they cover; verification re-derives the asset's own box map and walks the two lists in
  lockstep, so both the names and their order must line up. The box map is a **wire format shared
  with whoever signed the asset** — names and byte ranges are the signer's convention, and changing
  one silently breaks already-signed files. The load-bearing conventions: a JPEG box starts at its
  `0xFF` marker (marker + length field are hashed with the payload) and the SOS box swallows the
  whole entropy-coded scan, stuffed `FF00` and restart markers included, so image data is bound by
  SOS rather than left unnamed; a run of APP11 CAI segments collapses into ONE box named `C2PA`; a
  PNG chunk box spans length + type + data + CRC, the 8-byte signature is the synthetic `PNGh` box
  (a producer may legitimately omit it, and only it, from the list), and each `caBX` chunk is its
  own `C2PA` box; a GIF global colour table folds into the LSD box and a local one into its image
  descriptor's, with image data a separate `TBID` box. Only JPEG, PNG and GIF have a box map —
  everything else reports `general.unsupported` rather than guessing at a structure.
  **The permitted-exclusion check is the security boundary.** A box-hash entry may carve ranges out
  of its own hash, which is exactly how a forged assertion would leave tampered pixels unbound, so
  every exclusion is checked against what the container says is excludable at all (spec §15.12.3):
  the manifest store, and asset metadata (a JPEG `COM`/signed `APP1`/`APP13` payload, a PNG
  `eXIf`/`iTXt`/`tEXt`/`zTXt` payload including its CRC, a GIF comment or XMP extension's sub-block
  data). Anything else is `assertion.boxesHash.mismatch`. Do not relax this to "the range is inside
  the box". Exclusions must arrive already increasing and non-overlapping and are validated **as
  given**, never sorted. Two deliberate divergences from c2pa-rs: the APP11 run must be contiguous,
  and boxes the assertion never names are `assertion.boxesHash.unknownBox` rather than silently
  unbound — c2pa-rs stops when its own list runs out, which leaves an appended trailer unchecked.
- **Trust lists are embedded via `go:embed trustlists/*.pem`.** `C2PA-TRUST-LIST.pem` (signing
  anchors) and `C2PA-TSA-TRUST-LIST.pem` (TSA anchors) are the official C2PA conformance lists; they
  go stale — refresh from `c2pa-org/conformance-public`. Callers override via `WithSigningTrust` /
  `WithTimestampTrust`. The c2pa-rs **test** fixture is signed by a *test* PKI and will NOT validate
  against the production list — tests anchor at the fixture's own chain via the override options.
- **`golang.org/x/crypto`** is a dependency (for `ocsp`). CMS/RFC 3161 signature verification is
  hand-rolled in `timestamp.go` (no mature pure-Go CMS lib; extending the proven ASN.1 descent keeps
  deps light and the never-panic contract ours). Still no cgo.

## Tests

`testdata/c2pa_signed.jpg` is a real signed JPEG from contentauth/c2pa-rs (see `testdata/README.md`
for provenance + license). `TestActionsAreAI` synthesises CBOR assertions in-memory because there's
no public AI-positive fixture. `example_test.go` holds the runnable godoc examples — the JPEG pair plus
`ExampleRead_pdf` / `ExampleValidate_pdf` / `ExampleReadAll_pdf`, and the signer's
`ExampleSigner_Sign` / `ExampleSigner_Sign_resign` — and they have real `// Output:` blocks, so
`go test` checks them. The signing examples mint a self-signed P-256 leaf in-test (`exampleSigner`;
Go's `x509.Verify` accepts a leaf that is itself in the root pool, so a one-cert chain verifies)
and sign `video_no_manifest.mp4` / re-sign `c2pa_chatgpt.pdf` into buffers — nothing lands in
`testdata/`. The re-sign example is the PDF and not `c2pa_signed.jpg` on purpose: the ingredient
only reports `ingredient.manifest.validated` when its own validation adds no failure, and the JPEG
fixture's DigiCert timestamp is `timeStamp.untrusted` (a FAILURE) against the embedded TSA list,
which `WithSigningTrust` does not touch; the ChatGPT PDF has no timestamp at all. **The README's PDF section is the same three examples**, with each
checked value repeated as an inline `// comment` — so those values are verified in `example_test.go`
and hand-copied in `README.md`. Change one and change the other; nothing catches the README.

The `Fuzz*` targets cover the read pipeline, the recursive box walker,
the ASN.1 timestamp descent, the offset-aware `parseStore`/`parseBoxTree`, the full `Validate`
pipeline, the CMS timestamp verifier, the exclusion-range hashing, the PDF object scan, and the
Merkle paths — the leaf cut, the flat fragmented file (`FuzzBMFFFragment`), the merkle box decoder,
the proof fold and the whole split-file pipeline (`FuzzValidateFragmented`); their seed corpora run
as normal tests in CI. **`.github/workflows/fuzz.yml`
lists the targets by name**, so a new `Fuzz*` function is silently un-fuzzed nightly until it is
added there — `FuzzBMFFMerkle` and `FuzzMerkleLeafRanges` shipped a release without being listed.

**PDF has a real fixture AND synthetic documents.** `testdata/c2pa_chatgpt.pdf` is a genuine
ChatGPT-pipeline document contributed under this repository's MIT licence (see
`testdata/README.md`) — the only fixture written by a real producer rather than assembled by a
test, and the one the PDF godoc examples run against. It validates fully: trusted signer
`OpenAI Media Service`, `assertion.dataHash.match`, and no timestamp at all (`timeStamp.missing`).
Reach for it when the question is "what does a real producer write"; its carrier shape — catalog at
generation 1, `/Type /FileSpec`, a literal-string `/Subtype`, the manifest added by an incremental
update — is what synthetic builders do not think to produce.

Everything else is synthesised, like the BMFF tests (`pdf_test.go`'s `pdfDoc` builder), because one
fixture cannot express a broken xref chain or a store in an object stream. A fully valid *generated*
PDF comes from the corpus (`assembleAsset`'s PDF case, in the positive matrix). Where `pdf_test.go`
carries the JPEG fixture's own store in a PDF, that fixture's `c2pa.hash.data` legitimately
mismatches — its exclusions describe the JPEG — so those tests assert on the signature step, not on
`Valid`.

**Validation tests are self-contained.** The fixture's signer chain (leaf + intermediate) is in its
own COSE x5chain, so positive tests anchor a test pool at the fixture's own intermediate via
`WithSigningTrust` rather than shipping the c2pa-rs test root. Failure paths are synthesised by byte
-mutating the fixture (flip image data → `dataHash.mismatch`; flip an assertion → `hashedURI.mismatch`;
corrupt the COSE signature → `claimSignature.mismatch`; empty trust pool → `signingCredential.untrusted`)
and by generating ephemeral certs in-test — no new binary fixtures.

**There is also a generated corpus** (`corpus_gen_test.go`, `corpus_container_test.go`,
`corpus_test.go`, `corpus_tsa_test.go`, `corpus_timestamp_test.go`, `corpus_fuzz_test.go`) that
builds valid C2PA assets from scratch — JUMBF superbox/`jumd` writer, assertion store, 1.x and 2.x
claims, COSE_Sign1, JPEG APP11 / PNG caBX / PDF embedded-file framing, and a hand-rolled
RFC 3161 / CMS token writer —
then applies named mutations. It exists because five fixtures cannot express an expired certificate,
an ES256 signature, or a timestamp that fails one specific way. Everything is built in memory;
nothing lands in `testdata/`. Four things to know before extending it:

- **`buildAsset` iterates to a fixpoint.** The `c2pa.hash.data` exclusion is circular — the declared
  `start`/`length` change the CBOR integer width that determines them — so it converges the offsets,
  then writes the digest in a final pass. The digest lives inside the excluded range, so writing it
  cannot invalidate it. Anything the generator emits must therefore be **length-stable across
  passes**, or the fixpoint never settles.
- **That is why the test TSA signs with RSA PKCS#1 v1.5, not ECDSA.** An ECDSA DER signature is a
  `SEQUENCE{r,s}` whose length varies with the leading bits of r and s, so a freshly minted token
  changes size between passes. PKCS#1 v1.5 is fixed-length and deterministic. (The COSE signature is
  fine either way — COSE ECDSA is raw `r||s`, fixed width.)
- **The timestamp binding rule is never reimplemented.** `mintTSToken` takes `tbs` from the package's
  own `coseParts` + `coseCountersignData`, so a generated token cannot drift from what the validator
  recomputes. Do not hand-roll the CounterSignature array in a test.
- **Assert on the exported `Status*` constants, never string literals.** `StatusCode.Severity()`
  treats an unknown code as *informational*, so a typo'd literal degrades silently into a passing
  test instead of failing.

**Every declared status code has an emission site**, and that is an invariant worth keeping: a code
that can never be reported is worse than an absent one, because `StatusCode.Severity()` treats an
unknown code as *informational* and a caller matching on it waits forever. `manifest.multipleParents`
was added without one and had to be fixed separately. To check, compare the `Status*` constants in
`statuscodes.go` against `v.add(Status…` across the package.

Where the recent ones live: `assertion.boxesHash.*` in `boxeshash_test.go`; `assertion.bmffHash.*`
including the Merkle paths in `bmffmerkle_test.go`, and the split-file paths plus
`ValidateFragmented` in `fragmented_test.go`; `manifest.update.invalid` /
`manifest.update.wrongParents` / `manifest.multipleParents` in `updatemanifest_test.go`.

**The signer's acceptance test is c2patool.** `sign_interop_test.go` signs each supported container
and runs c2pa-rs's `c2patool` over the file: `Valid` with only `signingCredential.untrusted` in
`failure` for a private chain, `Trusted` with `trust --trust_anchors root.pem`, the right hash-match
code in `success`, and — for a re-sign — the prior manifest listed as a `parentOf` ingredient with no
failure deltas. The timestamp row (`TestSignInteropTimestamp`) checks `timeStamp.untrusted` stays
INFORMATIONAL without the TSA anchor and becomes `timeStamp.trusted` with it — supplied through
`--settings` TOML, where v0.27.16 has ONE list, `trust.trust_anchors`, for manifest signers and TSAs
alike (a `trust_kind = "tsa"` table is silently ignored, not rejected: settings tolerate unknown
keys, so a wrong schema looks like "anchors not applied", never like an error). It skips when the
binary is absent unless `C2PA_REQUIRE_C2PATOOL` is set, which the
`interop` job in `ci.yml` sets so it can never pass by skipping. The pin (`v0.27.16`) moves in lockstep
with `corpus.yml`. Before this gate existed, generated assets had never been run through c2patool at
all — and the corpus's COSE put x5chain in the unprotected header under a text key for years without
anything noticing, because `x5chainCandidates` reads both.

**The corpus frames through the production embedders.** `assembleAsset(container, store)` is
`embedStore(container, unsignedCorpusAsset(container), store)` for every container but PDF, so the
positive matrix and every negative case exercise INSERTION into an existing asset with the same code
`Sign` uses; `assetFraming` returns `[]byteRange` because TIFF has two exclusions. `buildAsset` sets
`manifestSpec.bmffBinding` for BMFF, so `buildFramedAsset` writes `c2pa.hash.bmff.v3` and hashes with
`bmffHashDigest`; the matrix is 9 containers × 4 algorithms × 2 claim versions = 72 rows, every one
of them through `embedStore` — the hand-built PDF frame is gone (`pdfProducerFraming` and
`pdfTwoSectionFraming` remain for the reader shapes they exercise).

**Fragmented assets are built in memory too.** `fragmentedFlatAsset` / `fragmentedFiles`
(`bmffmerkle_test.go`) lay out flat and split fragmented assets with every merkle box padded to one
fixed size, so what a box says never moves the chunk after it and no fixpoint is needed;
`signedFragmentedAsset` (`fragmented_test.go`) wraps the split init in a signed manifest whose
store box is placed LAST, so `initHash` (`moov` alone) is independent of the store's size — the
same argument `buildBoxHashAsset` makes. `runFragmented` exercises the binding alone;
`validateFragmentedCorpus` runs the real entry point. `ExampleValidateFragmented` runs over
`testdata/dash/dashinit.mp4` + `dash1.m4s`, a third-party PRE-SIGNED pair from c2pa-rs's fixtures
(1.x claim, `c2pa.hash.bmff.v2`, one fragment of eleven, canonical CBOR key order in the merkle box),
anchoring the chain it presents; its `// Output:` is the honest partial verdict — valid, not bound,
"1 of 11 fragments verified". `testdata/dash/bunny/` is c2pa-rs's UNSIGNED Big Buck Bunny rendition
(init + 11 `.m4s`), the input the fragmented signer's tests and the c2patool interop rows sign.

**Cost tests assert a SCALING RATIO, not a wall-clock ceiling.** `assertScalesLinearly` (in
`pdf_test.go`) builds a document at n and 4n objects and fails when the larger takes more than 8x —
linear grows 4x, quadratic 16x, and the midpoint separates them. Do not add another
`time.Since(start) > N*time.Second` guard — there are none left in the file, and that is deliberate.
Three of them existed; two went red on CI within a day of each other (8.02s against an 8s bound for
work that takes 1.3s locally, then 4.38s against a 4s bound for 0.39s of work). Headroom is not the
fix: a shared runner can be 10x slower than a developer machine, which is the same order as the
regression these are meant to catch, so any bound tight enough to catch one is loose enough to flake.

**Box-hash corpus assets are built in two passes** (`buildBoxHashAsset`), not by fixpoint like the
data-hash ones. The first pass has no hard binding and exists only to lay the container out so its
box map can be read; the second embeds the assertion derived from it. That is sound because a box
hash covers box CONTENT, not offsets — adding the assertion grows the store's box, whose bytes are
never hashed, and shifts everything after it without changing any other box's bytes. The builder
asserts that rather than assuming it.
