# c2pa

[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/c2pa.svg)](https://pkg.go.dev/github.com/richardwooding/c2pa)
[![CI](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/c2pa)](https://goreportcard.com/report/github.com/richardwooding/c2pa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Website:** [richardwooding.github.io/c2pa](https://richardwooding.github.io/c2pa/)

A small, **pure-Go** (no cgo) library for [C2PA / Content Credentials](https://c2pa.org)
provenance manifests embedded in **JPEG**, **PNG**, **BMFF** (MP4, MOV, HEIC, HEIF, AVIF),
**RIFF** (WebP, WAV, AVI), **TIFF** (and DNG), **GIF**, **MP3**, **SVG** and **PDF** files, with three modes:

- **`Read`** — a fast, *unverified* reader. Surfaces what a file *claims* (creating tool, title,
  format, AI-generated flag, signer identity, signing time) like EXIF or an email `From:` header.
- **`Validate`** — a full, opt-in *verifier*. Checks the COSE signature, the certificate chain
  against the C2PA trust list, assertion and hard-binding hashes, the RFC 3161 timestamp,
  revocation, and ingredients — reporting C2PA status codes. Pure Go, no `c2pa-rs`/CGO.
- **`Sign`** — a *writer*. Embeds a signed `c2pa.claim.v2` manifest into any of the nine containers
  with your key and certificate chain, optionally timestamped, chaining any manifest already there.
  Every container's output is checked against c2pa-rs's `c2patool` in CI.

```sh
go get github.com/richardwooding/c2pa
```

## `Read` — fast, unverified triage

`Read` reports the file's **claims**; it does **not** authenticate them. Treat every field like
EXIF: accurate-as-recorded, not proven. `SignedBy` is *who the file claims signed it*. Use it for
**search, indexing, triage, and inventory** ("find images with Content Credentials", "find
AI-generated assets") — not for trust decisions.

```go
f, _ := os.Open("photo.jpg")
defer f.Close()

info := c2pa.Read(context.Background(), c2pa.JPEG, f) // or c2pa.PNG / c2pa.BMFF / c2pa.RIFF / c2pa.TIFF / c2pa.GIF / c2pa.MP3 / c2pa.SVG / c2pa.PDF
if !info.Present {
    return // no Content Credentials embedded
}

fmt.Println(info.ClaimGenerator) // e.g. "Adobe Firefly"
fmt.Println(info.Title)          // claim dc:title
fmt.Println(info.Format)         // claim dc:format
fmt.Println(info.AIGenerated)    // declared AI-generated?
fmt.Println(info.SoftwareAgent)  // tool that performed the action, e.g. "gpt-image/2.0"
fmt.Println(info.SignedBy)       // CLAIMED signer cert CN (unverified)
fmt.Println(info.SignedAt)       // RFC 3161 signing time (unverified)
```

`Read` is best-effort and never returns an error: a missing or malformed manifest yields
`Info{Present: false}`. It reads at most `c2pa.MaxScan` (16 MiB) from the reader and honours the
context — a cancelled call surrenders promptly mid-scan.

For **RIFF** (WebP, WAV, AVI), the store is a top-level `C2PA` chunk inside the outer `RIFF`
container; a chunk declaring more bytes than the file holds is refused rather than read past.

For **TIFF**, **BigTIFF** and **DNG**, the store is IFD tag `0xCD41` with field type UNDEFINED;
every IFD in the chain is checked, and the chain is hop-capped because a next-IFD offset may point
backwards. Classic and BigTIFF are the same walk at different field widths — 4- vs 8-byte offsets,
and three counts that classic TIFF deliberately does not share.

For **GIF**, the store is the application extension identified by `C2PA_GIF`, reassembled from its
data sub-blocks; the block structure is walked rather than scanned, since LZW image data can spell
the marker. For **MP3**, it is an ID3v2 `GEOB` frame with MIME type `application/c2pa`. For **SVG**,
it is base64 in a `<c2pa:manifest>` element bound to `http://c2pa.org/manifest`, parsed as XML so a
match in a comment or CDATA is not mistaken for it.

For **PDF**, the manifest store is the embedded file the document catalog associates with
`/AFRelationship /C2PA_Manifest` (spec §A.4). The catalog is the one the last `startxref` names, so
bytes appended after `%%EOF` cannot redirect the document; a catalog or file specification
compressed into an object stream is recovered by inflating it, and a `/FlateDecode` stream is
inflated under a bound. Where the catalog associates no store, one the spec's markers find is still
surfaced. Where an object associates one of its own (§A.4.3 object-level manifests, attached to an
image or font stream through its `/AF` entry) that association is resolved, so the manifest is
reported as a claim about that resource — `Info.Attribution` is `AttributionEmbedded`, and its hard
binding is not hashed against the document, which would be the wrong subject. Only a store nothing
associates at all falls back to `AttributionUnknown`. Every store the document carries is resolved
against as one, across incremental update sections and object levels alike, which is what §A.4.2.1
asks.

| `Info` field | Meaning |
|---|---|
| `Present` | a C2PA manifest was found and parsed |
| `Attribution` | who the manifest is a claim **about**. `AttributionAsset` when the asset's own structure associates it; `AttributionEmbedded` when the asset associates it with a resource it CARRIES rather than with itself (PDF §A.4.3); `AttributionUnknown` when only the C2PA markers identified it and nothing places it; `AttributionNone` (the zero value) when there is no manifest. For `Embedded` and `Unknown`, **do not report its signer as the asset's** |
| `ClaimGenerator` | the tool that created/edited the asset |
| `Title` | claim `dc:title` |
| `Format` | claim `dc:format` (declared media type) |
| `AIGenerated` | a `c2pa.actions` `digitalSourceType` declares `trainedAlgorithmicMedia` / `compositeWithTrainedAlgorithmicMedia` |
| `SoftwareAgent` | the tool the first `c2pa.actions` action names, as `name/version` (e.g. `gpt-image/2.0`) — the model or app, where `ClaimGenerator` is often the signing service |
| `SignedBy` | COSE signer leaf-cert common name — **unverified**; the proven counterpart is `ValidationResult.VerifiedSigner()` |
| `SignedAt` | RFC 3161 signing time — **unverified**; the proven counterpart is `ValidationResult.SignedAt` |

## `Validate` — full cryptographic verification

`Validate` is the verified counterpart. It performs the complete C2PA validation algorithm in pure
Go and returns a structured result with per-step status codes:

```go
f, _ := os.Open("photo.jpg")
defer f.Close()

r := c2pa.Validate(context.Background(), c2pa.JPEG, f)
if r.Valid {
    fmt.Println("verified, signed at", r.SignedAt)
} else {
    fmt.Println("not valid:", r.FirstFailure().Code)
}

// Inspect individual outcomes:
fmt.Println("signature verified:", r.Has(c2pa.StatusClaimSignatureValidated))
fmt.Println("signer trusted:", r.Has(c2pa.StatusSigningCredentialTrusted))
for _, s := range r.Statuses {
    fmt.Printf("[%v] %s — %s\n", s.Severity, s.Code, s.Explanation)
}
```

What it verifies:

- **COSE signature** — the `COSE_Sign1` over the claim (ES256/384/512, PS256/384/512, EdDSA).
- **Certificate chain + C2PA profile** — chains the signer to the trust list and enforces the C2PA
  certificate profile (EKU, key usage, no weak algorithms), at the verified signing time.
- **Hash bindings** — the hard binding and each assertion's `hashed_uri`. The hard binding is
  `c2pa.hash.data` for every container but BMFF, `c2pa.hash.bmff.v2`/`.v3` for BMFF assets, or the
  structural `c2pa.hash.boxes`, which is
  verified for JPEG segments, PNG chunks and GIF blocks — the containers whose box naming C2PA
  defines. A box hash may only exclude the manifest store and asset metadata; an exclusion reaching
  anywhere else is a mismatch, not a permitted edit.
- **Merkle BMFF** — a `c2pa.hash.bmff.v3` `merkle` array is verified in full wherever the bytes are
  in hand. A non-fragmented asset whose `mdat` is hashed piecewise has its leaves cut from the box and
  the tree rebuilt; a fragmented asset in one flat file has its initialization hash checked and every
  chunk checked against the Merkle proof in the chunk's own `merkle` box; an asset split across files
  (DASH/CMAF) is verified with `ValidateFragmented` — see below. An initialization segment read on its
  own through `Validate` proves or disproves its hash, and the fragments it binds — other files — are
  named rather than folded into a success.
- **RFC 3161 timestamp** — full CMS signature verification, the TSA chain, and that the timestamp
  covers this signature.
- **Revocation** — OCSP/CRL, opt-in (off by default), soft-fail.
- **Update manifests** — a manifest that adds assertions without changing the content (spec
  §11.2.3) carries no hard binding of its own, so one is not demanded of it. What binds the content
  is the manifest it updates, reached through its single `parentOf` ingredient, and that binding is
  verified against the asset. An update manifest carrying a hard binding, a thumbnail, or an action
  that would change content is reported as invalid. For BMFF the updated store stays in the file
  under purpose `original` and both are read as one.
- **Ingredients** — recursive validation of nested manifests, with cycle detection.

`r.Valid` is true exactly when no failure-severity status was recorded. Like `Read`, `Validate`
never returns an error and never panics — malformed or untrusted input is reported as failure
statuses. It reads up to `c2pa.ValidateMaxScan` (256 MiB) so it can hash the whole asset; an asset
larger than the cap reports an informational status rather than a false hash mismatch.

### Trust anchors and options

By default `Validate` uses the official C2PA conformance trust lists, embedded in the binary (see
[`trustlists/`](trustlists/README.md)). These are a point-in-time snapshot — refresh them
periodically. Supply your own anchors and tune behaviour with options:

```go
r := c2pa.Validate(ctx, c2pa.JPEG, f,
    c2pa.WithSigningTrust(myPool),       // override signing-anchor *x509.CertPool
    c2pa.WithTimestampTrust(myTSAPool),  // override TSA-anchor pool
    c2pa.WithOnlineRevocation(true),     // enable OCSP/CRL (network; default off)
    c2pa.WithClock(func() time.Time { return now }), // signing-time fallback
    c2pa.WithMaxIngredientDepth(16),     // bound nested-manifest recursion
    c2pa.WithMaxScan(64 << 20),          // cap bytes read
    c2pa.WithHTTPClient(client),         // HTTP client for OCSP/CRL
)
```

`ValidationResult` also exposes `Info` (the same fields `Read` returns), `ActiveManifestLabel`, and
the parsed `SignerChain`. Status codes mirror the [C2PA specification §15](https://spec.c2pa.org)
(e.g. `claimSignature.validated`, `signingCredential.untrusted`, `assertion.dataHash.mismatch`);
each `StatusEntry` has a `Severity` (success / informational / failure).

### Fragmented BMFF (DASH / CMAF)

A streaming asset ships as an initialization segment (`init.mp4`: `ftyp` + `moov`, carrying the
manifest) and media fragments (`.m4s`: `moof` + `mdat`, each carrying the Merkle proof that binds it).
`ValidateFragmented` runs the whole pipeline over the initialization segment and checks every
fragment against its proof, reading one fragment at a time. Supplying a subset is a legitimate partial
check: it is reported as informational, never as a false match, and a fragment that has been tampered
with fails at its own index.

```go
init, _ := os.Open("video/init.mp4")
paths, _ := filepath.Glob("video/*.m4s")
frags := make([]io.Reader, 0, len(paths))
for _, p := range paths {
    f, _ := os.Open(p)
    defer f.Close()
    frags = append(frags, f)
}
r := c2pa.ValidateFragmented(ctx, init, frags)
fmt.Println(r.Valid, r.Has(c2pa.StatusAssertionBMFFHashMatch)) // bound only if every fragment was supplied and verified
for _, s := range r.Statuses {
    fmt.Println(s.Code, s.URI, s.Explanation) // a fragment failure's URI ends in "#fragment=<i>"
}
```

## `Sign` — write Content Credentials

`NewSigner` takes a `crypto.Signer` and its certificate chain, leaf first (the root may be left
out); `Sign` writes a copy of the asset with a `c2pa.claim.v2` manifest embedded at the container's
canonical position, bound to the content with `c2pa.hash.data` (or `c2pa.hash.bmff.v3` for BMFF).
The COSE algorithm follows the key. Nothing reaches `out` until the output has passed `Validate`:
a signed asset this library could not verify is a bug, not an output.

```go
keyPEM, _ := os.ReadFile("signer.key")  // PKCS#8, unencrypted
crtPEM, _ := os.ReadFile("signer.crt")  // leaf first, then any intermediates
kb, _ := pem.Decode(keyPEM)
key, _ := x509.ParsePKCS8PrivateKey(kb.Bytes)
var chain []*x509.Certificate
for b, rest := pem.Decode(crtPEM); b != nil; b, rest = pem.Decode(rest) {
    c, _ := x509.ParseCertificate(b.Bytes)
    chain = append(chain, c)
}

signer, err := c2pa.NewSigner(key.(crypto.Signer), chain,
    c2pa.WithClaimGenerator("my-app", "1.2.0"))
if err != nil {
    return err // ErrSignerKey / ErrSignerChain: the key or chain would not verify
}

in, _ := os.Open("photo.jpg")
out, _ := os.Create("photo-signed.jpg")
err = signer.Sign(ctx, c2pa.JPEG, in, out, c2pa.Manifest{
    Title: "photo.jpg",
    Actions: []c2pa.Action{{
        Action:            c2pa.ActionCreated, // this asset has no earlier provenance
        DigitalSourceType: c2pa.DigitalSourceTypeDigitalCapture,
    }},
})
```

A key that can only sign whole messages — WebCrypto, some HSM or KMS APIs — implements the standard
`crypto.MessageSigner` too; `Sign` then hands it the COSE structure instead of a digest, with the
same options and signature encoding `x509.CreateCertificate` uses.

The first action must be `c2pa.created` (nothing preceded this asset) or `c2pa.opened` (something
did) — c2pa-rs rejects a manifest without one. `Assertions` adds your own, each a CBOR-encodable
`Value` or raw `JSON` under any label the generated assertions do not reserve. Verify the result
with your own anchor:

```go
pool := x509.NewCertPool()
pool.AddCert(chain[len(chain)-1])
r := c2pa.Validate(ctx, c2pa.JPEG, signed, c2pa.WithSigningTrust(pool))
fmt.Println(r.Valid, r.VerifiedSigner()) // true "My Signer"
```

A self-signed test chain that satisfies the C2PA certificate profile (`digitalSignature`, a
constrained EKU, not a CA):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout signer.key -out signer.crt -subj "/CN=My Signer/O=Example" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=emailProtection" \
  -addext "basicConstraints=critical,CA:FALSE"
```

**What c2pa-rs says.** Every container's output is run through c2pa-rs's `c2patool` in CI
(`sign_interop_test.go`). With a private chain it reports `Valid` with `signingCredential.untrusted`
— correct, it has never seen your root; with `c2patool photo-signed.jpg trust --trust_anchors
signer.crt` it reports `Trusted`; a re-signed asset lists the previous manifest as a `parentOf`
ingredient with no failure deltas; a timestamped one reaches `timeStamp.trusted` once the TSA is
anchored.

**Timestamping** is opt-in. With a TSA configured, `Sign` timestamps the signature (RFC 3161) after
signing and embeds the token as `sigTst2`; the reply is verified with the same code `Validate` uses
— imprint, CMS signature, nonce echo — before it is embedded, and a TSA failure is `ErrTimestamp`
with nothing written. It is the one path that touches the network.

```go
signer, err := c2pa.NewSigner(key, chain,
    c2pa.WithTimestampAuthority("https://timestamp.digicert.com"),
    c2pa.WithTimestampHTTPClient(&http.Client{Timeout: 10 * time.Second}))
```

**Re-signing chains provenance.** An asset that already carries Content Credentials keeps them:
every prior manifest is carried into the new store verbatim and the previous active one becomes the
new manifest's `parentOf` ingredient, with its validation results recorded as c2pa-rs requires. Open
it with `ActionOpened`; `ActionCreated` on such an asset is `ErrManifestInvalid`, because a prior
manifest proves something preceded it. `ExampleSigner_Sign_resign` in
[`example_test.go`](example_test.go) does this to the ChatGPT PDF and verifies both signers.

**Limits.** Fragmented BMFF (`moof`/`sidx`) is refused with `ErrFragmentedBMFF` (authoring Merkle
trees per fragment is a separate project); encrypted (`/Encrypt`) or certified (`/Perms`) PDFs and
ID3v2.2 MP3 tags are refused; only standard `c2pa.claim.v2` manifests are written (no update
manifests); the store must fit in 64 MiB and the asset under `ValidateMaxScan`. Every existing
store is removed and the new one written at the container's canonical position — deterministic, and
a deliberate difference from c2pa-rs's replace-in-place.

| Key | COSE algorithm |
| --- | --- |
| ECDSA P-256 | ES256 |
| ECDSA P-384 | ES384 |
| ECDSA P-521 | ES512 |
| RSA ≥ 2048 bits | PS256 |
| Ed25519 | EdDSA |

## PDF

PDF is the container with the most to say, so it gets worked examples. All three run as
[`Example` functions](example_test.go) against `testdata/c2pa_chatgpt.pdf` — a real document from
ChatGPT's image pipeline whose signer chains to a production trust anchor — so the output below is
checked by `go test`, not written by hand.

### Read a PDF, and check what the manifest is about

A PDF can carry a manifest describing an image or font *inside* it rather than the document (§A.4.3).
That manifest's signer is not the document's, so `Attribution` is checked before `SignedBy` is
reported — skipping that check is how a file gets credited to whoever signed a picture inside it.

```go
info := c2pa.Read(ctx, c2pa.PDF, f)
if !info.Present {
    return // no Content Credentials
}
fmt.Println("generator:", info.ClaimGenerator)     // ChatGPT
fmt.Println("title:", info.Title)                  // image.pdf
fmt.Println("ai-generated:", info.AIGenerated)     // true

switch info.Attribution {
case c2pa.AttributionAsset:
    // The document's own structure associates this manifest.
    fmt.Println("signed by (claimed):", info.SignedBy)  // OpenAI Media Service
default:
    // A claim about something the document carries, or one nothing places.
    fmt.Println("manifest describes:", info.Attribution)
}
```

### Verify it

`VerifiedSigner()` is the proven identity — empty unless the claim signature verified **and** the
chain reached a trust anchor. `Info.SignedBy` is only what the file claims.

```go
r := c2pa.Validate(ctx, c2pa.PDF, f)
fmt.Println("valid:", r.Valid)                                        // true
fmt.Println("verified signer:", r.VerifiedSigner())                   // OpenAI Media Service
fmt.Println("content hash bound:", r.Has(c2pa.StatusAssertionDataHashMatch)) // true
// This document carries no RFC 3161 timestamp, so the signing time is
// unproven and r.SignedAt stays zero.
fmt.Println("trusted timestamp:", !r.Has(c2pa.StatusTimeStampMissing)) // false
```

### Enumerate every store the document carries

Only PDF returns more than one entry today: §A.4.1 embeds the document's own store as an associated
file, and §A.4.3 lets an object carry a manifest of its own, so a document and the image inside it
can both bear provenance. The first entry is exactly what `Read` returns.

```go
for i, info := range c2pa.ReadAll(ctx, c2pa.PDF, f) {
    fmt.Printf("%d: %s signed by %q (%s)\n",
        i, info.Attribution, info.SignedBy, info.ClaimGenerator)
}
// 0: asset signed by "OpenAI Media Service" (ChatGPT)
```

A signed attachment inside an unsigned document is the case this exists for: `Read` alone would
report the document as carrying no provenance, and `ReadAll` shows the attachment's — with
`AttributionEmbedded`, so it is never mistaken for the document's own.

## Lower-level

`c2pa.ReadAll(ctx, container, r)` enumerates every store an asset carries — the asset's own first,
then the object-level manifests an object associates with itself (`AttributionEmbedded`), such as a
signed image inside a PDF, then anything the C2PA markers find that nothing places
(`AttributionUnknown`). `Read` is the first entry's view.

`c2pa.ExtractStore(ctx, container, r)` returns the raw JUMBF manifest store exactly as it appears in
the file, and `c2pa.WalkBoxes(ctx, jumbf, fn)` walks its box tree. Together they reach assertions
`Read` doesn't model — the pair a manifest viewer wants. A nil store means none was found, not an
error. Box nesting is depth-capped so adversarial input can't exhaust the stack.

```go
store, err := c2pa.ExtractStore(ctx, c2pa.JPEG, file)
c2pa.WalkBoxes(ctx, store, func(label, tbox string, content []byte) {
    fmt.Printf("%s %s %d bytes\n", label, tbox, len(content))
})
```

## Requirements

- **Go 1.26+** (the floor is set by `golang.org/x/crypto`'s own minimum)
- Pure-Go dependencies only: [`fxamacker/cbor`](https://github.com/fxamacker/cbor) (CBOR),
  [`veraison/go-cose`](https://github.com/veraison/go-cose) (COSE_Sign1), and
  [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) (OCSP). No cgo.

## License

MIT — see [LICENSE](LICENSE). The test fixture under `testdata/` is from
[contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs) (see `testdata/README.md`). The
embedded trust lists under `trustlists/` are the official C2PA conformance lists (see
[`trustlists/README.md`](trustlists/README.md)).

---

Extracted from [file-search-on](https://github.com/richardwooding/file-search-on), where it powers
the `is_c2pa` / `c2pa_*` search attributes.
