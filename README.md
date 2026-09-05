# c2pa

[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/c2pa.svg)](https://pkg.go.dev/github.com/richardwooding/c2pa)
[![CI](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/c2pa)](https://goreportcard.com/report/github.com/richardwooding/c2pa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Website:** [richardwooding.github.io/c2pa](https://richardwooding.github.io/c2pa/)

A small, **pure-Go** (no cgo) library for [C2PA / Content Credentials](https://c2pa.org)
provenance manifests embedded in **JPEG**, **PNG**, **BMFF** (MP4, MOV, HEIC, HEIF, AVIF),
**RIFF** (WebP, WAV, AVI), **TIFF** (and DNG), **GIF**, **MP3**, **SVG** and **PDF** files, with two modes:

- **`Read`** — a fast, *unverified* reader. Surfaces what a file *claims* (creating tool, title,
  format, AI-generated flag, signer identity, signing time) like EXIF or an email `From:` header.
- **`Validate`** — a full, opt-in *verifier*. Checks the COSE signature, the certificate chain
  against the C2PA trust list, assertion and hard-binding hashes, the RFC 3161 timestamp,
  revocation, and ingredients — reporting C2PA status codes. Pure Go, no `c2pa-rs`/CGO.

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
| `Attribution` | `AttributionAsset` when the asset's own structure associates the manifest; `AttributionEmbedded` when the asset associates it with a resource it CARRIES rather than with itself (PDF §A.4.3); `AttributionUnknown` when only the C2PA markers identified it and nothing places it. For the last two, **do not report its signer as the asset's** |
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
- **Merkle BMFF** — a `c2pa.hash.bmff.v3` `merkle` array is verified as far as a single reader can
  settle it. A non-fragmented asset whose `mdat` is hashed piecewise is checked in full: the leaves
  are cut from the box, the tree rebuilt, and the row the assertion stores compared against it. For a
  fragmented asset the initialization hash is checked, and what needs the other chunk files is named
  rather than folded into a success — a wrong initialization hash is still a mismatch, since this
  file disproves it.
- **RFC 3161 timestamp** — full CMS signature verification, the TSA chain, and that the timestamp
  covers this signature.
- **Revocation** — OCSP/CRL, opt-in (off by default), soft-fail.
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

- **Go 1.25+** (the floor is set by `golang.org/x/crypto`'s own minimum)
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
