# c2pa

[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/c2pa.svg)](https://pkg.go.dev/github.com/richardwooding/c2pa)
[![CI](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml/badge.svg)](https://github.com/richardwooding/c2pa/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/richardwooding/c2pa)](https://goreportcard.com/report/github.com/richardwooding/c2pa)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Website:** [richardwooding.github.io/c2pa](https://richardwooding.github.io/c2pa/)

A small, **pure-Go** (no cgo) library for [C2PA / Content Credentials](https://c2pa.org)
provenance manifests embedded in **JPEG** and **PNG** files, with two modes:

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

info := c2pa.Read(context.Background(), c2pa.JPEG, f) // or c2pa.PNG
if !info.Present {
    return // no Content Credentials embedded
}

fmt.Println(info.ClaimGenerator) // e.g. "Adobe Firefly"
fmt.Println(info.Title)          // claim dc:title
fmt.Println(info.Format)         // claim dc:format
fmt.Println(info.AIGenerated)    // declared AI-generated?
fmt.Println(info.SignedBy)       // CLAIMED signer cert CN (unverified)
fmt.Println(info.SignedAt)       // RFC 3161 signing time (unverified)
```

`Read` is best-effort and never returns an error: a missing or malformed manifest yields
`Info{Present: false}`. It reads at most `c2pa.MaxScan` (16 MiB) from the reader and honours the
context — a cancelled call surrenders promptly mid-scan.

| `Info` field | Meaning |
|---|---|
| `Present` | a C2PA manifest was found and parsed |
| `ClaimGenerator` | the tool that created/edited the asset |
| `Title` | claim `dc:title` |
| `Format` | claim `dc:format` (declared media type) |
| `AIGenerated` | a `c2pa.actions` `digitalSourceType` declares `trainedAlgorithmicMedia` / `compositeWithTrainedAlgorithmicMedia` |
| `SignedBy` | COSE signer leaf-cert common name — **unverified** |
| `SignedAt` | RFC 3161 signing time — **unverified** |

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
- **Hash bindings** — the hard-binding `c2pa.hash.data` (the asset content hash) and each
  assertion's `hashed_uri`.
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

`c2pa.WalkBoxes(ctx, jumbf, fn)` exposes the JUMBF box-tree walker for callers that want to surface
assertions `Read` doesn't model. Box nesting is depth-capped so adversarial input can't exhaust the
stack.

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
