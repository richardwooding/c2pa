# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/richardwooding/c2pa` is a flat (single Go package, no subpackages) **pure-Go** library
for C2PA / Content Credentials provenance manifests in JPEG, PNG, and BMFF (MP4/MOV/HEIC/HEIF/
AVIF), with **two modes**:

- **`Read(ctx, container, r) Info`** — the fast, *unverified* reader. Surfaces what a file CLAIMS
  (generator, title, signer CN, signing time, AI flag) like EXIF or an unverified `From:` header. It
  never fails, never does crypto, and is tuned for triage/indexing. Lives in `c2pa.go`, unchanged.
- **`Validate(ctx, container, r, opts...) ValidationResult`** — the full, opt-in *verifier*. Checks
  the COSE signature, the certificate chain + C2PA cert profile against the trust list, assertion and
  hard-binding hashes, the RFC 3161 timestamp, revocation, and ingredients — reporting C2PA §15 status
  codes. Pure Go, no cgo.

The package stays one `package c2pa` but is split across topic files (`validate.go`, `boxes.go`,
`cose_verify.go`, `chain.go`, `trust.go`, `hashbinding.go`, `timestamp.go`, `revocation.go`,
`ingredient.go`, `statuscodes.go`) — flat *import surface*, not one file. Don't introduce subpackages;
that would force exporting internal helpers.

Public surface:

- `Read` / `Info` — fields Present, ClaimGenerator, Title, Format, AIGenerated, SoftwareAgent,
  SignedBy, SignedAt.
- `Validate` / `ValidationResult` / `StatusEntry` / `StatusCode` / `Severity` — the verifier and its
  result. `ValidateOption` (`WithSigningTrust`, `WithTimestampTrust`, `WithOnlineRevocation`,
  `WithClock`, `WithMaxIngredientDepth`, `WithMaxScan`, `WithHTTPClient`).
- `WalkBoxes(ctx, jumbf, fn)` — lower-level JUMBF box-tree walker.
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

CI (`.github/workflows/ci.yml`) runs build + vet + race tests on Go `1.25` and `stable` plus
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

Don't entangle the paths: `Read` uses `parseManifest`; `Validate` uses `parseStore` (in `boxes.go`,
which additionally keeps raw box bytes + offsets that hashing needs). `Read`'s contract, tests, and
fuzz targets stay untouched.

## Things to know before editing

- **Go 1.25 is the floor**, set by `golang.org/x/crypto`'s own `go` directive (pulled in for OCSP).
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
  Hash assertions over `rawAssertion.full` (the whole superbox) for `hashed_uri`; sub-slice, never
  re-encode. BMFF hard bindings (`c2pa.hash.bmff.v2`/`.v3`) ARE verified (`bmffhash.go`): a single
  ascending pass where each top-level box not wholly excluded contributes its absolute offset as an
  8-byte big-endian integer followed by its bytes minus exclusion ranges. v1 `c2pa.hash.bmff` must be
  IGNORED per spec §18.6.1 (v1-only manifests → `hardBinding.missing`); `merkle`/fragmented assets →
  informational unsupported; a BMFF binding on a non-BMFF container → `hardBinding.missing` (not
  informational — see verifyHardBinding). Assertion CBOR encodes absent exclusion fields as explicit
  nulls — every optional-field decode must be nil-tolerant. The standard `/uuid` exclusion relies on
  its `data` predicate (offset 8 == the C2PA usertype) to exclude only the C2PA box. Exclusion `flags`
  with `exact=false` use spec bits-set semantics — deliberately NOT c2pa-rs's inverted subset test.
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
no public AI-positive fixture. `example_test.go` holds the runnable godoc `Example` — keep it passing,
it doubles as documentation. The `Fuzz*` targets cover the read pipeline, the recursive box walker,
the ASN.1 timestamp descent, the offset-aware `parseStore`/`parseBoxTree`, the full `Validate`
pipeline, the CMS timestamp verifier, and the exclusion-range hashing; their seed corpora run as
normal tests in CI.

**Validation tests are self-contained.** The fixture's signer chain (leaf + intermediate) is in its
own COSE x5chain, so positive tests anchor a test pool at the fixture's own intermediate via
`WithSigningTrust` rather than shipping the c2pa-rs test root. Failure paths are synthesised by byte
-mutating the fixture (flip image data → `dataHash.mismatch`; flip an assertion → `hashedURI.mismatch`;
corrupt the COSE signature → `claimSignature.mismatch`; empty trust pool → `signingCredential.untrusted`)
and by generating ephemeral certs in-test — no new binary fixtures.

**There is also a generated corpus** (`corpus_gen_test.go`, `corpus_container_test.go`,
`corpus_test.go`, `corpus_tsa_test.go`, `corpus_timestamp_test.go`, `corpus_fuzz_test.go`) that
builds valid C2PA assets from scratch — JUMBF superbox/`jumd` writer, assertion store, 1.x and 2.x
claims, COSE_Sign1, JPEG APP11 / PNG caBX framing, and a hand-rolled RFC 3161 / CMS token writer —
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

Four status codes are declared but have no emission site: `claim.multiple`,
`timeStamp.outsideValidity`, and `assertion.boxesHash.match`/`.mismatch` (the last two dead by
design while `c2pa.hash.boxes` reports `general.unsupported`). Don't write corpus cases for them
expecting a result — they need a library change first.
