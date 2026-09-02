# trustlists

The default C2PA trust anchors, embedded into the package via `go:embed` (see
`trust.go`) and used by `Validate` unless overridden with `WithSigningTrust` /
`WithTimestampTrust`.

- **C2PA-TRUST-LIST.pem** — root CA anchors authorized to issue C2PA *signing*
  certificates.
- **C2PA-TSA-TRUST-LIST.pem** — root CA anchors for the RFC 3161 *timestamp
  authorities* C2PA recognizes.

Both are the official conformance lists published at
[c2pa-org/conformance-public](https://github.com/c2pa-org/conformance-public/tree/main/trust-list).

Current snapshot: commit `43213566c9e5` (2026-09-01) — 30 signing anchors,
22 TSA anchors. The weekly `corpus.yml` workflow refetches the lists and fails
on drift, so a stale snapshot shows up as a red run rather than as
`signingCredential.untrusted` on files from newly certified signers.

These lists change over time as the C2PA program admits new authorities. They
are a point-in-time snapshot — refresh them periodically from the source above:

```sh
base=https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list
curl -fsSL "$base/C2PA-TRUST-LIST.pem"     -o trustlists/C2PA-TRUST-LIST.pem
curl -fsSL "$base/C2PA-TSA-TRUST-LIST.pem" -o trustlists/C2PA-TSA-TRUST-LIST.pem
```

Note: the `testdata/c2pa_signed.jpg` fixture is signed by the c2pa-rs *test* PKI,
which is intentionally **not** in these production lists — so it validates as
"untrusted signer" against the defaults. Tests anchor at the fixture's own chain.
