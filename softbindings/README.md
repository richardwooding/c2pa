# softbindings

The C2PA **soft binding algorithm list** — the authoritative set of algorithm identifiers a
`c2pa.soft-binding` assertion's `alg` field may name (spec §9.3.2) — embedded into the package via
`go:embed` (see `softbindingalgs.go`).

`Validate` reads it for one purpose: to tell **"a registered algorithm we cannot compute"** from
**"an identifier nobody registered"**. The library implements no soft binding algorithm, so it reports
either way; the list is what lets the report say which.

Published at
[c2pa-org/softbinding-algorithm-list](https://github.com/c2pa-org/softbinding-algorithm-list).

Current snapshot: commit `a9d9699097785b6ffa8e46cefba21f366308fa06` (2026-08-20) — **53 entries, 44
watermark, 9 fingerprint**. Those counts are asserted by `TestSoftBindingRegistry`, so a botched
refresh is a red test rather than a silent change of verdict. The weekly `corpus.yml` workflow refetches
the list and fails on drift.

Refresh from the source:

```sh
curl -fsSL https://raw.githubusercontent.com/c2pa-org/softbinding-algorithm-list/main/softbinding-algorithm-list.json \
  -o softbindings/softbinding-algorithm-list.json
```

…then update the snapshot line and the counts above, and the counts in `TestSoftBindingRegistry`.

## Staleness matters less here than it does for the trust lists — deliberately

This is a point-in-time copy, so `SoftBinding.AlgorithmRegistered == false` means *"not in **this**
snapshot"*, which may mean "registered upstream since we last refreshed" as much as "registered by
nobody". Anyone may submit an algorithm by pull request upstream, so the list grows.

That is exactly why an unlisted algorithm is reported **informationally**
(`softBinding.alg.unlisted`) and never as a failure, even though §9.3.2 requires a listed one. The
spec's own worked example uses `"alg": "phash"`, which is not in the list — failing on that basis
would fail correct files. Compare the trust lists, where staleness surfaces as a spec-mandated
`signingCredential.untrusted` **failure** and the drift check is the only mitigation: here staleness
degrades a *field*, not a *verdict*.

The asymmetry that follows, and it is intentional: the **writer** refuses an algorithm this snapshot
does not name, while the **reader** only notes it. Strict in what we emit, liberal in what we accept.

## What is parsed

`identifier`, `alg`, `type`, `decodedMediaTypes`, `encodedMediaTypes`,
`softBindingResolutionApis`, and `entryMetadata.description` / `.dateEntered`. Note the two
media-type keys carry two different vocabularies — `decodedMediaTypes` holds bare families
(`image`, `audio`, …) and `encodedMediaTypes` holds full media types (`audio/mpeg`, …), with seven
entries carrying both.

`entryMetadata.contact` is deliberately **not** parsed or exported: it is a personal name or email
address with no validation use, and the file is in the repository for anyone who wants the rest.
