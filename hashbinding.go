package c2pa

import (
	"context"
	"crypto"
	"crypto/subtle"
	"hash"
	"slices"
	"sort"
	"strings"
)

// verifyAssertionHashes checks each assertion referenced by the claim against
// the bytes of the matching assertion box: the claim's assertions[] entries
// carry a SHA hash that must equal the hash of the assertion superbox's content
// (rawAssertion.boxContent). This is what binds the signed claim to the actual
// assertions present in the manifest. A referenced assertion that is absent is
// a failure; a hash mismatch is a failure.
func (v *validator) verifyAssertionHashes(m *parsedManifest, uri string) {
	entries := claimAssertionEntries(m.claim)
	if len(entries) == 0 {
		return
	}
	byLabel := make(map[string]rawAssertion, len(m.assertions))
	for _, a := range m.assertions {
		byLabel[a.label] = a
	}
	defaultAlg, _ := m.claim["alg"].(string)
	for _, e := range entries {
		if v.cancelled(uri, "while checking assertion hashes") {
			return
		}
		label := assertionLabelFromURL(e.url)
		a, ok := byLabel[label]
		if !ok {
			v.add(StatusAssertionMissing, e.url, "claim references an assertion not present in the store", nil)
			continue
		}
		algName := e.alg
		if algName == "" {
			algName = defaultAlg
		}
		h, ok := hashByName(algName)
		if !ok {
			v.add(StatusAlgorithmUnsupported, e.url, "unsupported assertion hash algorithm", nil)
			continue
		}
		if hashWrite(v.ctx, h, a.boxContent) != nil {
			v.cancelled(e.url, "while hashing an assertion") // a truncated digest is not a mismatch
			return
		}
		if subtle.ConstantTimeCompare(h.Sum(nil), e.hash) == 1 {
			v.add(StatusAssertionHashedURIMatch, e.url, "assertion hash matches", nil)
		} else {
			v.add(StatusAssertionHashedURIMismatch, e.url, "assertion hash does not match", nil)
		}
	}
}

// verifyHardBinding checks the manifest's hard-binding assertion, which proves
// the asset content has not changed since signing. For every container except
// BMFF this is c2pa.hash.data (a SHA over the whole file minus declared exclusion ranges
// that cover the manifest itself); for BMFF assets it is c2pa.hash.bmff.v2/.v3
// (verified by verifyBMFFHash); a structural c2pa.hash.boxes is verified by
// verifyBoxesHash for the containers whose box naming C2PA defines. A v1
// c2pa.hash.bmff assertion is ignored per spec §18.6.1 and a BMFF binding on a
// non-BMFF asset cannot bind it. Absence of any usable hard binding is a
// failure.
//
// When a manifest carries more than one of these, the container-specific
// binding wins: only one is the asset's real hard binding, and hashing bytes
// against the wrong model produces a mismatch rather than a verdict.
func (v *validator) verifyHardBinding(m *parsedManifest, uri string) {
	// An object-level manifest (§A.4.3) is attached to the image, font or other
	// stream whose provenance it records, so its hard binding covers THAT
	// object's bytes. Hashing the carrier's bytes against it would manufacture
	// a mismatch out of asking the wrong question — the binding is not absent,
	// it is over a subject this extractor does not yet isolate.
	if v.attribution == AttributionEmbedded {
		v.add(StatusUnsupported, uri, "manifest records an embedded object's provenance "+
			"(§A.4.3); its hard binding covers that object's bytes, which are not evaluated", nil)
		v.bind(BindingUnevaluated)
		return
	}
	var dataHash, bmffHash, boxesHash *rawAssertion
	bmffV1 := false
	for i := range m.assertions {
		switch m.assertions[i].label {
		case "c2pa.hash.data":
			dataHash = &m.assertions[i]
		case "c2pa.hash.bmff": // v1: validators must ignore it entirely
			bmffV1 = true
		case "c2pa.hash.bmff.v2", "c2pa.hash.bmff.v3":
			bmffHash = &m.assertions[i]
		case "c2pa.hash.boxes":
			boxesHash = &m.assertions[i]
		}
	}
	if v.fragments != nil && bmffHash == nil {
		// Only a BMFF merkle binding reaches bytes in other files; a
		// c2pa.hash.data over the initialization segment would "match" while
		// leaving every fragment unbound.
		v.add(StatusHardBindingMissing, uri,
			"no c2pa.hash.bmff.v2/.v3 assertion binds the supplied fragments", nil)
		v.bind(BindingNone)
		return
	}
	start := len(v.res.Statuses)
	switch {
	case bmffHash != nil && v.container == BMFF:
		v.verifyBMFFHash(bmffHash, uri)
		v.bindFromStep(start, StatusAssertionBMFFHashMatch)
	case dataHash != nil:
		v.verifyDataHash(dataHash, uri)
		v.bindFromStep(start, StatusAssertionDataHashMatch)
	case bmffHash != nil:
		// A BMFF binding cannot bind a non-BMFF asset: treating it as merely
		// "unsupported" would let a bmff-only manifest wrapped around, say,
		// tampered JPEG bytes validate with no hard binding checked at all.
		v.add(StatusHardBindingMissing, uri+"/"+bmffHash.label,
			"BMFF hard binding cannot bind a non-BMFF asset", nil)
		v.bind(BindingNone)
	case boxesHash != nil:
		defaultAlg, _ := m.claim["alg"].(string)
		v.verifyBoxesHash(boxesHash, uri, defaultAlg)
		v.bindFromStep(start, StatusAssertionBoxesHashMatch)
	case bmffV1:
		v.add(StatusHardBindingMissing, uri,
			"manifest's only hard binding is a v1 c2pa.hash.bmff assertion, which validators must ignore", nil)
		v.bind(BindingNone)
	default:
		// A soft binding is worth naming here, because §9.1 forbids it as the
		// SOLE content binding — but the failure is the hard binding's absence,
		// which is already this status. There is deliberately no
		// soft-binding-flavoured code for it: that would double-report one
		// condition, and any check phrased "a soft binding without a hard
		// binding is a failure" would fail every correctly formed UPDATE
		// manifest (§11.2.3 forbids those a hard binding), which is why this
		// only extends the explanation.
		explain := "manifest has no hard-binding hash assertion"
		if hasSoftBinding(m) {
			explain += "; its only content binding is a soft binding, which §9.1 forbids as the sole binding"
		}
		v.add(StatusHardBindingMissing, uri, explain, nil)
		v.bind(BindingNone)
	}
}

// verifyDataHash verifies a c2pa.hash.data assertion against the asset bytes.
func (v *validator) verifyDataHash(a *rawAssertion, uri string) {
	subj := uri + "/c2pa.hash.data"
	var assertion map[string]any
	if decMode.Unmarshal(a.data, &assertion) != nil {
		v.add(StatusAssertionDataHashMismatch, subj, "data-hash assertion did not decode", nil)
		return
	}
	want, _ := assertion["hash"].([]byte)
	if len(want) == 0 {
		v.add(StatusAssertionDataHashMismatch, subj, "data-hash assertion has no hash", nil)
		return
	}
	h, ok := hashByName(stringOr(assertion["alg"], ""))
	if !ok {
		v.add(StatusAlgorithmUnsupported, subj, "unsupported data-hash algorithm", nil)
		return
	}

	raw, ok := decodeExclusions(assertion["exclusions"], len(v.data))
	if !ok {
		v.add(StatusAssertionDataHashMismatch, subj, "data-hash exclusion out of range", nil)
		return
	}
	// §15.12.1.1: when an update manifest was encountered, the store grew after
	// this manifest was signed, so the exclusion that starts where the store
	// starts is treated as the store's CURRENT length and later exclusions
	// shift by the difference. The container says where the store sits and
	// how much framing a writer excludes with it; the adjusted ranges are
	// bounds-checked again because the shift is derived, not declared.
	explain := "asset data hash matches"
	if v.updateSeen {
		if adjusted, changed := adjustExclusionsForUpdate(raw, storeRanges(v.ctx, v.container, v.data)); changed {
			if !rangesInBounds(adjusted, len(v.data)) {
				v.add(StatusAssertionDataHashMismatch, subj,
					"data-hash exclusion adjusted for the update manifest falls outside the asset", nil)
				return
			}
			raw = adjusted
			explain += " (exclusion extended to the manifest store's current length, §15.12.1.1)"
		}
	}
	ranges := mergeRanges(raw)
	// MaxScan truncation: if the asset filled the scan cap it may have been cut
	// short, so the data hash cannot be computed reliably. Report informationally
	// — never a false mismatch.
	if len(v.data) >= v.cfg.maxScan {
		v.add(StatusUnsupported, subj, "asset reached the scan cap; data hash not verified", nil)
		return
	}

	if hashWithExclusions(v.ctx, v.data, h, ranges) != nil {
		v.cancelled(subj, "while hashing the asset") // a truncated digest is not a mismatch
		return
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want) == 1 {
		v.add(StatusAssertionDataHashMatch, subj, explain, nil)
	} else {
		v.add(StatusAssertionDataHashMismatch, subj, "asset data hash does not match", nil)
	}
}

// adjustExclusionsForUpdate applies spec §15.12.1.1 to the exclusions a
// standard manifest recorded: "if any update manifests were encountered then
// the length value of the exclusion range whose start value is the offset of
// the start of the entire C2PA Manifest Store shall be treated as the current
// length of the entire C2PA Manifest Store plus any file format specific
// extras", with every exclusion that starts after it shifted by the growth.
//
// An update manifest is appended to the store AFTER the standard manifest
// signed it, so the exclusion that manifest recorded describes the store as it
// was, not as it is — c2pa-rs's update_manifest.jpg records {9964, 18874} over
// a run that now spans {9964, 43607}, and hashing with the stale range is a
// false assertion.dataHash.mismatch (issue #72). current is what the container
// says a writer would exclude for the store as it sits now (storeRanges), so a
// recorded exclusion is matched to it by start, as c2pa-rs does. Only growth
// is applied: a store that did not grow needs no adjustment, and one that
// shrank is not what an update leaves behind, so the recorded ranges stand and
// the hash decides. The result is a copy; changed says whether anything moved.
func adjustExclusionsForUpdate(recorded, current []byteRange) (out []byteRange, changed bool) {
	out = append([]byteRange(nil), recorded...)
	for _, s := range current {
		i := slices.IndexFunc(out, func(r byteRange) bool { return r.start == s.start })
		if i < 0 || s.length <= out[i].length {
			continue
		}
		delta := s.length - out[i].length
		out[i].length = s.length
		for j := range out {
			if j != i && out[j].start > s.start {
				out[j].start += delta
			}
		}
		changed = true
	}
	return out, changed
}

// rangesInBounds reports whether every range lies within an n-byte asset.
func rangesInBounds(rs []byteRange, n int) bool {
	for _, r := range rs {
		if r.start < 0 || r.length < 0 || r.start > n || r.length > n-r.start {
			return false
		}
	}
	return true
}

// byteRange is a [start, start+length) exclusion in the asset.
type byteRange struct{ start, length int }

// exclusionRanges decodes and validates a c2pa.hash.data exclusions array into
// sorted, merged, in-bounds ranges. It returns ok=false if any range is out of
// range or numerically invalid (an indication of a malformed/forged assertion).
func exclusionRanges(v any, n int) ([]byteRange, bool) {
	raw, ok := decodeExclusions(v, n)
	if !ok {
		return nil, false
	}
	return mergeRanges(raw), true
}

// decodeExclusions decodes a c2pa.hash.data exclusions array into in-bounds
// ranges in the order and shape the assertion gives them — unsorted and
// unmerged, which is what the §15.12.1.1 adjustment needs to match an entry
// by its start. ok=false means a range is out of range or numerically invalid.
func decodeExclusions(v any, n int) ([]byteRange, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, true // no exclusions: hash the whole asset
	}
	out := make([]byteRange, 0, len(list))
	for _, e := range list {
		em, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		start, sok := toInt(em["start"])
		length, lok := toInt(em["length"])
		if !sok || !lok || start < 0 || length < 0 || start > n || length > n-start {
			return nil, false
		}
		out = append(out, byteRange{start, length})
	}
	return out, true
}

// mergeRanges sorts ranges by start and merges overlapping/adjacent ones so the
// hashing walk never produces a negative-length gap.
func mergeRanges(rs []byteRange) []byteRange {
	sort.Slice(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
	out := rs[:0:0]
	for _, r := range rs {
		if len(out) > 0 {
			last := &out[len(out)-1]
			lastEnd := last.start + last.length
			if r.start <= lastEnd {
				if end := r.start + r.length; end > lastEnd {
					last.length = end - last.start
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// hashWithExclusions writes the asset to h, skipping the (sorted, merged,
// in-bounds) excluded ranges. It returns the context's error when cancelled
// mid-way, and h is then not to be compared with anything.
func hashWithExclusions(ctx context.Context, data []byte, h hash.Hash, ranges []byteRange) error {
	cur := 0
	for _, r := range ranges {
		if r.start > cur {
			if err := hashWrite(ctx, h, data[cur:r.start]); err != nil {
				return err
			}
		}
		if end := r.start + r.length; end > cur {
			cur = end
		}
	}
	if cur < len(data) {
		return hashWrite(ctx, h, data[cur:])
	}
	return ctx.Err()
}

// claimAssertionEntry is one entry of the claim's assertions[] array.
type claimAssertionEntry struct {
	url  string
	hash []byte
	alg  string
}

// claimAssertionEntries pulls the assertions[] (and, for v2 claims,
// created_assertions / gathered_assertions) entries from a decoded claim.
func claimAssertionEntries(claim map[string]any) []claimAssertionEntry {
	var out []claimAssertionEntry
	for _, key := range []string{"assertions", "created_assertions", "gathered_assertions"} {
		list, ok := claim[key].([]any)
		if !ok {
			continue
		}
		for _, e := range list {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			url, _ := em["url"].(string)
			hsh, _ := em["hash"].([]byte)
			if url == "" || len(hsh) == 0 {
				continue
			}
			out = append(out, claimAssertionEntry{url: url, hash: hsh, alg: stringOr(em["alg"], "")})
		}
	}
	return out
}

// assertionLabelFromURL extracts the assertion label from a JUMBF URI such as
// "self#jumbf=c2pa.assertions/c2pa.actions" → "c2pa.actions".
func assertionLabelFromURL(url string) string {
	if i := strings.LastIndex(url, "/"); i >= 0 {
		return url[i+1:]
	}
	return url
}

// hashByName maps a C2PA algorithm name to a hash.Hash. SHA-1/MD5 are refused.
func hashByName(name string) (hash.Hash, bool) {
	switch strings.ToLower(name) {
	case "sha256":
		return crypto.SHA256.New(), true
	case "sha384":
		return crypto.SHA384.New(), true
	case "sha512":
		return crypto.SHA512.New(), true
	}
	return nil, false
}

// toInt coerces a CBOR-decoded integer (uint64/int64/int/float64) to int.
func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case uint64:
		return int(x), true
	case int64:
		return int(x), true
	case int:
		return x, true
	case float64:
		return int(x), true
	}
	return 0, false
}

func stringOr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}
