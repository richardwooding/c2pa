package c2pa

import (
	"crypto"
	"crypto/subtle"
	"hash"
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
		h.Write(a.boxContent)
		if subtle.ConstantTimeCompare(h.Sum(nil), e.hash) == 1 {
			v.add(StatusAssertionHashedURIMatch, e.url, "assertion hash matches", nil)
		} else {
			v.add(StatusAssertionHashedURIMismatch, e.url, "assertion hash does not match", nil)
		}
	}
}

// verifyHardBinding checks the manifest's hard-binding assertion, which proves
// the asset content has not changed since signing. For JPEG/PNG this is
// c2pa.hash.data (a SHA over the whole file minus declared exclusion ranges
// that cover the manifest itself); for BMFF assets it is c2pa.hash.bmff.v2/.v3
// (verified by verifyBMFFHash). A v1 c2pa.hash.bmff assertion is ignored per
// spec §18.6.1; a BMFF binding on a non-BMFF asset cannot bind it; and
// c2pa.hash.boxes remains unsupported. Absence of any usable hard binding is a
// failure.
func (v *validator) verifyHardBinding(m *parsedManifest, uri string) {
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
	switch {
	case bmffHash != nil && v.container == BMFF:
		v.verifyBMFFHash(bmffHash, uri)
	case dataHash != nil:
		v.verifyDataHash(dataHash, uri)
	case bmffHash != nil:
		// A BMFF binding cannot bind a non-BMFF asset: treating it as merely
		// "unsupported" would let a bmff-only manifest wrapped around, say,
		// tampered JPEG bytes validate with no hard binding checked at all.
		v.add(StatusHardBindingMissing, uri+"/"+bmffHash.label,
			"BMFF hard binding cannot bind a non-BMFF asset", nil)
	case boxesHash != nil:
		v.add(StatusUnsupported, uri+"/"+boxesHash.label,
			"c2pa.hash.boxes hard-binding hashing is not supported", nil)
	case bmffV1:
		v.add(StatusHardBindingMissing, uri,
			"manifest's only hard binding is a v1 c2pa.hash.bmff assertion, which validators must ignore", nil)
	default:
		v.add(StatusHardBindingMissing, uri, "manifest has no hard-binding hash assertion", nil)
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

	ranges, ok := exclusionRanges(assertion["exclusions"], len(v.data))
	if !ok {
		v.add(StatusAssertionDataHashMismatch, subj, "data-hash exclusion out of range", nil)
		return
	}
	// MaxScan truncation: if the asset filled the scan cap it may have been cut
	// short, so the data hash cannot be computed reliably. Report informationally
	// — never a false mismatch.
	if len(v.data) >= v.cfg.maxScan {
		v.add(StatusUnsupported, subj, "asset reached the scan cap; data hash not verified", nil)
		return
	}

	hashWithExclusions(v.data, h, ranges)
	if subtle.ConstantTimeCompare(h.Sum(nil), want) == 1 {
		v.add(StatusAssertionDataHashMatch, subj, "asset data hash matches", nil)
	} else {
		v.add(StatusAssertionDataHashMismatch, subj, "asset data hash does not match", nil)
	}
}

// byteRange is a [start, start+length) exclusion in the asset.
type byteRange struct{ start, length int }

// exclusionRanges decodes and validates a c2pa.hash.data exclusions array into
// sorted, merged, in-bounds ranges. It returns ok=false if any range is out of
// range or numerically invalid (an indication of a malformed/forged assertion).
func exclusionRanges(v any, n int) ([]byteRange, bool) {
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
	return mergeRanges(out), true
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
// in-bounds) excluded ranges.
func hashWithExclusions(data []byte, h hash.Hash, ranges []byteRange) {
	cur := 0
	for _, r := range ranges {
		if r.start > cur {
			h.Write(data[cur:r.start])
		}
		if end := r.start + r.length; end > cur {
			cur = end
		}
	}
	if cur < len(data) {
		h.Write(data[cur:])
	}
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
