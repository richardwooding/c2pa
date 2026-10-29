package c2pa

import (
	"crypto/subtle"
)

// Multi-asset hash (§18.9): c2pa.hash.multi-asset describes a file made of
// several concatenated assets (a multipart JPEG, say), each part under its own
// hash assertion, some of which may be optional and dropped in transit. The
// status codes live in statuscodes.go.

// verifyMultiAssetHash evaluates a c2pa.hash.multi-asset assertion against the
// asset. It is consulted only when the manifest's whole-asset data hash did not
// hold: an asset that arrived intact is bound by that hash and needs no part
// accounting, while one that lost optional parts still verifies through the
// parts that remain.
//
// Parts must tile the asset from offset 0 with no gap or overlap (anything else
// is malformed). A part wholly beyond the end of the asset is absent: fine if
// optional, assertion.multiAssetHash.missingPart if required. A part cut short,
// or whose bytes do not hash to its data-hash assertion, is a mismatch, as is
// data left over after the last part that is present.
//
// It reports whether the parts were evaluated at all. §18.9.2 also allows a
// bmffBox locator and a boxes- or BMFF-hash part assertion; those shapes are
// not evaluated here and are reported as informational general.unsupported, in
// which case the caller keeps the whole-asset mismatch that led it here rather
// than manufacturing a verdict from a shape it did not check.
func (v *validator) verifyMultiAssetHash(m *parsedManifest, a *rawAssertion, uri string) (evaluated bool) {
	subj := uri + "/c2pa.hash.multi-asset"
	var assertion map[string]any
	if decMode.Unmarshal(a.data, &assertion) != nil {
		v.add(StatusMultiAssetHashMalformed, subj, "multi-asset hash assertion did not decode", nil)
		return true
	}
	parts, _ := assertion["parts"].([]any)
	if len(parts) == 0 {
		v.add(StatusMultiAssetHashMalformed, subj, "multi-asset hash has no parts", nil)
		return true
	}
	byLabel := make(map[string]rawAssertion, len(m.assertions))
	for _, ra := range m.assertions {
		byLabel[ra.label] = ra
	}
	defaultAlg, _ := m.claim["alg"].(string)

	size := len(v.data)
	next := 0    // where the previous part ended
	covered := 0 // end of the last part present in the asset
	problem := false
	for _, p := range parts {
		pm, _ := p.(map[string]any)
		loc, _ := pm["location"].(map[string]any)
		if _, isBox := loc["bmffBox"]; isBox {
			v.add(StatusUnsupported, subj,
				"multi-asset hash part located by bmffBox is not evaluated", nil)
			return false
		}
		off, okOff := toInt(loc["byteOffset"])
		length, okLen := toInt(loc["length"])
		if !okOff || !okLen || length <= 0 || off != next {
			v.add(StatusMultiAssetHashMalformed, subj,
				"multi-asset hash parts do not tile the asset without gap or overlap", nil)
			return true
		}
		next = off + length
		optional, _ := pm["optional"].(bool)

		if off >= size {
			if !optional {
				v.add(StatusMultiAssetHashMissingPart, subj, "required part is absent from the asset", nil)
				problem = true
			}
			continue
		}
		if next > size {
			v.add(StatusMultiAssetHashMismatch, subj, "part is cut short", nil)
			problem = true
			continue
		}
		covered = next

		ref, _ := pm["hashAssertion"].(map[string]any)
		url, _ := ref["url"].(string)
		want, _ := ref["hash"].([]byte)
		pa, ok := byLabel[assertionLabelFromURL(url)]
		if !ok {
			v.add(StatusMultiAssetHashMalformed, subj, "part names a hash assertion that is not in the manifest", nil)
			return true
		}
		if assertionLabelBase(pa.label) != "c2pa.hash.data.part" {
			v.add(StatusUnsupported, subj,
				"multi-asset hash part bound by "+pa.label+" is not evaluated (only c2pa.hash.data.part is)", nil)
			return false
		}
		// The part's assertion is itself covered by the multi-asset assertion's
		// hashed URI.
		alg, _ := ref["alg"].(string)
		if alg == "" {
			alg = defaultAlg
		}
		if h, ok := hashByName(alg); ok && len(want) > 0 {
			if hashWrite(v.ctx, h, pa.boxContent) != nil {
				v.cancelled(subj, "while hashing a part's assertion")
				return true
			}
			if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
				v.add(StatusMultiAssetHashMismatch, subj, "part's data-hash assertion does not match its hashed URI", nil)
				problem = true
				continue
			}
		}
		switch ok, err := v.partHashMatches(pa, v.data[off:next]); {
		case err != nil:
			v.cancelled(subj, "while hashing a part")
			return true
		case !ok:
			v.add(StatusMultiAssetHashMismatch, subj, "part content does not match its data hash", nil)
			problem = true
		}
	}
	if covered != size {
		v.add(StatusMultiAssetHashMismatch, subj, "asset has data beyond its last present part", nil)
		return true
	}
	if !problem {
		v.add(StatusMultiAssetHashMatch, subj, "multi-asset hash matches the parts present", nil)
	}
	return true
}

// partHashMatches checks one part's bytes against its c2pa.hash.data.part
// assertion (alg, hash and exclusions relative to the part). A non-nil error is
// the context's: nothing was compared, and the caller must not call it a
// mismatch.
func (v *validator) partHashMatches(a rawAssertion, part []byte) (bool, error) {
	var d map[string]any
	if decMode.Unmarshal(a.data, &d) != nil {
		return false, nil
	}
	want, _ := d["hash"].([]byte)
	h, ok := hashByName(stringOr(d["alg"], ""))
	if !ok || len(want) == 0 {
		return false, nil
	}
	raw, ok := decodeExclusions(d["exclusions"], len(part))
	if !ok {
		return false, nil
	}
	if err := hashWithExclusions(v.ctx, part, h, mergeRanges(raw)); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(h.Sum(nil), want) == 1, nil
}
