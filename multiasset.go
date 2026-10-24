package c2pa

import (
	"crypto/subtle"
)

// Multi-asset hash status codes (§9.3): c2pa.hash.multi-asset binds a file made
// of several concatenated assets (a multipart JPEG, say), each part under its
// own data-hash assertion, some of which may be optional and dropped in transit.
const (
	StatusMultiAssetHashMatch       StatusCode = "assertion.multiAssetHash.match"
	StatusMultiAssetHashMismatch    StatusCode = "assertion.multiAssetHash.mismatch"
	StatusMultiAssetHashMalformed   StatusCode = "assertion.multiAssetHash.malformed"
	StatusMultiAssetHashMissingPart StatusCode = "assertion.multiAssetHash.missingPart"
)

func init() {
	statusSeverity[StatusMultiAssetHashMatch] = SeveritySuccess
	statusSeverity[StatusMultiAssetHashMismatch] = SeverityFailure
	statusSeverity[StatusMultiAssetHashMalformed] = SeverityFailure
	statusSeverity[StatusMultiAssetHashMissingPart] = SeverityFailure
}

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
func (v *validator) verifyMultiAssetHash(m *parsedManifest, a *rawAssertion, uri string) {
	subj := uri + "/c2pa.hash.multi-asset"
	var assertion map[string]any
	if decMode.Unmarshal(a.data, &assertion) != nil {
		v.add(StatusMultiAssetHashMalformed, subj, "multi-asset hash assertion did not decode", nil)
		return
	}
	parts, _ := assertion["parts"].([]any)
	if len(parts) == 0 {
		v.add(StatusMultiAssetHashMalformed, subj, "multi-asset hash has no parts", nil)
		return
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
		off, okOff := toInt(loc["byteOffset"])
		length, okLen := toInt(loc["length"])
		if !okOff || !okLen || length <= 0 || off != next {
			v.add(StatusMultiAssetHashMalformed, subj,
				"multi-asset hash parts do not tile the asset without gap or overlap", nil)
			return
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
			v.add(StatusMultiAssetHashMalformed, subj, "part names a data-hash assertion that is not in the manifest", nil)
			return
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
				return
			}
			if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
				v.add(StatusMultiAssetHashMismatch, subj, "part's data-hash assertion does not match its hashed URI", nil)
				problem = true
				continue
			}
		}
		if !v.partHashMatches(pa, v.data[off:next]) {
			v.add(StatusMultiAssetHashMismatch, subj, "part content does not match its data hash", nil)
			problem = true
		}
	}
	if covered != size {
		v.add(StatusMultiAssetHashMismatch, subj, "asset has data beyond its last present part", nil)
		return
	}
	if !problem {
		v.add(StatusMultiAssetHashMatch, subj, "multi-asset hash matches the parts present", nil)
	}
}

// partHashMatches checks one part's bytes against its c2pa.hash.data-style
// assertion (alg, hash and exclusions relative to the part).
func (v *validator) partHashMatches(a rawAssertion, part []byte) bool {
	var d map[string]any
	if decMode.Unmarshal(a.data, &d) != nil {
		return false
	}
	want, _ := d["hash"].([]byte)
	h, ok := hashByName(stringOr(d["alg"], ""))
	if !ok || len(want) == 0 {
		return false
	}
	raw, ok := decodeExclusions(d["exclusions"], len(part))
	if !ok {
		return false
	}
	if hashWithExclusions(v.ctx, part, h, mergeRanges(raw)) != nil {
		v.cancelled("", "while hashing a part")
		return false
	}
	return subtle.ConstantTimeCompare(h.Sum(nil), want) == 1
}
