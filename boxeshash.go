package c2pa

import (
	"crypto/subtle"
	"strings"
)

// c2pa.hash.boxes hard-binding verification (C2PA spec §18.6, §15.12.3). Where
// c2pa.hash.data binds an asset by hashing the whole file minus byte ranges,
// a box hash binds it structurally: the assertion is an ordered list of
// entries, each naming one or more consecutive boxes of the container and
// carrying a hash of the bytes those boxes span.
//
// Verification re-derives the asset's own box map (boxmap.go) and walks the two
// lists in lockstep. Both the order and the names must line up: an entry that
// does not match the next box in file order, or a box the assertion never
// accounts for, means the assertion does not describe this asset.
//
// The entry naming the C2PA store is skipped — it holds the manifest doing the
// binding — and so is any entry marked "excluded". Every other entry is hashed.
//
// Exclusions are the sharp edge. A box-hash entry may carve byte ranges out of
// its own hash, which is exactly how a forged assertion would leave tampered
// bytes unbound, so each one is checked against what the container's structure
// says is excludable at all: the manifest store, and asset metadata (§9.2.6).
// An exclusion anywhere else is a mismatch, not a matter of taste.

// boxHashEntry is one decoded entry of the assertion's boxes[] array.
type boxHashEntry struct {
	names      []string
	alg        string
	hash       []byte
	excluded   bool
	exclusions []boxExclusion
	// hasExclusions distinguishes an absent exclusions field from a present
	// but empty one, which the CDDL ("1* box-exclusions-map") forbids.
	hasExclusions bool
}

// boxExclusion is a byte range, relative to one of the entry's named boxes,
// left out of that entry's hash.
type boxExclusion struct {
	start, length int
	// boxIndex selects which of the entry's names the range is relative to.
	// It may be omitted only when the entry names exactly one box.
	boxIndex    int
	hasBoxIndex bool
}

// verifyBoxesHash verifies a c2pa.hash.boxes assertion against the asset bytes.
// defaultAlg is the claim's algorithm, used for entries that do not name their
// own.
func (v *validator) verifyBoxesHash(a *rawAssertion, uri, defaultAlg string) {
	subj := uri + "/" + a.label
	var assertion map[string]any
	if decMode.Unmarshal(a.data, &assertion) != nil {
		v.add(StatusAssertionBoxesHashMalformed, subj, "box-hash assertion did not decode", nil)
		return
	}
	entries, ok := decodeBoxHashEntries(assertion["boxes"])
	if !ok {
		v.add(StatusAssertionBoxesHashMalformed, subj, "box-hash assertion boxes[] did not decode", nil)
		return
	}
	if len(entries) == 0 {
		v.add(StatusAssertionBoxesHashMalformed, subj, "box-hash assertion lists no boxes", nil)
		return
	}
	// MaxScan truncation: a cap-truncated asset cannot be hashed reliably and
	// its final box may be cut short — report informationally before parsing so
	// truncation is never misread as a missing box or a mismatch.
	if len(v.data) >= v.cfg.maxScan {
		v.add(StatusUnsupported, subj, "asset reached the scan cap; box hashes not verified", nil)
		return
	}
	source, ok := assetBoxMap(v.ctx, v.container, v.data)
	if !ok {
		v.add(StatusUnsupported, subj,
			"box-hash verification is defined for JPEG, PNG and GIF; this container has no box map", nil)
		return
	}
	if len(source) == 0 {
		v.add(StatusAssertionBoxesHashUnknownBox, subj, "asset box structure did not parse", nil)
		return
	}

	// PNG's 8-byte signature is a box in the asset's own map, but a producer
	// may start its list at the first real chunk instead. Skip it only when the
	// assertion plainly does not begin there.
	si := 0
	if source[0].name == pngHeaderBoxName && entries[0].firstName() != pngHeaderBoxName {
		si = 1
	}

	additional := false
	for _, e := range entries {
		if len(e.names) == 0 {
			v.add(StatusAssertionBoxesHashMalformed, subj, "box-hash entry names no boxes", nil)
			return
		}
		// Checked before the entry is skipped below: "excluded" says the hash
		// is not computed, not that a present exclusions field may be malformed.
		if e.hasExclusions && len(e.exclusions) == 0 {
			v.add(StatusAssertionBoxesHashMalformed, subj, "box-hash entry has an empty exclusions array", nil)
			return
		}

		// The store's box holds the manifest doing the binding, so its bytes are
		// never hashed. Letting it share an entry with other boxes would take
		// those out of the hash along with it — checked for every name, not just
		// the first, so the store cannot be smuggled into the middle of a span.
		for _, name := range e.names {
			if name == c2paBoxName && len(e.names) != 1 {
				v.add(StatusAssertionBoxesHashMalformed, subj,
					"box-hash entry groups the C2PA store with other boxes", nil)
				return
			}
		}

		boxes := make([]assetBox, 0, len(e.names))
		for _, name := range e.names {
			if si >= len(source) || source[si].name != name {
				v.add(StatusAssertionBoxesHashUnknownBox, subj,
					"box-hash entry names "+quoteBoxName(name)+" where the asset has "+
						describeSourceBox(source, si), nil)
				return
			}
			boxes = append(boxes, source[si])
			si++
		}
		if boxes[0].name == c2paBoxName {
			continue
		}
		if e.excluded {
			// A whole box skipped that is not the store itself is an exclusion
			// beyond the baseline, whatever the box holds.
			additional = true
			continue
		}

		spanStart, spanEnd := boxes[0].start, boxes[len(boxes)-1].end()
		excl, meta, status := boxHashExclusionRanges(boxes, spanStart, spanEnd, e.exclusions)
		if status != "" {
			v.add(status, subj, "box-hash entry for "+quoteBoxName(boxes[0].name)+
				" has an exclusion that is not permitted there", nil)
			return
		}
		additional = additional || meta

		algName := e.alg
		if algName == "" {
			algName = defaultAlg
		}
		h, ok := hashByName(algName)
		if !ok {
			v.add(StatusAlgorithmUnsupported, subj, "unsupported box-hash algorithm", nil)
			return
		}
		writeGaps(v.data, spanStart, spanEnd, excl, h)
		if subtle.ConstantTimeCompare(h.Sum(nil), e.hash) != 1 {
			v.add(StatusAssertionBoxesHashMismatch, subj,
				"box hash does not match for "+quoteBoxName(boxes[0].name), nil)
			return
		}
	}

	// Boxes the assertion never named are bytes it does not bind. c2pa-rs stops
	// once its own list runs out; this reports it, because a hard binding that
	// covers a prefix of the asset is not a hard binding — appended frames or a
	// rewritten trailer would pass unnoticed.
	if si < len(source) {
		v.add(StatusAssertionBoxesHashUnknownBox, subj,
			"asset has boxes the assertion does not cover, starting at "+
				quoteBoxName(source[si].name), nil)
		return
	}

	v.add(StatusAssertionBoxesHashMatch, subj, "asset box hashes match", nil)
	if additional {
		v.add(StatusAssertionBoxesHashAdditionalExclusions, subj,
			"box hash excludes asset metadata beyond the C2PA store itself", nil)
	}
}

// boxHashExclusionRanges resolves an entry's exclusions into absolute byte
// ranges to leave out of [spanStart, spanEnd). It returns those ranges, whether
// any of them was asset metadata rather than the store, and a status code that
// is empty on success.
//
// The spec requires the exclusions to arrive already in increasing,
// non-overlapping order, and that is checked as given rather than sorted: a
// list that has to be reordered to make sense is malformed, and sorting it
// would quietly accept an assertion no conforming producer writes.
func boxHashExclusionRanges(boxes []assetBox, spanStart, spanEnd int, excl []boxExclusion) (ranges []byteRange, metadata bool, status StatusCode) {
	for _, e := range excl {
		idx := 0
		switch {
		case e.hasBoxIndex:
			idx = e.boxIndex
		case len(boxes) != 1:
			// Without an index there is nothing to resolve the range against.
			return nil, false, StatusAssertionBoxesHashMalformed
		}
		if idx < 0 || idx >= len(boxes) || e.start < 0 || e.length < 0 {
			return nil, false, StatusAssertionBoxesHashMalformed
		}
		b := boxes[idx]
		end := e.start + e.length
		if end < e.start { // overflow
			return nil, false, StatusAssertionBoxesHashMalformed
		}
		var permitted *allowedExclusion
		for i := range b.allowed {
			if b.allowed[i].boundedBy(b.length) && b.allowed[i].contains(e.start, end) {
				permitted = &b.allowed[i]
				break
			}
		}
		if permitted == nil {
			return nil, false, StatusAssertionBoxesHashMismatch
		}
		if permitted.kind == exclAssetMetadata {
			metadata = true
		}
		r := byteRange{start: b.start + e.start, length: e.length}
		if n := len(ranges); n > 0 && ranges[n-1].start+ranges[n-1].length > r.start {
			return nil, false, StatusAssertionBoxesHashMalformed
		}
		if r.start < spanStart || r.start+r.length > spanEnd {
			return nil, false, StatusAssertionBoxesHashMalformed
		}
		ranges = append(ranges, r)
	}
	return ranges, metadata, ""
}

// decodeBoxHashEntries decodes the assertion's boxes[] array. Structural
// problems return ok=false; the caller reports them as malformed rather than as
// a hash mismatch, because nothing was compared.
func decodeBoxHashEntries(raw any) ([]boxHashEntry, bool) {
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]boxHashEntry, 0, len(list))
	for _, item := range list {
		em, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		var e boxHashEntry
		names, ok := em["names"].([]any)
		if !ok {
			return nil, false
		}
		for _, n := range names {
			s, ok := n.(string)
			if !ok {
				return nil, false
			}
			e.names = append(e.names, s)
		}
		if e.hash, ok = em["hash"].([]byte); !ok {
			return nil, false
		}
		if raw, present := em["alg"]; present && raw != nil {
			if e.alg, ok = raw.(string); !ok {
				return nil, false
			}
		}
		if raw, present := em["excluded"]; present && raw != nil {
			if e.excluded, ok = raw.(bool); !ok {
				return nil, false
			}
		}
		if raw, present := em["exclusions"]; present && raw != nil {
			items, ok := raw.([]any)
			if !ok {
				return nil, false
			}
			e.hasExclusions = true
			for _, ei := range items {
				em, ok := ei.(map[string]any)
				if !ok {
					return nil, false
				}
				var x boxExclusion
				if x.start, ok = toInt(em["start"]); !ok {
					return nil, false
				}
				if x.length, ok = toInt(em["length"]); !ok {
					return nil, false
				}
				if raw, present := em["boxIndex"]; present && raw != nil {
					if x.boxIndex, ok = toInt(raw); !ok {
						return nil, false
					}
					x.hasBoxIndex = true
				}
				e.exclusions = append(e.exclusions, x)
			}
		}
		out = append(out, e)
	}
	return out, true
}

// firstName is the entry's leading box name, or "" when it names none.
func (e boxHashEntry) firstName() string {
	if len(e.names) == 0 {
		return ""
	}
	return e.names[0]
}

// quoteBoxName renders a box name for an explanation, keeping an empty or
// non-printable name from producing an unreadable message.
func quoteBoxName(name string) string {
	if name == "" {
		return `box ""`
	}
	var b strings.Builder
	b.WriteString(`box "`)
	for _, r := range name {
		if r < 0x20 || r > 0x7E {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	b.WriteString(`"`)
	return b.String()
}

// describeSourceBox names the asset box the walk is standing on, or says the
// asset has run out of boxes.
func describeSourceBox(source []assetBox, i int) string {
	if i >= len(source) {
		return "no more boxes"
	}
	return quoteBoxName(source[i].name)
}
