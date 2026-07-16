package c2pa

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"strconv"
	"strings"
)

// c2pa.hash.bmff.v2/.v3 hard-binding verification (C2PA spec §18.6). The
// assertion carries an exclusions array whose entries select boxes by xpath
// plus optional predicates; the digest is a single ascending pass over the
// asset where each top-level box that is not wholly excluded contributes its
// absolute file offset as an 8-byte big-endian integer followed by its bytes
// minus the exclusion ranges.
//
// Fragmented/Merkle assets (a `merkle` field, or no flat `hash`) are reported
// as informational unsupported: ordinary signed HEIC/AVIF/MP4/MOV carry only
// the flat hash.

// bmffExclusion is one decoded exclusions-map entry.
type bmffExclusion struct {
	xpath   string
	length  int // exact box size incl. headers; -1 when absent
	data    []bmffDataMatch
	subset  []bmffSubsetRange
	version int // FullBox version to match; -1 when absent
	flags   []byte
	exact   bool // flags comparison mode (default true)
}

// bmffDataMatch requires the box bytes at offset (from box start) to equal
// value for the exclusion to apply. This predicate is load-bearing: the
// standard "/uuid" exclusion uses it to exclude only the C2PA uuid box, not
// foreign uuid boxes.
type bmffDataMatch struct {
	offset int
	value  []byte
}

// bmffSubsetRange is a byte range relative to the box start; length 0 means
// "to the end of the box"; ranges are clamped to the box end.
type bmffSubsetRange struct {
	offset, length int
}

// verifyBMFFHash verifies a c2pa.hash.bmff.v2 / .v3 assertion against the
// asset bytes.
func (v *validator) verifyBMFFHash(a *rawAssertion, uri string) {
	subj := uri + "/" + a.label
	var assertion map[string]any
	if decMode.Unmarshal(a.data, &assertion) != nil {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash assertion did not decode", nil)
		return
	}
	if _, hasMerkle := assertion["merkle"]; hasMerkle {
		v.add(StatusUnsupported, subj, "fragmented/Merkle BMFF hashing is not supported", nil)
		return
	}
	want, _ := assertion["hash"].([]byte)
	if len(want) == 0 {
		// No flat hash and no merkle field: nothing verifiable.
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash assertion has no hash", nil)
		return
	}
	h, ok := hashByName(stringOr(assertion["alg"], ""))
	if !ok {
		v.add(StatusAlgorithmUnsupported, subj, "unsupported BMFF-hash algorithm", nil)
		return
	}
	// MaxScan truncation: a cap-truncated asset cannot be hashed reliably, and
	// its final box may be cut short — report informationally before parsing so
	// truncation is never misread as malformed or a mismatch.
	if len(v.data) >= v.cfg.maxScan {
		v.add(StatusUnsupported, subj, "asset reached the scan cap; BMFF hash not verified", nil)
		return
	}

	top := parseBMFFBoxes(v.ctx, v.data)
	if len(top) == 0 {
		v.add(StatusAssertionBMFFHashMalformed, subj, "asset has no parseable BMFF box structure", nil)
		return
	}
	excl, ok := decodeBMFFExclusions(assertion["exclusions"])
	if !ok {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash exclusions did not decode", nil)
		return
	}
	ranges, ok := bmffExclusionByteRanges(v.data, top, excl)
	if !ok {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash exclusion out of range", nil)
		return
	}

	hashBMFFTopLevel(v.ctx, v.data, top, ranges, h)
	if subtle.ConstantTimeCompare(h.Sum(nil), want) == 1 {
		v.add(StatusAssertionBMFFHashMatch, subj, "asset BMFF hash matches", nil)
	} else {
		v.add(StatusAssertionBMFFHashMismatch, subj, "asset BMFF hash does not match", nil)
	}
}

// decodeBMFFExclusions decodes the assertion's exclusions array. A missing or
// empty array is allowed (hash everything); a structurally invalid one is not.
func decodeBMFFExclusions(raw any) ([]bmffExclusion, bool) {
	if raw == nil {
		return nil, true
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]bmffExclusion, 0, len(list))
	for _, item := range list {
		em, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		e := bmffExclusion{length: -1, version: -1, exact: true}
		if e.xpath, ok = em["xpath"].(string); !ok || e.xpath == "" {
			return nil, false
		}
		if raw, present := em["length"]; present && raw != nil {
			if e.length, ok = toInt(raw); !ok || e.length < 0 {
				return nil, false
			}
		}
		if raw, present := em["version"]; present && raw != nil {
			if e.version, ok = toInt(raw); !ok {
				return nil, false
			}
		}
		if raw, present := em["flags"]; present && raw != nil {
			if e.flags, ok = raw.([]byte); !ok || len(e.flags) != 3 {
				return nil, false
			}
		}
		if raw, present := em["exact"]; present && raw != nil {
			if e.exact, ok = raw.(bool); !ok {
				return nil, false
			}
		}
		if raw, present := em["data"]; present && raw != nil {
			items, ok := raw.([]any)
			if !ok {
				return nil, false
			}
			for _, di := range items {
				dm, ok := di.(map[string]any)
				if !ok {
					return nil, false
				}
				offset, ook := toInt(dm["offset"])
				value, vok := dm["value"].([]byte)
				if !ook || !vok || offset < 0 || len(value) == 0 {
					return nil, false
				}
				e.data = append(e.data, bmffDataMatch{offset: offset, value: value})
			}
		}
		if raw, present := em["subset"]; present && raw != nil {
			items, ok := raw.([]any)
			if !ok {
				return nil, false
			}
			for _, si := range items {
				sm, ok := si.(map[string]any)
				if !ok {
					return nil, false
				}
				offset, ook := toInt(sm["offset"])
				length, lok := toInt(sm["length"])
				if !ook || !lok || offset < 0 || length < 0 {
					return nil, false
				}
				e.subset = append(e.subset, bmffSubsetRange{offset: offset, length: length})
			}
		}
		out = append(out, e)
	}
	return out, true
}

// matchBMFFXPath resolves an xpath like "/moov/trak/mdia" against the box
// tree. An unindexed segment matches every sibling of that type; a "[n]"
// suffix selects the nth (1-based) sibling of that type within its parent. An
// xpath may match zero or more boxes.
func matchBMFFXPath(roots []*bmffBox, xpath string) []*bmffBox {
	if !strings.HasPrefix(xpath, "/") {
		return nil
	}
	return matchBMFFXPathSegments(roots, strings.Split(strings.TrimPrefix(xpath, "/"), "/"))
}

// matchBMFFXPathSegments recursively matches path segments against sibling
// pools; "[n]" indices count per sibling pool.
func matchBMFFXPathSegments(pool []*bmffBox, segs []string) []*bmffBox {
	if len(segs) == 0 {
		return nil
	}
	seg := segs[0]
	if seg == "" {
		return nil
	}
	typ, index := seg, 0
	if open := strings.IndexByte(seg, '['); open >= 0 && strings.HasSuffix(seg, "]") {
		typ = seg[:open]
		n, err := strconv.Atoi(seg[open+1 : len(seg)-1])
		if err != nil || n < 1 {
			return nil
		}
		index = n
	}
	var matched []*bmffBox
	seen := 0
	for _, b := range pool {
		if b.typ != typ {
			continue
		}
		seen++
		if index == 0 || seen == index {
			matched = append(matched, b)
		}
	}
	if len(segs) == 1 {
		return matched
	}
	var out []*bmffBox
	for _, b := range matched {
		out = append(out, matchBMFFXPathSegments(b.children, segs[1:])...)
	}
	return out
}

// bmffExclusionApplies evaluates an exclusion's optional predicates against a
// matched box. Per spec: length must equal the box size including headers;
// data values must match at their offsets; version/flags compare against the
// FullBox header bytes (flags with exact=false use bits-set semantics —
// (file & want) == want — per the spec, deliberately NOT c2pa-rs's inverted
// subset test).
func bmffExclusionApplies(data []byte, b *bmffBox, e bmffExclusion) bool {
	if e.length >= 0 && e.length != b.end-b.start {
		return false
	}
	for _, dm := range e.data {
		lo := b.start + dm.offset
		if lo < b.start || lo+len(dm.value) > b.end {
			return false
		}
		if !bytes.Equal(data[lo:lo+len(dm.value)], dm.value) {
			return false
		}
	}
	if e.version >= 0 || e.flags != nil {
		p := b.start + b.headerLen
		if p+4 > b.end {
			return false
		}
		if e.version >= 0 && int(data[p]) != e.version {
			return false
		}
		if e.flags != nil {
			fileFlags := data[p+1 : p+4]
			if e.exact {
				if !bytes.Equal(fileFlags, e.flags) {
					return false
				}
			} else {
				for i := 0; i < 3; i++ {
					if fileFlags[i]&e.flags[i] != e.flags[i] {
						return false
					}
				}
			}
		}
	}
	return true
}

// bmffExclusionByteRanges resolves exclusions against the box tree into
// sorted, merged byte ranges. An exclusion that matches no box contributes
// nothing (allowed); a subset with invalid arithmetic reports not-ok.
func bmffExclusionByteRanges(data []byte, roots []*bmffBox, excl []bmffExclusion) ([]byteRange, bool) {
	var out []byteRange
	for _, e := range excl {
		for _, b := range matchBMFFXPath(roots, e.xpath) {
			if !bmffExclusionApplies(data, b, e) {
				continue
			}
			if len(e.subset) == 0 {
				out = append(out, byteRange{start: b.start, length: b.end - b.start})
				continue
			}
			for _, s := range e.subset {
				lo := b.start + s.offset
				if lo >= b.end {
					continue // subset beyond box end: nothing to exclude
				}
				hi := b.end
				if s.length > 0 && lo+s.length < hi {
					hi = lo + s.length
				}
				out = append(out, byteRange{start: lo, length: hi - lo})
			}
		}
	}
	return mergeRanges(out), true
}

// hashBMFFTopLevel computes the v2/v3 BMFF hash: for each top-level box, in
// file order, that is not wholly excluded, write the box's absolute offset as
// an 8-byte big-endian integer, then the box's bytes minus exclusion ranges.
//
// Marker granularity note: the spec describes offset markers per top-level
// box; c2pa-rs's HashRange plumbing could also be read as one marker per
// included range. The two coincide when exclusions cover whole top-level
// boxes (the real-world case — /uuid, /ftyp, /mfra); the signed-MP4 fixture
// test is the oracle for this reading.
func hashBMFFTopLevel(ctx context.Context, data []byte, top []*bmffBox, ranges []byteRange, h hash.Hash) {
	var offsetBuf [8]byte
	for _, b := range top {
		if ctx.Err() != nil {
			return
		}
		if coveredByRanges(b.start, b.end, ranges) {
			continue // wholly excluded: no offset marker, no bytes
		}
		binary.BigEndian.PutUint64(offsetBuf[:], uint64(b.start))
		h.Write(offsetBuf[:])
		writeGaps(data, b.start, b.end, ranges, h)
	}
}

// coveredByRanges reports whether [start,end) is entirely inside one merged
// exclusion range.
func coveredByRanges(start, end int, ranges []byteRange) bool {
	for _, r := range ranges {
		if r.start <= start && r.start+r.length >= end {
			return true
		}
	}
	return false
}

// writeGaps writes data[start:end] to h, skipping any parts covered by the
// (sorted, merged) exclusion ranges.
func writeGaps(data []byte, start, end int, ranges []byteRange, h hash.Hash) {
	cur := start
	for _, r := range ranges {
		rEnd := r.start + r.length
		if rEnd <= cur {
			continue
		}
		if r.start >= end {
			break
		}
		if r.start > cur {
			h.Write(data[cur:min(r.start, end)])
		}
		if rEnd > cur {
			cur = rEnd
		}
		if cur >= end {
			return
		}
	}
	if cur < end {
		h.Write(data[cur:end])
	}
}
