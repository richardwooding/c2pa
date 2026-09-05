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
	rawMerkle, hasMerkle := assertion["merkle"]
	hasMerkle = hasMerkle && rawMerkle != nil
	want, _ := assertion["hash"].([]byte)
	if len(want) == 0 && !hasMerkle {
		// No flat hash and no merkle field: nothing verifiable.
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash assertion has no hash", nil)
		return
	}
	defaultAlg := stringOr(assertion["alg"], "")
	// A merkle-only assertion takes its algorithm per map, so the top-level one
	// may legitimately be absent; a flat hash cannot be checked without it.
	h, ok := hashByName(defaultAlg)
	if !ok && len(want) > 0 {
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

	if len(want) > 0 {
		hashBMFFTopLevel(v.ctx, v.data, top, ranges, h)
		if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
			v.add(StatusAssertionBMFFHashMismatch, subj, "asset BMFF hash does not match", nil)
			return
		}
		if !hasMerkle {
			v.add(StatusAssertionBMFFHashMatch, subj, "asset BMFF hash matches", nil)
			return
		}
	}
	v.verifyBMFFMerkle(subj, rawMerkle, defaultAlg, top, ranges)
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

// Merkle BMFF hashing (C2PA spec §18.6.3 / §18.6.6). A c2pa.hash.bmff.v3
// assertion may carry a `merkle` array instead of — or as well as — a flat
// hash, one merkle-map per 'mdat' box or per track.
//
// What a single reader can settle, and what it cannot, is the whole shape of
// this code. Three arrangements exist:
//
//   - A NON-FRAGMENTED asset whose 'mdat' is hashed piecewise. The blocks are
//     in this file, so the tree is rebuilt from them and checked in full.
//   - A FRAGMENTED asset stored as ONE flat file. `initHash` covers everything
//     before the first 'moof' and is checked here; each chunk's own hash lives
//     in that chunk's C2PA 'merkle' box, which this reader does not yet parse.
//   - A FRAGMENTED asset SPLIT ACROSS FILES (DASH/CMAF .m4s). The chunks are
//     other files entirely and no amount of care with this one will produce
//     them.
//
// So a mismatch is reported whenever this file disproves the assertion, and
// what could not be checked is named precisely rather than rolled into a
// success. Verifying a chunk against its Merkle proof needs the chunk, which
// means an API that takes more than one reader.

// maxMerkleLeaves caps how many leaf hashes a merkle-map may induce. A
// `fixedBlockSize` of 2 over a large 'mdat' would otherwise ask for hundreds of
// millions of leaves and the tree above them — the assertion is attacker
// controlled, and the block size is what turns its size into our allocation.
const maxMerkleLeaves = 1 << 20

// mdatBlockPrefix is the number of bytes at the start of an 'mdat' box that a
// Merkle leaf never covers. Per the spec's exclusion-list requirements this is
// exactly 16 whether the box uses the 8-byte or the 16-byte large-size header,
// so it is NOT the same thing as the box's own header length.
const mdatBlockPrefix = 16

// merkleMap is one decoded entry of the assertion's merkle array.
type merkleMap struct {
	count    int
	alg      string
	initHash []byte
	hashes   [][]byte
	// fixedBlockSize / variableBlockSizes describe how a non-fragmented asset's
	// 'mdat' payload is cut into leaves. At most one may be present.
	fixedBlockSize     int
	variableBlockSizes []int
	hasFixed           bool
	hasVariable        bool
}

// verifyBMFFMerkle checks every merkle-map the assertion carries against what
// this file actually holds. ranges are the assertion's exclusions already
// resolved against the box tree.
func (v *validator) verifyBMFFMerkle(subj string, raw any, defaultAlg string, top []*bmffBox, ranges []byteRange) {
	maps, ok := decodeBMFFMerkle(raw)
	if !ok {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash merkle array did not decode", nil)
		return
	}
	if len(maps) == 0 {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash merkle array is empty", nil)
		return
	}

	// The first 'moof' is what makes an asset fragmented, and where the init
	// segment ends.
	firstMoof := -1
	var mdats []*bmffBox
	for _, b := range top {
		if b.typ == "moof" && firstMoof < 0 {
			firstMoof = b.start
		}
		if b.typ == "mdat" {
			mdats = append(mdats, b)
		}
	}

	verified, unverified := 0, ""
	for i, m := range maps {
		algName := m.alg
		if algName == "" {
			algName = defaultAlg
		}
		if _, ok := hashByName(algName); !ok {
			v.add(StatusAlgorithmUnsupported, subj, "unsupported merkle-map algorithm", nil)
			return
		}
		if m.hasFixed && m.hasVariable {
			v.add(StatusAssertionBMFFHashMalformed, subj,
				"merkle-map declares both fixedBlockSize and variableBlockSizes", nil)
			return
		}

		if len(m.initHash) > 0 {
			if firstMoof < 0 {
				// initHash is required absent for non-fragmented media, so this
				// is most likely a fragmented asset's initialization segment
				// being read on its own — in which case the hash covers this
				// whole file and the chunks it binds are elsewhere.
				unverified = "asset carries a fragmented-BMFF initialization hash but no 'moof' box; " +
					"the chunks it binds are in other files"
				continue
			}
			// The init hash covers everything before the first 'moof': the
			// assertion's own exclusions, plus the whole fragmented remainder.
			initRanges := mergeRanges(append(append([]byteRange(nil), ranges...),
				byteRange{start: firstMoof, length: len(v.data) - firstMoof}))
			h, _ := hashByName(algName)
			hashBMFFTopLevel(v.ctx, v.data, top, initRanges, h)
			if subtle.ConstantTimeCompare(h.Sum(nil), m.initHash) != 1 {
				v.add(StatusAssertionBMFFHashMismatch, subj,
					"fragmented BMFF initialization segment hash does not match", nil)
				return
			}
			verified++
			unverified = "fragmented BMFF chunk hashes need each chunk's own merkle box; " +
				"only the initialization segment was verified"
			continue
		}

		// No init hash: a non-fragmented asset whose 'mdat' is hashed as one
		// unit or piecewise. There is one merkle-map per 'mdat', paired in file
		// order — so the pairing is positional and only means anything when the
		// two counts agree.
		if len(mdats) != len(maps) {
			unverified = "merkle maps do not correspond one-to-one with the asset's 'mdat' boxes"
			continue
		}
		mdat := mdats[i]
		leaves, status := merkleLeafRanges(mdat, m)
		if status != "" {
			v.add(status, subj, "merkle-map leaf blocks do not describe this 'mdat' box", nil)
			return
		}
		if !v.checkMerkleTree(subj, algName, m, leaves) {
			return
		}
		verified++
	}

	switch {
	case verified == 0:
		v.add(StatusUnsupported, subj, "merkle BMFF hash not verified: "+unverified, nil)
	case unverified != "":
		// Something checked out and something could not be checked at all.
		// Reporting a match here would say the media is bound when only part
		// of it is, so the honest roll-up is the informational.
		v.add(StatusUnsupported, subj, "merkle BMFF hash only partly verified: "+unverified, nil)
	default:
		v.add(StatusAssertionBMFFHashMatch, subj, "asset BMFF merkle hashes match", nil)
	}
}

// merkleLeafRanges cuts an 'mdat' box into the leaf blocks a merkle-map
// declares. The blocks start mdatBlockPrefix bytes into the box and must cover
// the rest of it exactly.
func merkleLeafRanges(mdat *bmffBox, m merkleMap) ([]byteRange, StatusCode) {
	start := mdat.start + mdatBlockPrefix
	length := (mdat.end - mdat.start) - mdatBlockPrefix
	if length < 0 || start > mdat.end {
		return nil, StatusAssertionBMFFHashMalformed
	}
	switch {
	case m.hasFixed:
		if m.fixedBlockSize <= 1 {
			return nil, StatusAssertionBMFFHashMalformed
		}
		n := (length + m.fixedBlockSize - 1) / m.fixedBlockSize
		if n > maxMerkleLeaves {
			return nil, StatusAssertionBMFFHashMalformed
		}
		out := make([]byteRange, 0, n)
		for left := length; left > 0; {
			take := min(left, m.fixedBlockSize)
			out = append(out, byteRange{start: start, length: take})
			start += take
			left -= take
		}
		return out, ""
	case m.hasVariable:
		if len(m.variableBlockSizes) > maxMerkleLeaves {
			return nil, StatusAssertionBMFFHashMalformed
		}
		total := 0
		for _, n := range m.variableBlockSizes {
			if n < 0 || n > length-total {
				return nil, StatusAssertionBMFFHashMalformed
			}
			total += n
		}
		// The spec requires the sizes to sum to the payload exactly; a short
		// sum would leave media bytes bound by nothing.
		if total != length {
			return nil, StatusAssertionBMFFHashMalformed
		}
		out := make([]byteRange, 0, len(m.variableBlockSizes))
		for _, n := range m.variableBlockSizes {
			out = append(out, byteRange{start: start, length: n})
			start += n
		}
		return out, ""
	}
	// Neither field: the whole payload is one leaf.
	return []byteRange{{start: start, length: length}}, ""
}

// checkMerkleTree hashes each leaf block, rebuilds the tree above them and
// compares it with the row the assertion stored. It reports whether to carry
// on, adding a status itself when it does not.
func (v *validator) checkMerkleTree(subj, algName string, m merkleMap, leaves []byteRange) bool {
	if len(leaves) != m.count {
		v.add(StatusAssertionBMFFHashMalformed, subj,
			"merkle-map count does not match the leaf blocks it declares", nil)
		return false
	}
	digests := make([][]byte, 0, len(leaves))
	for _, r := range leaves {
		if v.ctx.Err() != nil {
			v.add(StatusUnsupported, subj, "merkle BMFF hashing cancelled", nil)
			return false
		}
		h, _ := hashByName(algName)
		h.Write(v.data[r.start : r.start+r.length])
		digests = append(digests, h.Sum(nil))
	}
	// hashes is one row of the tree — leaf-most, root, or between — and which
	// row is implied by its length.
	for _, layer := range merkleLayers(algName, digests) {
		if len(layer) != len(m.hashes) {
			continue
		}
		for i := range layer {
			if subtle.ConstantTimeCompare(layer[i], m.hashes[i]) != 1 {
				v.add(StatusAssertionBMFFHashMismatch, subj,
					"asset BMFF merkle hash does not match", nil)
				return false
			}
		}
		return true
	}
	v.add(StatusAssertionBMFFHashMalformed, subj,
		"merkle-map hashes match no row of the tree its leaf count implies", nil)
	return false
}

// merkleLayers builds the C2PA Merkle tree over already-hashed leaves and
// returns every row, leaf-most first. A parent is the hash of its two children
// concatenated; a last child with no sibling is carried up UNCHANGED — not
// duplicated and not re-hashed, which is what makes this tree C2PA's rather
// than the more common Bitcoin-style one.
func merkleLayers(algName string, leaves [][]byte) [][][]byte {
	layers := [][][]byte{leaves}
	for cur := leaves; len(cur) > 1; {
		next := make([][]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 == len(cur) {
				next = append(next, cur[i])
				continue
			}
			h, _ := hashByName(algName)
			h.Write(cur[i])
			h.Write(cur[i+1])
			next = append(next, h.Sum(nil))
		}
		layers = append(layers, next)
		cur = next
	}
	return layers
}

// decodeBMFFMerkle decodes the assertion's merkle array. Structural problems
// return ok=false; the caller reports them as malformed, since nothing was
// compared.
func decodeBMFFMerkle(raw any) ([]merkleMap, bool) {
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]merkleMap, 0, len(list))
	for _, item := range list {
		em, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		var m merkleMap
		if m.count, ok = toInt(em["count"]); !ok || m.count < 1 {
			return nil, false
		}
		hashes, ok := em["hashes"].([]any)
		if !ok || len(hashes) == 0 {
			return nil, false
		}
		for _, hv := range hashes {
			b, ok := hv.([]byte)
			if !ok || len(b) == 0 {
				return nil, false
			}
			m.hashes = append(m.hashes, b)
		}
		if raw, present := em["alg"]; present && raw != nil {
			if m.alg, ok = raw.(string); !ok {
				return nil, false
			}
		}
		if raw, present := em["initHash"]; present && raw != nil {
			if m.initHash, ok = raw.([]byte); !ok || len(m.initHash) == 0 {
				return nil, false
			}
		}
		if raw, present := em["fixedBlockSize"]; present && raw != nil {
			if m.fixedBlockSize, ok = toInt(raw); !ok {
				return nil, false
			}
			m.hasFixed = true
		}
		if raw, present := em["variableBlockSizes"]; present && raw != nil {
			sizes, ok := raw.([]any)
			if !ok || len(sizes) == 0 {
				return nil, false
			}
			for _, sv := range sizes {
				n, ok := toInt(sv)
				if !ok {
					return nil, false
				}
				m.variableBlockSizes = append(m.variableBlockSizes, n)
			}
			m.hasVariable = true
		}
		out = append(out, m)
	}
	return out, true
}
