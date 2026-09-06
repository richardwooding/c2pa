package c2pa

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
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
// Merkle assets (a `merkle` array, with or without a flat `hash`) are verified
// by verifyBMFFMerkle below as far as the bytes in hand can settle them;
// ordinary signed HEIC/AVIF/MP4/MOV carry only the flat hash.

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

	excl, ok := decodeBMFFExclusions(assertion["exclusions"])
	if !ok {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash exclusions did not decode", nil)
		return
	}
	seg, ok := newBMFFSegment(v.ctx, v.data, excl)
	if !ok {
		v.add(StatusAssertionBMFFHashMalformed, subj, "asset has no parseable BMFF box structure", nil)
		return
	}

	if len(want) > 0 {
		hashBMFFTopLevel(v.ctx, seg.data, seg.top, seg.ranges, h)
		if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
			v.add(StatusAssertionBMFFHashMismatch, subj, "asset BMFF hash does not match", nil)
			return
		}
		if !hasMerkle {
			v.add(StatusAssertionBMFFHashMatch, subj, "asset BMFF hash matches", nil)
			return
		}
	}
	v.verifyBMFFMerkle(subj, rawMerkle, defaultAlg, seg)
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
// nothing (allowed), and a subset past the box end is clamped, so nothing here
// can fail: the exclusions were validated when they were decoded.
func bmffExclusionByteRanges(data []byte, roots []*bmffBox, excl []bmffExclusion) []byteRange {
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
	return mergeRanges(out)
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
// Three arrangements exist, and each is verified as far as the bytes in hand
// can settle it:
//
//   - A NON-FRAGMENTED asset whose 'mdat' is hashed piecewise. The blocks are
//     in this file, so the tree is rebuilt from them and checked in full.
//   - A FRAGMENTED asset stored as ONE flat file. `initHash` covers everything
//     before the first 'moof'; each chunk — a 'moof' and the boxes up to the
//     next one — is hashed and checked against the Merkle proof carried by the
//     C2PA 'merkle' box that precedes it. Both are checked in full.
//   - A FRAGMENTED asset SPLIT ACROSS FILES (DASH/CMAF .m4s). Read on its own,
//     the initialization segment proves or disproves `initHash`; the chunks
//     are other files, and are named as such rather than rolled into a match.
//
// A mismatch is reported whenever the bytes in hand disprove the assertion,
// and whatever could not be checked is named precisely.

// maxMerkleLeaves caps how many leaf hashes a merkle-map may induce. A
// `fixedBlockSize` of 2 over a large 'mdat' would otherwise ask for hundreds of
// millions of leaves and the tree above them — the assertion is attacker
// controlled, and the block size is what turns its size into our allocation.
const maxMerkleLeaves = 1 << 20

// maxMerkleProof caps the proof a merkle box may carry. A proof holds one hash
// per row climbed, so ⌈log2(maxMerkleLeaves)⌉ = 20 is the most any tree under
// the leaf cap can need; 64 leaves generous room without letting a box hand the
// verifier an unbounded list.
const maxMerkleProof = 64

// mdatBlockPrefix is the number of bytes at the start of an 'mdat' box that a
// Merkle leaf never covers. Per the spec's exclusion-list requirements this is
// exactly 16 whether the box uses the 8-byte or the 16-byte large-size header,
// so it is NOT the same thing as the box's own header length.
const mdatBlockPrefix = 16

// merkleMap is one decoded entry of the assertion's merkle array.
type merkleMap struct {
	// uniqueID and localID name the tree. The merkle box in each fragment
	// carries the same pair, which is how a fragment finds its map; -1 when the
	// assertion omits them.
	uniqueID, localID int
	count             int
	alg               string
	initHash          []byte
	hashes            [][]byte
	// fixedBlockSize / variableBlockSizes describe how a non-fragmented asset's
	// 'mdat' payload is cut into leaves. At most one may be present.
	fixedBlockSize     int
	variableBlockSizes []int
	hasFixed           bool
	hasVariable        bool
}

// merkleBox is one decoded C2PA merkle-purpose uuid box (spec §A.5.4.1.3): the
// bmff-merkle-map naming the tree the fragment belongs to, the fragment's leaf
// position in it and — unless the assertion already stores the leaf row — the
// proof from that leaf up to the stored row.
type merkleBox struct {
	uniqueID, localID, location int
	hashes                      [][]byte // the proof; nil when absent
	box                         *bmffBox
}

// bmffSegment is one BMFF file — the asset, an initialization segment or a
// fragment — with its top-level boxes parsed and the assertion's exclusions
// resolved against THAT file's box tree. Exclusions name boxes by path, not by
// byte range, so a fragment re-resolves them against its own tree, and the
// mandatory "/uuid" exclusion then removes the fragment's own merkle box.
type bmffSegment struct {
	data   []byte
	top    []*bmffBox
	ranges []byteRange
}

// newBMFFSegment parses data's top-level boxes and resolves excl against them.
// ok is false when data has no parseable box structure.
func newBMFFSegment(ctx context.Context, data []byte, excl []bmffExclusion) (bmffSegment, bool) {
	top := parseBMFFBoxes(ctx, data)
	if len(top) == 0 {
		return bmffSegment{}, false
	}
	return bmffSegment{data: data, top: top, ranges: bmffExclusionByteRanges(data, top, excl)}, true
}

// verifyBMFFMerkle checks every merkle-map the assertion carries against what
// this file actually holds.
func (v *validator) verifyBMFFMerkle(subj string, raw any, defaultAlg string, seg bmffSegment) {
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
	totalLeaves := 0
	for _, b := range seg.top {
		if b.typ == "moof" && firstMoof < 0 {
			firstMoof = b.start
		}
		if b.typ == "mdat" {
			mdats = append(mdats, b)
		}
	}
	for _, m := range maps {
		totalLeaves += m.count
	}

	// A flat fragmented file's chunks and merkle boxes are cut once, when the
	// first map carrying an initHash asks for them.
	var chunks [][]*bmffBox
	var boxes []merkleBox
	fragmentsCut := false

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
			// The init hash covers everything before the first 'moof' — or, for
			// an initialization segment read on its own, this whole file.
			initEnd := len(seg.data)
			if firstMoof >= 0 {
				initEnd = firstMoof
			}
			if !initHashMatches(v.ctx, seg, m, algName, initEnd) {
				if v.merkleCancelled(subj) {
					return
				}
				v.add(StatusAssertionBMFFHashMismatch, subj,
					"fragmented BMFF initialization segment hash does not match", nil)
				return
			}
			if firstMoof < 0 {
				// initHash is required absent for non-fragmented media, so a
				// file with no 'moof' is a fragmented asset's initialization
				// segment on its own: this file proves the hash, and the chunks
				// it binds are other files entirely.
				verified++
				unverified = fmt.Sprintf("the initialization segment hash matches; "+
					"the %d fragments it binds are in other files", totalLeaves)
				continue
			}
			if !fragmentsCut {
				chunks = bmffChunks(seg.top)
				if boxes, ok = bmffMerkleBoxes(seg.data, seg.top); !ok {
					v.add(StatusAssertionBMFFHashMalformed, subj,
						"fragmented BMFF merkle box did not decode", nil)
					return
				}
				fragmentsCut = true
			}
			if !v.verifyMerkleChunks(subj, algName, m, seg, chunks, boxes) {
				return
			}
			verified++
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
		if !v.checkMerkleTree(subj, algName, m, leaves, seg.data) {
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

// merkleCancelled reports a cancelled context as the informational it is, so a
// hash cut short by cancellation is never mistaken for a mismatch. It reports
// whether it added a status.
func (v *validator) merkleCancelled(subj string) bool {
	if v.ctx.Err() == nil {
		return false
	}
	v.add(StatusUnsupported, subj, "merkle BMFF hashing cancelled", nil)
	return true
}

// initHashMatches checks a merkle-map's initHash against the initialization
// segment: the same offset-marker walk as the flat hash (c2pa-rs reaches both
// through hash_stream_by_alg), over the assertion's exclusions plus everything
// from fragmentedFrom to the end of the file. In a flat fragmented file that is
// the first 'moof', so the walk covers 'ftyp' and 'moov' alone; an
// initialization segment that is a file of its own has nothing to cut off and
// passes len(seg.data).
func initHashMatches(ctx context.Context, seg bmffSegment, m merkleMap, algName string, fragmentedFrom int) bool {
	h, ok := hashByName(algName)
	if !ok {
		return false
	}
	ranges := seg.ranges
	if fragmentedFrom < len(seg.data) {
		ranges = mergeRanges(append(append([]byteRange(nil), seg.ranges...),
			byteRange{start: fragmentedFrom, length: len(seg.data) - fragmentedFrom}))
	}
	hashBMFFTopLevel(ctx, seg.data, seg.top, ranges, h)
	return subtle.ConstantTimeCompare(h.Sum(nil), m.initHash) == 1
}

// bmffChunks splits a flat fragmented file into its chunks: each begins at a
// 'moof' and runs to the box before the next one, or to the end of the file.
// Everything before the first 'moof' is the initialization segment and belongs
// to no chunk. nil when there is no 'moof' — or when the file BEGINS with one,
// which is a bare fragment rather than fragmented content (c2pa-rs
// split_fragment_boxes draws the same line).
func bmffChunks(top []*bmffBox) [][]*bmffBox {
	first := -1
	for i, b := range top {
		if b.typ == "moof" {
			first = i
			break
		}
	}
	if first <= 0 {
		return nil
	}
	var chunks [][]*bmffBox
	start := first
	for i := first + 1; i <= len(top); i++ {
		if i == len(top) || top[i].typ == "moof" {
			chunks = append(chunks, top[start:i])
			start = i
		}
	}
	return chunks
}

// verifyMerkleChunks checks a flat fragmented file's chunks against one
// merkle-map. The pairing is positional — the k-th merkle box describes the
// k-th chunk, as in c2pa-rs — so both counts must equal the map's. A chunk's
// hash is the same offset-marker walk as the flat hash over just that chunk's
// boxes, the assertion's exclusions still applied; the merkle box before a
// 'moof' lies outside the chunk in any case, and under the mandatory "/uuid"
// exclusion besides. It reports whether to carry on, adding a status itself
// when it does not.
func (v *validator) verifyMerkleChunks(subj, algName string, m merkleMap, seg bmffSegment, chunks [][]*bmffBox, boxes []merkleBox) bool {
	if len(chunks) != m.count {
		v.add(StatusAssertionBMFFHashMismatch, subj,
			fmt.Sprintf("asset holds %d fragment chunks but the merkle map binds %d", len(chunks), m.count), nil)
		return false
	}
	if len(boxes) != m.count {
		v.add(StatusAssertionBMFFHashMismatch, subj,
			fmt.Sprintf("asset carries %d merkle boxes but the merkle map binds %d chunks", len(boxes), m.count), nil)
		return false
	}
	for k, chunk := range chunks {
		if v.merkleCancelled(subj) {
			return false
		}
		mb := boxes[k]
		if m.uniqueID >= 0 && (mb.uniqueID != m.uniqueID || mb.localID != m.localID) {
			v.add(StatusAssertionBMFFHashMismatch, subj,
				fmt.Sprintf("fragmented BMFF chunk %d carries a merkle box for uniqueId %d, localId %d, not this map's %d, %d",
					k, mb.uniqueID, mb.localID, m.uniqueID, m.localID), nil)
			return false
		}
		// §15.12.2: locations run 0, 1, 2… in rendered order, and a flat file
		// renders in file order. Left unchecked, two chunks could swap places
		// along with their proofs and still verify.
		if mb.location != k {
			v.add(StatusAssertionBMFFHashMismatch, subj,
				fmt.Sprintf("fragmented BMFF chunk %d carries merkle location %d", k, mb.location), nil)
			return false
		}
		h, _ := hashByName(algName)
		hashBMFFTopLevel(v.ctx, seg.data, chunk, seg.ranges, h)
		ok, malformed := merkleProve(algName, m, h.Sum(nil), k, mb.hashes)
		if malformed {
			v.add(StatusAssertionBMFFHashMalformed, subj,
				fmt.Sprintf("fragmented BMFF chunk %d carries a merkle proof that does not fit the tree", k), nil)
			return false
		}
		if !ok {
			if v.merkleCancelled(subj) {
				return false
			}
			v.add(StatusAssertionBMFFHashMismatch, subj,
				fmt.Sprintf("fragmented BMFF chunk %d hash does not match its merkle proof", k), nil)
			return false
		}
	}
	return true
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

// checkMerkleTree hashes each leaf block of data, rebuilds the tree above them
// and compares it with the row the assertion stored. It reports whether to
// carry on, adding a status itself when it does not.
func (v *validator) checkMerkleTree(subj, algName string, m merkleMap, leaves []byteRange, data []byte) bool {
	if len(leaves) != m.count {
		v.add(StatusAssertionBMFFHashMalformed, subj,
			"merkle-map count does not match the leaf blocks it declares", nil)
		return false
	}
	digests := make([][]byte, 0, len(leaves))
	for _, r := range leaves {
		if v.merkleCancelled(subj) {
			return false
		}
		h, _ := hashByName(algName)
		h.Write(data[r.start : r.start+r.length])
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

// merkleLayout returns the width of every row of a C2PA Merkle tree over count
// leaves, leaf-most first — the shape merkleLayers builds, without the hashes.
// Each row pairs the one below and carries an unpaired last node up as one, so
// a row of n has ⌈n/2⌉ above it. nil for a count below one.
func merkleLayout(count int) []int {
	if count < 1 {
		return nil
	}
	widths := []int{count}
	for n := count; n > 1; {
		n -= n / 2 // ⌈n/2⌉ without the overflow n+1 could bring
		widths = append(widths, n)
	}
	return widths
}

// merkleProve checks one leaf against the row the assertion stores, using the
// proof the leaf's merkle box carries: the sibling hash at each row from the
// leaf up to the stored one. This is c2pa-rs's check_merkle_tree. Climbing
// from location, a node at an odd index is a right child, so its sibling is
// hashed first; at an even index it is a left child; the last node of an odd
// row has no sibling and is carried up unchanged, consuming no proof element —
// the same shape merkleLayers builds. ok reports whether the stored row is
// reached with the right hash; a location outside the tree is simply not ok.
// malformed reports a proof that cannot fit the tree at all — too short to
// climb to the stored row, too long once it is reached, or a stored row that no
// tree over count leaves has — which is a defect in the assertion or the box
// rather than evidence about the bytes. An algorithm hashByName refuses is the
// caller's to report; it is refused here as malformed only so that nothing can
// panic.
func merkleProve(algName string, m merkleMap, leaf []byte, location int, proof [][]byte) (ok, malformed bool) {
	if location < 0 || location >= m.count {
		return false, false
	}
	if _, ok := hashByName(algName); !ok {
		return false, true
	}
	index, node, used := location, leaf, 0
	for _, width := range merkleLayout(m.count) {
		if width == len(m.hashes) {
			if used != len(proof) {
				return false, true // the proof goes on past the stored row
			}
			return subtle.ConstantTimeCompare(m.hashes[index], node) == 1, false
		}
		if sibling := index ^ 1; sibling < width {
			if used == len(proof) {
				return false, true // needs a sibling the proof does not carry
			}
			h, _ := hashByName(algName)
			if index&1 == 1 {
				h.Write(proof[used])
				h.Write(node)
			} else {
				h.Write(node)
				h.Write(proof[used])
			}
			node = h.Sum(nil)
			used++
		}
		index /= 2
	}
	return false, true // no row of this tree has len(m.hashes) nodes
}

// bmffMerkleBoxes decodes every top-level C2PA merkle box in file order. ok is
// false when one of them does not decode or there are more than the leaf cap
// allows: the file then says something the verifier cannot read, which is
// malformed rather than a mismatch.
func bmffMerkleBoxes(data []byte, top []*bmffBox) ([]merkleBox, bool) {
	var out []merkleBox
	for _, b := range top {
		payload := c2paMerklePayload(data, b)
		if payload == nil {
			continue
		}
		mb, ok := decodeMerkleBox(payload)
		if !ok || len(out) >= maxMerkleLeaves {
			return nil, false
		}
		mb.box = b
		out = append(out, mb)
	}
	return out, true
}

// decodeMerkleBox decodes a merkle box's CBOR. The box is padded to a fixed
// size with zeros (§A.5.4.1.3), so only the first CBOR item is read and what
// follows it is ignored. uniqueId, localId and location are required and
// non-negative; hashes is optional but, when present, holds 1..maxMerkleProof
// non-empty byte strings.
func decodeMerkleBox(payload []byte) (merkleBox, bool) {
	var em map[string]any
	if _, err := decMode.UnmarshalFirst(payload, &em); err != nil {
		return merkleBox{}, false
	}
	var mb merkleBox
	var ok bool
	if mb.uniqueID, ok = toInt(em["uniqueId"]); !ok || mb.uniqueID < 0 {
		return merkleBox{}, false
	}
	if mb.localID, ok = toInt(em["localId"]); !ok || mb.localID < 0 {
		return merkleBox{}, false
	}
	if mb.location, ok = toInt(em["location"]); !ok || mb.location < 0 {
		return merkleBox{}, false
	}
	if raw, present := em["hashes"]; present && raw != nil {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 || len(list) > maxMerkleProof {
			return merkleBox{}, false
		}
		for _, hv := range list {
			b, ok := hv.([]byte)
			if !ok || len(b) == 0 {
				return merkleBox{}, false
			}
			mb.hashes = append(mb.hashes, b)
		}
	}
	return mb, true
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
		m := merkleMap{uniqueID: -1, localID: -1}
		if m.count, ok = toInt(em["count"]); !ok || m.count < 1 {
			return nil, false
		}
		if raw, present := em["uniqueId"]; present && raw != nil {
			if m.uniqueID, ok = toInt(raw); !ok || m.uniqueID < 0 {
				return nil, false
			}
		}
		if raw, present := em["localId"]; present && raw != nil {
			if m.localID, ok = toInt(raw); !ok || m.localID < 0 {
				return nil, false
			}
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
