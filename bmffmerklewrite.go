package c2pa

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Authoring the fragmented BMFF binding (spec §A.5.4): the C2PA merkle box each
// fragment carries, the tree row the assertion stores, the proof each box
// holds, and the edit that puts a merkle box into a fragment. The verifier's
// own functions do the hashing (bmffHashDigest) and the tree (merkleLayers,
// merkleLayout), so what is written here is exactly what fragmented.go reads.

// merkleMaxProofs is c2pa-rs's core.merkle_tree_max_proofs default: the
// assertion stores tree row min(merkleMaxProofs, top) — the root for fewer
// than 2^5 fragments — so no fragment carries more than five proof hashes.
const merkleMaxProofs = 5

// merkleBoxSpec is what one fragment's C2PA merkle box says.
type merkleBoxSpec struct {
	uniqueID, localID, location int
	hashes                      [][]byte // the proof; empty when the stored row is the leaf row
}

// merkleRowIndex is the row of a count-leaf tree the assertion stores.
func merkleRowIndex(count int) int {
	return min(merkleMaxProofs, len(merkleLayout(count))-1)
}

// merkleProofLen is how many sibling hashes the leaf at location needs to
// climb to rowIndex: one per row below it where the node has a sibling — the
// unpaired last node of an odd row is carried up as is and needs none.
func merkleProofLen(count, location, rowIndex int) int {
	n, index := 0, location
	for row, width := range merkleLayout(count) {
		if row == rowIndex {
			break
		}
		if index^1 < width {
			n++
		}
		index /= 2
	}
	return n
}

// merkleProof is the proof for the leaf at location: the sibling at each row
// from the leaf row up to, not including, rowIndex — the same shape merkleProve
// consumes, derived from the same layers.
func merkleProof(layers [][][]byte, location, rowIndex int) [][]byte {
	var proof [][]byte
	index := location
	for row := 0; row < rowIndex && row < len(layers); row++ {
		if sib := index ^ 1; sib < len(layers[row]) {
			proof = append(proof, layers[row][sib])
		}
		index /= 2
	}
	return proof
}

// merkleBoxHeader is the fixed part of a merkle box: size, 'uuid', the C2PA
// usertype, FullBox version and flags, and "merkle" with its NUL. There is NO
// 8-byte merkle-offset field — only the store-carrying purposes have one
// (c2paMerklePayload reads the CBOR right after the NUL).
const merkleBoxHeader = 8 + 16 + 4 + len("merkle") + 1

// merkleBoxBytes frames spec as a C2PA merkle box of exactly padTo bytes, the
// CBOR followed by zero padding (§A.5.4.1.3). hashes is omitted when the proof
// is empty — both this verifier and c2pa-rs read an absent key as no proof.
// padTo <= 0 means no padding.
func merkleBoxBytes(spec merkleBoxSpec, padTo int) ([]byte, error) {
	m := map[string]any{"uniqueId": spec.uniqueID, "localId": spec.localID, "location": spec.location}
	if len(spec.hashes) > 0 {
		m["hashes"] = spec.hashes
	}
	raw, err := encMode.Marshal(m)
	if err != nil {
		return nil, err
	}
	size := merkleBoxHeader + len(raw)
	if padTo > 0 {
		if size > padTo {
			return nil, fmt.Errorf("merkle box needs %d bytes, more than the %d it is padded to", size, padTo)
		}
		size = padTo
	}
	if int64(size) > math.MaxUint32 {
		return nil, errors.New("merkle box would exceed 4 GiB")
	}
	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint32(out, uint32(size))
	out = append(out, "uuid"...)
	out = append(out, c2paBoxUUID[:]...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, "merkle"...)
	out = append(out, 0)
	out = append(out, raw...)
	return append(out, make([]byte, size-merkleBoxHeader-len(raw))...), nil
}

// cborUintLen is the encoded length of a non-negative CBOR integer.
func cborUintLen(v int) int {
	switch {
	case v < 24:
		return 1
	case v < 1<<8:
		return 2
	case v < 1<<16:
		return 3
	case v < 1<<32:
		return 5
	}
	return 9
}

// merkleBoxSize is the size every merkle box of a count-leaf tree is padded to:
// the largest box any location needs. The box's CONTENT is excluded from every
// hash, but its LENGTH moves the 'moof' and 'mdat' behind it, whose offsets
// are hashed as markers — so the layout of every fragment must be known before
// any leaf is hashed, and one size for all is what fixes it. The size varies
// with location (its integer widens at 24, 256 and 65536) and with the proof
// length (an unpaired node needs no sibling), so it is the maximum over all
// locations, computed from the CBOR encoding's arithmetic and checked once
// against a real encoding.
func merkleBoxSize(alg string, uniqueID, localID, count, rowIndex int) (int, error) {
	h, ok := hashByName(alg)
	if !ok {
		return 0, fmt.Errorf("unsupported hash algorithm %q", alg)
	}
	hashLen := h.Size()
	// map header + "uniqueId"/"localId"/"location" keys and values; a proof adds
	// the "hashes" key, an array header and one byte string per element.
	fixed := 1 + (1 + len("uniqueId") + cborUintLen(uniqueID)) + (1 + len("localId") + cborUintLen(localID))
	best, bestLoc := 0, 0
	for loc := 0; loc < count; loc++ {
		size := fixed + 1 + len("location") + cborUintLen(loc)
		if p := merkleProofLen(count, loc, rowIndex); p > 0 {
			size += 1 + len("hashes") + cborUintLen(p) + p*(cborUintLen(hashLen)+hashLen)
		}
		if size > best {
			best, bestLoc = size, loc
		}
	}
	// Prove the arithmetic on the location it picked.
	p := merkleProofLen(count, bestLoc, rowIndex)
	proof := make([][]byte, p)
	for i := range proof {
		proof[i] = make([]byte, hashLen)
	}
	real, err := merkleBoxBytes(merkleBoxSpec{uniqueID: uniqueID, localID: localID, location: bestLoc, hashes: proof}, 0)
	if err != nil {
		return 0, err
	}
	if len(real) != merkleBoxHeader+best {
		return 0, fmt.Errorf("c2pa: internal: merkle box size arithmetic says %d, encoding says %d", merkleBoxHeader+best, len(real))
	}
	return len(real), nil
}

// prepareFragment returns frag with box — a C2PA merkle box — inserted
// immediately before its 'moof', where c2pa-rs puts it, every earlier C2PA box
// removed, and the offsets the insertion moved repaired. It is a pure function
// of (frag, box): the signer calls it with a placeholder to learn a fragment's
// hash and again with the real box, and relies on the second output differing
// from the first only inside the box.
//
// A fragment carries one 'moof' and one 'mdat' (c2pa-rs's rule too); a file
// with 'ftyp' or 'moov' is an initialization segment, not a fragment. Offsets:
// a top-level 'sidx' before the insertion point has its first_offset
// re-anchored (c2pa-rs leaves it stale, pointing at the merkle box), and a
// 'tfhd' with base-data-offset-present is re-anchored too. Nothing else in a
// fragment is an absolute file offset — 'trun' data offsets, 'saio' and 'senc'
// are relative to the track fragment's base — so bmffPatchOffsets, which would
// shift a 'saio', is deliberately not run. A stale pointer INTO a removed C2PA
// box (c2pa-rs's own output) is taken to mean the media after it.
func prepareFragment(ctx context.Context, frag, box []byte) ([]byte, error) {
	top := parseBMFFBoxes(ctx, frag)
	if len(top) == 0 {
		return nil, fmt.Errorf("%w: no BMFF box structure", errCarrierMalformed)
	}
	if last := top[len(top)-1]; last.end != len(frag) {
		return nil, fmt.Errorf("%w: %d trailing bytes outside any box", errCarrierMalformed, len(frag)-last.end)
	}
	var moof *bmffBox
	moofs, mdats := 0, 0
	var edits []edit
	var removed []byteRange
	for _, b := range top {
		switch b.typ {
		case "ftyp", "moov":
			return nil, fmt.Errorf("%w: '%s' box: this is an initialization segment, not a fragment", errCarrierMalformed, b.typ)
		case "moof":
			moofs++
			if moof == nil {
				moof = b
			}
		case "mdat":
			mdats++
		case "uuid":
			if b.usertype == c2paBoxUUID {
				edits = append(edits, edit{at: b.start, remove: b.end - b.start})
				removed = append(removed, byteRange{start: b.start, length: b.end - b.start})
			}
		}
	}
	if moof == nil {
		return nil, fmt.Errorf("%w: no 'moof' box; is this the initialization segment?", errCarrierMalformed)
	}
	if moofs != 1 || mdats != 1 {
		return nil, fmt.Errorf("%w: fragment has %d 'moof' and %d 'mdat' boxes; one of each is signable", errCarrierUnsupported, moofs, mdats)
	}
	edits = append(edits, edit{at: moof.start, insert: box})
	out, _, remap, err := applyEdits(frag, edits)
	if err != nil {
		return nil, err
	}
	// anchor maps an old offset to its new one; one that pointed into a removed
	// C2PA box meant whatever followed that box.
	anchor := func(off int) (int, bool) {
		if n, ok := remap(off); ok {
			return n, true
		}
		for _, r := range removed {
			if off >= r.start && off < r.start+r.length {
				return remap(r.start + r.length)
			}
		}
		return 0, false
	}
	for _, b := range top {
		if b.typ == "sidx" && b.start < moof.start {
			if err := patchSidxFirstOffset(frag, out, b, anchor, remap); err != nil {
				return nil, err
			}
		}
	}
	for _, traf := range moof.children {
		if traf.typ != "traf" {
			continue
		}
		for _, c := range traf.children {
			if c.typ == "tfhd" {
				if err := patchTfhdBase(frag, out, c, anchor, remap); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

// patchSidxFirstOffset re-anchors a 'sidx' (ISO 14496-12 §8.16.3) whose
// first_offset counts from the end of the box to the first subsegment. After
// the FullBox version and flags come reference_ID and timescale (u32 each),
// then earliest_presentation_time and first_offset — both u32 in version 0
// (first_offset at payload+16), both u64 in version 1 (at payload+20).
func patchSidxFirstOffset(old, out []byte, b *bmffBox, anchor, remap func(int) (int, bool)) error {
	payload := b.start + b.headerLen
	if payload+4 > b.end {
		return fmt.Errorf("%w: truncated 'sidx'", errCarrierMalformed)
	}
	field, w := payload+16, 4
	if old[payload] != 0 {
		field, w = payload+20, 8
	}
	if field+w > b.end {
		return fmt.Errorf("%w: truncated 'sidx'", errCarrierMalformed)
	}
	var first uint64
	if w == 4 {
		first = uint64(binary.BigEndian.Uint32(old[field:]))
	} else {
		first = binary.BigEndian.Uint64(old[field:])
	}
	if first > uint64(len(old)-b.end) {
		return fmt.Errorf("%w: 'sidx' first_offset points past the fragment", errCarrierMalformed)
	}
	target, ok := anchor(b.end + int(first))
	if !ok {
		return fmt.Errorf("%w: 'sidx' first_offset points into a removed C2PA box", errCarrierMalformed)
	}
	// The box itself did not move (it precedes the insertion): its end in the
	// new file is the mapped last byte plus one.
	newEnd, ok := remap(b.end - 1)
	if !ok {
		return fmt.Errorf("%w: 'sidx' overlaps a removed box", errCarrierMalformed)
	}
	newEnd++
	if target < newEnd {
		return fmt.Errorf("%w: 'sidx' first_offset would be negative", errCarrierMalformed)
	}
	newFirst := uint64(target - newEnd)
	if w == 4 && newFirst > math.MaxUint32 {
		return fmt.Errorf("%w: 'sidx' first_offset overflows 32 bits", errCarrierUnsupported)
	}
	at, _ := remap(field)
	putN(out, at, w, newFirst)
	return nil
}

// patchTfhdBase re-anchors a 'tfhd' base_data_offset (flag 0x000001): a u64
// after version/flags and track_ID, and an absolute offset within the fragment.
func patchTfhdBase(old, out []byte, b *bmffBox, anchor, remap func(int) (int, bool)) error {
	payload := b.start + b.headerLen
	if payload+8 > b.end {
		return fmt.Errorf("%w: truncated 'tfhd'", errCarrierMalformed)
	}
	flags := uint32(old[payload+1])<<16 | uint32(old[payload+2])<<8 | uint32(old[payload+3])
	if flags&1 == 0 {
		return nil
	}
	field := payload + 8
	if field+8 > b.end {
		return fmt.Errorf("%w: truncated 'tfhd'", errCarrierMalformed)
	}
	base := binary.BigEndian.Uint64(old[field:])
	if base > uint64(len(old)) {
		return fmt.Errorf("%w: 'tfhd' base_data_offset points past the fragment", errCarrierMalformed)
	}
	target, ok := anchor(int(base))
	if !ok {
		return fmt.Errorf("%w: 'tfhd' base_data_offset points into a removed C2PA box", errCarrierMalformed)
	}
	at, ok := remap(field)
	if !ok {
		return fmt.Errorf("%w: 'tfhd' overlaps a removed box", errCarrierMalformed)
	}
	putN(out, at, 8, uint64(target))
	return nil
}
