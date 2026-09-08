package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
)

// Signing the flat single-file fragmented arrangement (spec §A.5.4 in one
// file): 'ftyp', 'moov', then 'moof'/'mdat' pairs, each chunk preceded by a
// C2PA merkle box, and the manifest in a C2PA uuid box after 'ftyp'. The
// verifier has always read this shape (bmffChunks, verifyMerkleChunks);
// SignFragmented writes the SPLIT arrangement, which c2pa-rs also writes, and
// this writes the flat one, for which there is no reference implementation.
//
// The one thing that makes it different from every other binding: the leaves
// are cut from the LAYOUT, not from the input. A merkle box's content is
// excluded from every hash, but its LENGTH moves the 'moof' and 'mdat' behind
// it, and those offsets are hashed as markers — so the file must be laid out
// with padded placeholder boxes before a single leaf can be hashed. That is
// what sign()'s phase (a) already does for the store, so digest() hashes the
// converged layout it is handed and keeps the tree.

// bmffFlatMerkleBinding is c2pa.hash.bmff.v3 with a merkle array over the
// chunks of ONE file. It is both the hard binding and its own embedder: the
// embedder must place a merkle box before every 'moof', which no other
// container needs and which the ordinary BMFF embedder refuses.
type bmffFlatMerkleBinding struct {
	alg      string
	count    int // 'moof' chunks, and so merkle boxes and leaves
	rowIndex int // the tree row the assertion stores
	padTo    int // every merkle box is padded to this one size
	// layers is the tree over the layout's chunks, set by digest and read by
	// embed for the proofs. While it is nil — through the layout passes — embed
	// writes proof-free boxes of the same padded length and payload writes a
	// row of zero hashes of the same encoded length.
	layers [][][]byte
}

// newFlatMerkleBinding recognises a flat fragmented BMFF file and returns the
// binding that signs it. It returns (nil, nil) for a file this arrangement
// does not describe — a plain MP4, or a bare fragment, both of which the
// ordinary BMFF path handles (the fragment by refusing it) — and an error only
// for a flat file this writer will not sign.
func newFlatMerkleBinding(ctx context.Context, alg string, asset []byte) (*bmffFlatMerkleBinding, error) {
	top := parseBMFFBoxes(ctx, asset)
	if err := ctx.Err(); err != nil {
		return nil, err // a cut-short parse decides nothing
	}
	chunks := bmffChunks(ctx, top)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(chunks) == 0 {
		return nil, nil // no 'moof', or the file begins with one: not this shape
	}
	moov := false
	for _, b := range top {
		if b.typ == "moov" {
			moov = true
			break
		}
		if b.typ == "moof" {
			break
		}
	}
	if !moov {
		// Fragments come before any 'moov': this is media without the
		// initialization segment that describes it, which SignFragmented signs
		// as a fragment. Let the ordinary path say so.
		return nil, nil
	}
	if len(chunks) > maxMerkleLeaves {
		return nil, fmt.Errorf("%w: %d fragment chunks exceed the %d-leaf cap", ErrUnsupportedContainer, len(chunks), maxMerkleLeaves)
	}
	for k, chunk := range chunks {
		mdat := false
		for _, b := range chunk {
			if b.typ == "mdat" {
				mdat = true
				break
			}
		}
		if !mdat {
			return nil, fmt.Errorf("%w: fragment chunk %d carries no 'mdat'", ErrUnsupportedContainer, k)
		}
	}
	rowIndex := merkleRowIndex(len(chunks))
	padTo, err := merkleBoxSize(alg, 1, 1, len(chunks), rowIndex)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedContainer, err)
	}
	return &bmffFlatMerkleBinding{alg: alg, count: len(chunks), rowIndex: rowIndex, padTo: padTo}, nil
}

func (*bmffFlatMerkleBinding) label() string         { return "c2pa.hash.bmff.v3" }
func (*bmffFlatMerkleBinding) matchCode() StatusCode { return StatusAssertionBMFFHashMatch }

func (b *bmffFlatMerkleBinding) embedder() embedder { return b }

// row is the tree row the assertion stores: zero hashes of the right shape
// while the layout is still converging, the real row afterwards. Both encode
// to the same length, which is what lets the store's length settle before the
// leaves exist.
func (b *bmffFlatMerkleBinding) row() ([][]byte, error) {
	if b.layers != nil {
		if b.rowIndex >= len(b.layers) {
			return nil, fmt.Errorf("c2pa: internal: tree has %d rows, row %d wanted", len(b.layers), b.rowIndex)
		}
		return b.layers[b.rowIndex], nil
	}
	h, ok := hashByName(b.alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %q", b.alg)
	}
	layout := merkleLayout(b.count)
	if b.rowIndex >= len(layout) {
		return nil, fmt.Errorf("c2pa: internal: a %d-leaf tree has %d rows, row %d wanted", b.count, len(layout), b.rowIndex)
	}
	zero := make([][]byte, layout[b.rowIndex])
	for i := range zero {
		zero[i] = make([]byte, h.Size())
	}
	return zero, nil
}

func (b *bmffFlatMerkleBinding) payload(_ []byteRange, digest []byte) ([]byte, error) {
	row, err := b.row()
	if err != nil {
		return nil, err
	}
	return bmffMerkleAssertion(b.alg, []merkleMapSpec{{
		uniqueID: 1, localID: 1, count: b.count, alg: b.alg, initHash: digest, hashes: row,
	}})
}

// digest cuts the leaves from the converged layout, keeps the tree for the
// proofs embed will write, and returns the initialization-segment hash the
// merkle map stores. It is only meaningful on a converged layout: the chunk
// offsets it hashes as markers are the output's own.
func (b *bmffFlatMerkleBinding) digest(ctx context.Context, layout []byte, _ []byteRange) ([]byte, error) {
	seg, err := bmffStandardSegment(ctx, layout)
	if err != nil {
		return nil, err
	}
	chunks := bmffChunks(ctx, seg.top)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(chunks) != b.count {
		return nil, fmt.Errorf("layout holds %d fragment chunks, %d were laid out", len(chunks), b.count)
	}
	h, ok := hashByName(b.alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %q", b.alg)
	}
	leaves := make([][]byte, len(chunks))
	for k, chunk := range chunks {
		h.Reset()
		// The verifier's own walk over just this chunk's boxes, the file's
		// exclusions still applied — so the placeholder merkle box that sits
		// at the end of the chunk, and the one before the chunk, are excluded
		// by "/uuid" and the leaf survives the proofs being written.
		if err := hashBMFFTopLevel(ctx, layout, chunk, seg.ranges, h); err != nil {
			return nil, err
		}
		leaves[k] = h.Sum(nil)
	}
	layers, err := merkleLayers(ctx, b.alg, leaves)
	if err != nil {
		return nil, err
	}
	b.layers = layers
	return bmffInitHash(ctx, seg, b.alg, chunks[0][0].start)
}

func (*bmffFlatMerkleBinding) compareRanges(ctx context.Context, layout []byte, _ []byteRange) ([]byteRange, error) {
	seg, err := bmffStandardSegment(ctx, layout)
	if err != nil {
		return nil, err
	}
	return seg.ranges, nil
}

func (*bmffFlatMerkleBinding) validatePrior(ctx context.Context, asset []byte) ValidationResult {
	return Validate(ctx, BMFF, bytes.NewReader(asset), WithOnlineRevocation(false))
}

func (*bmffFlatMerkleBinding) validateOutput(ctx context.Context, final []byte, opts []ValidateOption) ValidationResult {
	return Validate(ctx, BMFF, bytes.NewReader(final), opts...)
}

// embed writes the manifest box after 'ftyp' and one merkle box immediately
// before every 'moof' — where the split-file writer puts a fragment's box, and
// where bmffChunks and bmffMerkleBoxes expect to pair them positionally — with
// every existing C2PA box removed and the offsets the insertions moved
// repaired. Like the other BMFF embedders it declares no exclusion ranges: the
// binding excludes the C2PA boxes by the "/uuid" rule instead.
func (b *bmffFlatMerkleBinding) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	top := parseBMFFBoxes(ctx, asset)
	if err := ctx.Err(); err != nil {
		return nil, nil, err // a cut-short parse is not a malformed carrier
	}
	if len(top) == 0 {
		return nil, nil, fmt.Errorf("%w: no BMFF box structure", errCarrierMalformed)
	}
	if last := top[len(top)-1]; last.end != len(asset) {
		return nil, nil, fmt.Errorf("%w: %d trailing bytes outside any box", errCarrierMalformed, len(asset)-last.end)
	}
	var ftyp *bmffBox
	var moofs []*bmffBox
	var edits []edit
	var removed []byteRange
	for _, bx := range top {
		switch bx.typ {
		case "ftyp":
			if ftyp == nil {
				ftyp = bx
			}
		case "moof":
			moofs = append(moofs, bx)
		case "uuid":
			if bx.usertype != c2paBoxUUID {
				continue
			}
			edits = append(edits, edit{at: bx.start, remove: bx.end - bx.start})
			removed = append(removed, byteRange{start: bx.start, length: bx.end - bx.start})
		}
	}
	if ftyp == nil {
		return nil, nil, fmt.Errorf("%w: no 'ftyp' box", errCarrierMalformed)
	}
	if len(moofs) != b.count {
		return nil, nil, fmt.Errorf("%w: asset holds %d 'moof' boxes, %d were laid out", errCarrierMalformed, len(moofs), b.count)
	}
	manifest, err := c2paBoxBytes("manifest", store)
	if err != nil {
		return nil, nil, err
	}
	edits = append(edits, edit{at: ftyp.end, insert: manifest})
	for k, moof := range moofs {
		box, err := b.merkleBox(k)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errCarrierUnsupported, err)
		}
		edits = append(edits, edit{at: moof.start, insert: box})
	}
	out, _, remap, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	if err := bmffPatchFlatOffsets(ctx, asset, out, top, remap, removed); err != nil {
		return nil, nil, err
	}
	return out, nil, nil
}

// merkleBox is chunk k's box: proof-free through the layout passes, carrying
// the real proof once digest has built the tree, padded to one size either way.
func (b *bmffFlatMerkleBinding) merkleBox(k int) ([]byte, error) {
	spec := merkleBoxSpec{uniqueID: 1, localID: 1, location: k}
	if b.layers != nil {
		spec.hashes = merkleProof(b.layers, k, b.rowIndex)
	}
	return merkleBoxBytes(spec, b.padTo)
}

// bmffPatchFlatOffsets repairs the absolute file offsets a flat fragmented
// file holds, each in its own scope — which is the whole difference from
// bmffPatchOffsets, whose whole-tree walk would shift a 'saio' inside a 'traf'
// (relative to the track fragment's base) and corrupt CENC content:
//
//   - under 'moov': 'stco', 'co64', 'saio' and 'iloc', as for any BMFF file;
//   - in each 'moof': a 'tfhd' base_data_offset;
//   - each top-level 'sidx': first_offset and every referenced_size, since a
//     merkle box lands inside the subsegments they measure;
//   - under 'mfra': every 'tfra' moof_offset.
//
// old boxes and old bytes are what the sidx/tfhd/tfra patchers read (their
// values are re-anchored, so they need the removed spans), while the moov
// walk reads and writes out in place, as it does when signing a plain MP4.
func bmffPatchFlatOffsets(ctx context.Context, old, out []byte, top []*bmffBox, remap func(int) (int, bool), removed []byteRange) error {
	// anchor maps an old offset to its new one; one that pointed into a removed
	// C2PA box meant whatever followed that box (c2pa-rs's own output leaves
	// such pointers behind, and so does a re-sign of ours).
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
		if err := ctx.Err(); err != nil {
			return err
		}
		switch b.typ {
		case "sidx":
			if err := patchSidxFirstOffset(old, out, b, anchor, remap); err != nil {
				return err
			}
			if err := patchSidxSizes(ctx, old, out, b, anchor); err != nil {
				return err
			}
		case "moof":
			for _, traf := range b.children {
				if traf.typ != "traf" {
					continue
				}
				for _, c := range traf.children {
					if c.typ == "tfhd" {
						if err := patchTfhdBase(old, out, c, anchor, remap); err != nil {
							return err
						}
					}
				}
			}
		case "mfra":
			for _, c := range b.children {
				if c.typ == "tfra" {
					if err := patchTfra(ctx, old, out, c, anchor, remap); err != nil {
						return err
					}
				}
			}
		}
	}
	// The 'moov' subtree is patched from the OUT tree, where the boxes sit at
	// their new positions holding values in the old file's coordinates.
	for _, b := range parseBMFFBoxes(ctx, out) {
		if b.typ == "moov" {
			if err := bmffPatchOffsetsIn(ctx, out, []*bmffBox{b}, remap); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// sidxEntries locates a 'sidx' entry table: the offset of the first entry, how
// many there are, and the subsegment the table measures from (ISO 14496-12
// §8.16.3 — reference_ID and timescale, then earliest_presentation_time and
// first_offset, u32 each in version 0 and u64 in version 1, then a reserved
// u16 and reference_count).
func sidxEntries(data []byte, b *bmffBox) (at, count, first int, err error) {
	payload := b.start + b.headerLen
	if payload+4 > b.end {
		return 0, 0, 0, fmt.Errorf("%w: truncated 'sidx'", errCarrierMalformed)
	}
	fields, w := payload+16, 4
	if data[payload] != 0 {
		fields, w = payload+20, 8
	}
	if fields+w+4 > b.end {
		return 0, 0, 0, fmt.Errorf("%w: truncated 'sidx'", errCarrierMalformed)
	}
	var firstOffset uint64
	if w == 4 {
		firstOffset = uint64(binary.BigEndian.Uint32(data[fields:]))
	} else {
		firstOffset = binary.BigEndian.Uint64(data[fields:])
	}
	if firstOffset > uint64(len(data)) {
		return 0, 0, 0, fmt.Errorf("%w: 'sidx' first_offset points past the file", errCarrierMalformed)
	}
	count = int(binary.BigEndian.Uint16(data[fields+w+2:]))
	at = fields + w + 4
	if count > (b.end-at)/12 {
		return 0, 0, 0, fmt.Errorf("%w: 'sidx' declares %d references", errCarrierMalformed, count)
	}
	return at, count, int(firstOffset), nil //nolint:gosec // bounded above
}

// patchSidxSizes rewrites every referenced_size of a 'sidx' so the subsegments
// it measures still end where they did: a merkle box inserted before a 'moof'
// falls INSIDE the subsegment that begins at that 'moof', so the size grows by
// the box. Sizes are cumulative from the end of the box plus first_offset, and
// an entry with reference_type 1 measures another 'sidx' the same way. The top
// bit is the type and is preserved.
func patchSidxSizes(ctx context.Context, old, out []byte, b *bmffBox, anchor func(int) (int, bool)) error {
	at, count, first, err := sidxEntries(old, b)
	if err != nil {
		return err
	}
	cur := b.end + first
	for i := 0; i < count; i++ {
		if i&0xFFF == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		field := at + i*12
		v := binary.BigEndian.Uint32(old[field:])
		typeBit, size := v&0x80000000, int(v&0x7FFFFFFF)
		if size > len(old)-cur {
			return fmt.Errorf("%w: 'sidx' reference %d measures past the file", errCarrierMalformed, i)
		}
		start, ok := anchor(cur)
		if !ok {
			return fmt.Errorf("%w: 'sidx' reference %d starts inside a removed C2PA box", errCarrierMalformed, i)
		}
		end, ok := anchor(cur + size)
		if !ok {
			return fmt.Errorf("%w: 'sidx' reference %d ends inside a removed C2PA box", errCarrierMalformed, i)
		}
		if end < start || end-start > 0x7FFFFFFF {
			return fmt.Errorf("%w: 'sidx' referenced_size outgrows 31 bits", errCarrierUnsupported)
		}
		nat, ok := anchor(field)
		if !ok {
			return fmt.Errorf("%w: 'sidx' overlaps a removed box", errCarrierMalformed)
		}
		binary.BigEndian.PutUint32(out[nat:], typeBit|uint32(end-start)) //nolint:gosec // bounded above
		cur += size
	}
	return nil
}

// patchTfra rewrites the moof_offset of every entry of a 'tfra' — the track
// fragment random access box (ISO 14496-12 §8.8.10), the index a player seeks
// with, and absolute. The three trailing field widths are the low six bits of
// the u32 after track_ID: traf, trun and sample numbers are one to four bytes
// each. Version 1 stores time and moof_offset as u64, version 0 as u32.
// 'mfro', which records only the size of the enclosing 'mfra', is untouched
// because the insertions do not change it.
func patchTfra(ctx context.Context, old, out []byte, b *bmffBox, anchor, remap func(int) (int, bool)) error {
	payload := b.start + b.headerLen
	if payload+16 > b.end {
		return fmt.Errorf("%w: truncated 'tfra'", errCarrierMalformed)
	}
	version := old[payload]
	sizes := old[payload+11]
	trafW, trunW, sampleW := int((sizes>>4)&3)+1, int((sizes>>2)&3)+1, int(sizes&3)+1
	offW := 4
	if version != 0 {
		offW = 8
	}
	entrySize := 2*offW + trafW + trunW + sampleW
	count := int(binary.BigEndian.Uint32(old[payload+12:]))
	if count > (b.end-payload-16)/entrySize {
		return fmt.Errorf("%w: 'tfra' declares %d entries", errCarrierMalformed, count)
	}
	for i := 0; i < count; i++ {
		if i&0xFFF == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		field := payload + 16 + i*entrySize + offW
		var off uint64
		if offW == 4 {
			off = uint64(binary.BigEndian.Uint32(old[field:]))
		} else {
			off = binary.BigEndian.Uint64(old[field:])
		}
		if off > uint64(len(old)) {
			return fmt.Errorf("%w: 'tfra' moof_offset %d points past the file", errCarrierMalformed, off)
		}
		target, ok := anchor(int(off)) //nolint:gosec // bounded above
		if !ok {
			return fmt.Errorf("%w: 'tfra' moof_offset points into a removed C2PA box", errCarrierMalformed)
		}
		if offW == 4 && int64(target) > math.MaxUint32 {
			return fmt.Errorf("%w: 'tfra' moof_offset outgrows 32 bits", errCarrierUnsupported)
		}
		nat, ok := remap(field)
		if !ok {
			return fmt.Errorf("%w: 'tfra' overlaps a removed box", errCarrierMalformed)
		}
		putN(out, nat, offW, uint64(target))
	}
	return nil
}
