package c2pa

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Writing a manifest store into a BMFF asset (spec §A.5). The store goes into
// a C2PA uuid box immediately after 'ftyp' — before 'moov' and 'mdat', as
// §A.5.3 requires — which moves every byte after it. ISOBMFF stores absolute
// file offsets in several boxes ('stco', 'co64', 'saio', 'iloc'), so each is
// rewritten by the same displacement, and the test suite checks that every
// offset still addresses the bytes it did before: no validator hashes sample
// offsets, so nothing else would notice a mistake here.

// errFragmented marks a BMFF asset whose binding would be a Merkle tree rather
// than a flat hash: a fragmented file, or one already carrying merkle boxes.
var errFragmented = errors.New("the asset is fragmented; an initialization segment and its fragments are signed with SignFragmented")

// bmffEmbedder writes the C2PA uuid box for a non-fragmented BMFF asset.
type bmffEmbedder struct{}

// c2paBoxBytes frames store as the ContentProvenanceBox (§A.5.1): a 32-bit
// size — the standard "/uuid" exclusion's data predicate looks for the usertype
// at offset 8, which a largesize header would break — then the C2PA usertype,
// FullBox version 0 and flags 0, the NUL-terminated purpose, the 8-byte offset
// of the first merkle box (zero: there are none), and the raw store.
func c2paBoxBytes(purpose string, store []byte) ([]byte, error) {
	size := 8 + 16 + 4 + len(purpose) + 1 + 8 + len(store)
	if int64(size) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: C2PA box would exceed 4 GiB", errCarrierUnsupported)
	}
	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint32(out, uint32(size))
	out = append(out, "uuid"...)
	out = append(out, c2paBoxUUID[:]...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, purpose...)
	out = append(out, 0)
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 0)
	return append(out, store...), nil
}

func (bmffEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	top := parseBMFFBoxes(ctx, asset)
	if len(top) == 0 {
		return nil, nil, fmt.Errorf("%w: no BMFF box structure", errCarrierMalformed)
	}
	if last := top[len(top)-1]; last.end != len(asset) {
		return nil, nil, fmt.Errorf("%w: %d trailing bytes outside any box", errCarrierMalformed, len(asset)-last.end)
	}
	var ftyp *bmffBox
	var edits []edit
	for _, b := range top {
		switch b.typ {
		case "ftyp":
			if ftyp == nil {
				ftyp = b
			}
		case "moof", "mfra", "sidx", "styp":
			return nil, nil, fmt.Errorf("%w: top-level '%s' box", errFragmented, b.typ)
		case "uuid":
			if b.usertype != c2paBoxUUID {
				continue
			}
			if purpose, _, ok := c2paBoxPurpose(asset, b); ok && purpose == "merkle" {
				return nil, nil, fmt.Errorf("%w: merkle box present", errFragmented)
			}
			edits = append(edits, edit{at: b.start, remove: b.end - b.start})
		}
	}
	if ftyp == nil {
		return nil, nil, fmt.Errorf("%w: no 'ftyp' box", errCarrierMalformed)
	}
	if ftyp.end >= len(asset) {
		return nil, nil, fmt.Errorf("%w: nothing follows 'ftyp'", errCarrierMalformed)
	}
	box, err := c2paBoxBytes("manifest", store)
	if err != nil {
		return nil, nil, err
	}
	edits = append(edits, edit{at: ftyp.end, insert: box})
	out, _, remap, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	if err := bmffPatchOffsets(ctx, out, remap); err != nil {
		return nil, nil, err
	}
	return out, nil, nil
}

// bmffPatchOffsets rewrites every absolute file offset in out — whose boxes now
// sit at their new positions but still hold values in the old file's
// coordinates — through remap. A value that pointed into a removed C2PA box
// has nothing to point at any more, which is malformed input rather than
// something to guess about.
func bmffPatchOffsets(ctx context.Context, out []byte, remap func(int) (int, bool)) error {
	var walk func(boxes []*bmffBox) error
	walk = func(boxes []*bmffBox) error {
		for _, b := range boxes {
			if err := ctx.Err(); err != nil {
				return err
			}
			var err error
			switch b.typ {
			case "stco":
				err = patchChunkOffsets(out, b, 4, remap)
			case "co64":
				err = patchChunkOffsets(out, b, 8, remap)
			case "saio":
				err = patchSaio(out, b, remap)
			case "iloc":
				err = patchIloc(out, b, remap)
			}
			if err != nil {
				return err
			}
			if err := walk(b.children); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(parseBMFFBoxes(ctx, out))
}

// bmffOffsetField rewrites one w-byte big-endian offset in place.
func bmffOffsetField(out []byte, at, w int, remap func(int) (int, bool), what string) error {
	var v uint64
	if w == 4 {
		v = uint64(binary.BigEndian.Uint32(out[at:]))
	} else {
		v = binary.BigEndian.Uint64(out[at:])
	}
	if v > math.MaxInt64 {
		return fmt.Errorf("%w: %s offset %d is not addressable", errCarrierMalformed, what, v)
	}
	nv, ok := remap(int(v)) //nolint:gosec // bounded above
	if !ok {
		return fmt.Errorf("%w: %s offset %d points into a removed C2PA box", errCarrierMalformed, what, v)
	}
	if w == 4 {
		if int64(nv) > math.MaxUint32 {
			return fmt.Errorf("%w: %s offset outgrows 32 bits; stco→co64 conversion is out of scope", errCarrierUnsupported, what)
		}
		binary.BigEndian.PutUint32(out[at:], uint32(nv))
	} else {
		binary.BigEndian.PutUint64(out[at:], uint64(nv))
	}
	return nil
}

// patchChunkOffsets handles 'stco' (w = 4) and 'co64' (w = 8): a FullBox
// header, an entry count, then the chunk offsets.
func patchChunkOffsets(out []byte, b *bmffBox, w int, remap func(int) (int, bool)) error {
	p := b.start + b.headerLen
	if p+8 > b.end {
		return fmt.Errorf("%w: truncated '%s'", errCarrierMalformed, b.typ)
	}
	count := int(binary.BigEndian.Uint32(out[p+4 : p+8]))
	if count < 0 || count > (b.end-p-8)/w {
		return fmt.Errorf("%w: '%s' declares %d entries", errCarrierMalformed, b.typ, count)
	}
	for i := 0; i < count; i++ {
		if err := bmffOffsetField(out, p+8+i*w, w, remap, b.typ); err != nil {
			return err
		}
	}
	return nil
}

// patchSaio handles the sample auxiliary information offsets of encrypted
// (CENC) content: version 0 has 32-bit offsets, version 1 64-bit; flag bit 0
// adds aux_info_type and its parameter before the count.
func patchSaio(out []byte, b *bmffBox, remap func(int) (int, bool)) error {
	p := b.start + b.headerLen
	if p+4 > b.end {
		return fmt.Errorf("%w: truncated 'saio'", errCarrierMalformed)
	}
	version := out[p]
	flags := uint32(out[p+1])<<16 | uint32(out[p+2])<<8 | uint32(out[p+3])
	q := p + 4
	if flags&1 != 0 {
		q += 8
	}
	if q+4 > b.end {
		return fmt.Errorf("%w: truncated 'saio'", errCarrierMalformed)
	}
	w := 4
	if version != 0 {
		w = 8
	}
	count := int(binary.BigEndian.Uint32(out[q : q+4]))
	if count < 0 || count > (b.end-q-4)/w {
		return fmt.Errorf("%w: 'saio' declares %d entries", errCarrierMalformed, count)
	}
	for i := 0; i < count; i++ {
		if err := bmffOffsetField(out, q+4+i*w, w, remap, "saio"); err != nil {
			return err
		}
	}
	return nil
}

// patchIloc handles the item location box of HEIF/AVIF (versions 0, 1 and 2).
// Items stored in another file (data_reference_index != 0) or relative to
// 'idat' (construction_method != 0) carry no file offsets and are skipped.
// When a base_offset is present and every extent's absolute position moves by
// the same amount, the base alone is patched; otherwise each extent_offset is.
func patchIloc(out []byte, b *bmffBox, remap func(int) (int, bool)) error {
	p := b.start + b.headerLen
	if p+6 > b.end {
		return fmt.Errorf("%w: truncated 'iloc'", errCarrierMalformed)
	}
	version := out[p]
	q := p + 4
	offsetSize, lengthSize := int(out[q]>>4), int(out[q]&0x0F)
	baseSize := int(out[q+1] >> 4)
	indexSize := 0
	if version >= 1 {
		indexSize = int(out[q+1] & 0x0F)
	}
	for _, sz := range []int{offsetSize, lengthSize, baseSize, indexSize} {
		if sz != 0 && sz != 4 && sz != 8 {
			return fmt.Errorf("%w: 'iloc' field size %d", errCarrierMalformed, sz)
		}
	}
	q += 2
	read := func(at, w int) (uint64, error) {
		if at+w > b.end {
			return 0, fmt.Errorf("%w: truncated 'iloc'", errCarrierMalformed)
		}
		switch w {
		case 0:
			return 0, nil
		case 2:
			return uint64(binary.BigEndian.Uint16(out[at:])), nil
		case 4:
			return uint64(binary.BigEndian.Uint32(out[at:])), nil
		default:
			return binary.BigEndian.Uint64(out[at:]), nil
		}
	}
	countW := 2
	if version >= 2 {
		countW = 4
	}
	itemCount, err := read(q, countW)
	if err != nil {
		return err
	}
	q += countW
	for i := uint64(0); i < itemCount; i++ {
		q += countW // item_ID
		constructionMethod := uint64(0)
		if version >= 1 {
			if constructionMethod, err = read(q, 2); err != nil {
				return err
			}
			constructionMethod &= 0x0F
			q += 2
		}
		dataRef, err := read(q, 2)
		if err != nil {
			return err
		}
		q += 2
		baseAt := q
		base, err := read(q, baseSize)
		if err != nil {
			return err
		}
		q += baseSize
		extentCount, err := read(q, 2)
		if err != nil {
			return err
		}
		q += 2
		type extent struct{ offAt int }
		var extents []extent
		for e := uint64(0); e < extentCount; e++ {
			q += indexSize
			extents = append(extents, extent{offAt: q})
			q += offsetSize + lengthSize
		}
		if q > b.end {
			return fmt.Errorf("%w: truncated 'iloc'", errCarrierMalformed)
		}
		if dataRef != 0 || constructionMethod != 0 || (baseSize == 0 && offsetSize == 0) {
			continue
		}
		if base > math.MaxInt64 {
			return fmt.Errorf("%w: 'iloc' base offset not addressable", errCarrierMalformed)
		}
		// Absolute position of every extent, before and after.
		type move struct{ extOff, abs, newAbs int }
		var moves []move
		for _, ex := range extents {
			extOff, err := read(ex.offAt, offsetSize)
			if err != nil {
				return err
			}
			abs := int(base) + int(extOff) //nolint:gosec // bounded above
			nabs, ok := remap(abs)
			if !ok {
				return fmt.Errorf("%w: 'iloc' extent points into a removed C2PA box", errCarrierMalformed)
			}
			moves = append(moves, move{extOff: ex.offAt, abs: abs, newAbs: nabs})
		}
		if len(moves) == 0 {
			continue
		}
		uniform := baseSize > 0 && base != 0
		for _, m := range moves {
			if m.newAbs-m.abs != moves[0].newAbs-moves[0].abs {
				uniform = false
			}
		}
		if uniform {
			nb := int(base) + moves[0].newAbs - moves[0].abs
			if baseSize == 4 && int64(nb) > math.MaxUint32 {
				return fmt.Errorf("%w: 'iloc' base offset outgrows 32 bits", errCarrierUnsupported)
			}
			putN(out, baseAt, baseSize, uint64(nb))
			continue
		}
		if offsetSize == 0 {
			return fmt.Errorf("%w: 'iloc' extents need moving but have no offset field", errCarrierMalformed)
		}
		for _, m := range moves {
			nv := m.newAbs - int(base) //nolint:gosec // base ≤ MaxInt64 checked above
			if nv < 0 || (offsetSize == 4 && int64(nv) > math.MaxUint32) {
				return fmt.Errorf("%w: 'iloc' extent offset out of range", errCarrierUnsupported)
			}
			putN(out, m.extOff, offsetSize, uint64(nv))
		}
	}
	return nil
}

// putN writes v as a w-byte big-endian integer (w is 4 or 8).
func putN(out []byte, at, w int, v uint64) {
	if w == 4 {
		binary.BigEndian.PutUint32(out[at:], uint32(v))
	} else {
		binary.BigEndian.PutUint64(out[at:], v)
	}
}
