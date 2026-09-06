package c2pa

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
)

const (
	// tiffC2PATag is the private IFD tag carrying the manifest store.
	tiffC2PATag = 0xCD41
	// tiffUndefined is TIFF field type 7 (UNDEFINED), one byte per element, which
	// is what the store is written as.
	tiffUndefined = 7
	// maxTIFFIFDHops bounds the IFD chain. A next-IFD offset may point anywhere,
	// including backwards, so the chain can be made circular.
	maxTIFFIFDHops = 64
	// maxTIFFEntries bounds one IFD's entry walk. BigTIFF declares the count in
	// eight bytes, so an adversarial file can claim quadrillions; a real IFD has
	// dozens.
	maxTIFFEntries = 1 << 16
)

// tiffJUMBF returns the raw JUMBF manifest store from a TIFF or DNG asset, or
// nil when there is none. DNG is TIFF, so both are the same walk; BigTIFF is
// the same walk again at wider field widths.
//
// The store lives in IFD tag 0xCD41 with field type UNDEFINED. Every IFD in the
// chain is checked, since a producer may place it on a later page. Classic TIFF
// (magic 42: 4-byte offsets, 2-byte counts, 12-byte entries) and BigTIFF
// (magic 43: 8-byte offsets, 8-byte counts, 20-byte entries) are the same walk
// at different field widths.
func tiffJUMBF(ctx context.Context, data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	var bo binary.ByteOrder
	switch string(data[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return nil
	}

	// The two layouts, as field widths. Three DIFFERENT widths are in play and
	// classic TIFF does not share them: the IFD's entry count (2 vs 8), each
	// entry's element count (4 vs 8), and every offset (4 vs 8). An entry is
	// tag(2) type(2) count(entryCountW) value(offW).
	var offW, ifdCountW, entryCountW, entryLen, firstIFD int
	switch bo.Uint16(data[2:4]) {
	case 42:
		offW, ifdCountW, entryCountW, entryLen, firstIFD = 4, 2, 4, 12, 4
	case 43:
		// BigTIFF: two more header fields — the offset size (always 8) and a
		// reserved zero — precede the first-IFD pointer.
		if len(data) < 16 || bo.Uint16(data[4:6]) != 8 || bo.Uint16(data[6:8]) != 0 {
			return nil
		}
		offW, ifdCountW, entryCountW, entryLen, firstIFD = 8, 8, 8, 20, 8
	default:
		return nil
	}
	readW := func(b []byte, w int) int64 {
		switch w {
		case 2:
			return int64(bo.Uint16(b))
		case 4:
			return int64(bo.Uint32(b))
		default:
			return int64(bo.Uint64(b)) //nolint:gosec // bounded against len(data) below
		}
	}

	if firstIFD+offW > len(data) {
		return nil
	}
	next := readW(data[firstIFD:firstIFD+offW], offW)
	for hop := 0; hop < maxTIFFIFDHops && next > 0; hop++ {
		if ctx.Err() != nil {
			return nil
		}
		// Subtraction form: next comes from an attacker's eight bytes, so
		// next+ifdCountW can wrap past MaxInt64 and slip a huge offset through
		// an addition-form bound — the fuzzer found exactly that, a bare
		// BigTIFF header pointing its first IFD at MaxInt64-4.
		if next < 0 || next > int64(len(data))-int64(ifdCountW) {
			return nil
		}
		ifd := int(next)
		count := readW(data[ifd:ifd+ifdCountW], ifdCountW)
		if count < 0 || count > maxTIFFEntries {
			return nil
		}
		entries := int64(ifd + ifdCountW)
		// The entries, then the next-IFD pointer, must all be present.
		if entries+count*int64(entryLen)+int64(offW) > int64(len(data)) {
			return nil
		}
		for i := int64(0); i < count; i++ {
			e := int(entries + i*int64(entryLen))
			if int(bo.Uint16(data[e:e+2])) != tiffC2PATag {
				continue
			}
			if int(bo.Uint16(data[e+2:e+4])) != tiffUndefined {
				continue // the tag number alone does not make it a manifest store
			}
			size := readW(data[e+4:e+4+entryCountW], entryCountW)
			if size <= 0 {
				return nil
			}
			valAt := e + 4 + entryCountW
			// Up to offW bytes live in the value field itself; more is an offset.
			if size <= int64(offW) {
				return data[valAt : valAt+int(size)]
			}
			off := readW(data[valAt:valAt+offW], offW)
			if off < 8 || off+size < off || off+size > int64(len(data)) {
				return nil
			}
			return data[off : off+size]
		}
		nextAt := entries + count*int64(entryLen)
		next = readW(data[nextAt:nextAt+int64(offW)], offW)
	}
	return nil
}

// --- writing ------------------------------------------------------------------

// tiffEmbedder writes the store as tag 0xCD41 (type UNDEFINED) in a NEW last
// IFD that holds nothing else — spec §A.3.5: "the C2PA Manifest Store shall be
// the only box present in the last IFD, the IFD immediately preceding the end
// of the file" — appended after the existing bytes and linked from the
// previous last IFD. Any existing 0xCD41 entry is neutralised first.
type tiffEmbedder struct{}

// tiffLayout is the field-width table for classic TIFF (42) or BigTIFF (43).
type tiffLayout struct {
	bo                                                 binary.ByteOrder
	offW, ifdCountW, entryCountW, entryLen, firstIFDAt int
}

// tiffIFD is one IFD: where it starts, how many entries, where they begin,
// where its next-IFD pointer lives and what that pointer says.
type tiffIFD struct {
	at, count, entriesAt, nextPtrAt int
	next                            int64
}

func parseTIFFLayout(data []byte) (tiffLayout, error) {
	if len(data) < 8 {
		return tiffLayout{}, fmt.Errorf("%w: not a TIFF", errCarrierMalformed)
	}
	var l tiffLayout
	switch string(data[:2]) {
	case "II":
		l.bo = binary.LittleEndian
	case "MM":
		l.bo = binary.BigEndian
	default:
		return tiffLayout{}, fmt.Errorf("%w: not a TIFF", errCarrierMalformed)
	}
	switch l.bo.Uint16(data[2:4]) {
	case 42:
		l.offW, l.ifdCountW, l.entryCountW, l.entryLen, l.firstIFDAt = 4, 2, 4, 12, 4
	case 43:
		if len(data) < 16 || l.bo.Uint16(data[4:6]) != 8 || l.bo.Uint16(data[6:8]) != 0 {
			return tiffLayout{}, fmt.Errorf("%w: BigTIFF header is malformed", errCarrierMalformed)
		}
		l.offW, l.ifdCountW, l.entryCountW, l.entryLen, l.firstIFDAt = 8, 8, 8, 20, 8
	default:
		return tiffLayout{}, fmt.Errorf("%w: not a TIFF", errCarrierMalformed)
	}
	return l, nil
}

func (l tiffLayout) readW(b []byte, w int) int64 {
	switch w {
	case 2:
		return int64(l.bo.Uint16(b))
	case 4:
		return int64(l.bo.Uint32(b))
	default:
		return int64(l.bo.Uint64(b)) //nolint:gosec // every use is bounds-checked against len(data)
	}
}

func (l tiffLayout) putW(b []byte, w int, v int64) {
	switch w {
	case 2:
		l.bo.PutUint16(b, uint16(v))
	case 4:
		l.bo.PutUint32(b, uint32(v))
	default:
		l.bo.PutUint64(b, uint64(v))
	}
}

// ifds walks the IFD chain, refusing a chain the writer cannot reason about:
// an IFD out of bounds, an entry table that overruns the file, or a cycle.
func (l tiffLayout) ifds(ctx context.Context, data []byte) ([]tiffIFD, error) {
	next := l.readW(data[l.firstIFDAt:l.firstIFDAt+l.offW], l.offW)
	seen := map[int64]bool{}
	var out []tiffIFD
	for hop := 0; next > 0; hop++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if hop >= maxTIFFIFDHops || seen[next] {
			return nil, fmt.Errorf("%w: TIFF IFD chain is circular or too long", errCarrierMalformed)
		}
		seen[next] = true
		if next > int64(len(data))-int64(l.ifdCountW) {
			return nil, fmt.Errorf("%w: TIFF IFD at %d is outside the file", errCarrierMalformed, next)
		}
		ifd := tiffIFD{at: int(next)}
		count := l.readW(data[ifd.at:ifd.at+l.ifdCountW], l.ifdCountW)
		if count < 0 || count > maxTIFFEntries {
			return nil, fmt.Errorf("%w: TIFF IFD at %d declares %d entries", errCarrierMalformed, ifd.at, count)
		}
		ifd.count = int(count)
		ifd.entriesAt = ifd.at + l.ifdCountW
		ifd.nextPtrAt = ifd.entriesAt + ifd.count*l.entryLen
		if int64(ifd.nextPtrAt)+int64(l.offW) > int64(len(data)) {
			return nil, fmt.Errorf("%w: TIFF IFD at %d overruns the file", errCarrierMalformed, ifd.at)
		}
		ifd.next = l.readW(data[ifd.nextPtrAt:ifd.nextPtrAt+l.offW], l.offW)
		out = append(out, ifd)
		next = ifd.next
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: TIFF has no IFD", errCarrierMalformed)
	}
	return out, nil
}

func (tiffEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	l, err := parseTIFFLayout(asset)
	if err != nil {
		return nil, nil, err
	}
	chain, err := l.ifds(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	out := append([]byte(nil), asset...)

	// Neutralise every existing 0xCD41 entry in place. An IFD that holds only
	// that entry and has a predecessor is unlinked (case A); an entry sharing
	// an IFD with others — c2pa-rs's IFD0 placement — is removed and the
	// entries after it shift down (case B). Nothing else moves. When the
	// unlinked IFD and its store are exactly this writer's own trailing layout,
	// they are truncated away so repeated re-signs do not accumulate.
	truncateAt := -1
	for i := range chain {
		ifd := &chain[i]
		for e := 0; e < ifd.count; {
			at := ifd.entriesAt + e*l.entryLen
			if int(l.bo.Uint16(out[at:at+2])) != tiffC2PATag {
				e++
				continue
			}
			if ifd.count == 1 && i > 0 {
				prev := &chain[i-1]
				l.putW(out[prev.nextPtrAt:prev.nextPtrAt+l.offW], l.offW, ifd.next)
				prev.next = ifd.next
				if ifd.next == 0 && tiffOwnTrailer(l, out, *ifd) {
					truncateAt = ifd.at
				}
				chain = chain[:i]
				goto appended
			}
			// Case B: shift the following entries and the next pointer down.
			copy(out[at:], out[at+l.entryLen:ifd.nextPtrAt+l.offW])
			for z := ifd.nextPtrAt + l.offW - l.entryLen; z < ifd.nextPtrAt+l.offW; z++ {
				out[z] = 0
			}
			ifd.count--
			ifd.nextPtrAt -= l.entryLen
			l.putW(out[ifd.at:ifd.at+l.ifdCountW], l.ifdCountW, int64(ifd.count))
		}
	}
appended:
	if truncateAt >= 0 {
		out = out[:truncateAt]
	}
	if len(out)%2 == 1 {
		out = append(out, 0) // IFDs are word-aligned
	}
	appendAt := len(out)
	ifdLen := l.ifdCountW + l.entryLen + l.offW
	storeAt := appendAt + ifdLen
	if l.offW == 4 && int64(storeAt)+int64(len(store)) > math.MaxUint32 {
		return nil, nil, fmt.Errorf("%w: classic TIFF cannot address the store past 4 GiB", errCarrierUnsupported)
	}
	ifd := make([]byte, ifdLen)
	l.putW(ifd[0:l.ifdCountW], l.ifdCountW, 1)
	entry := ifd[l.ifdCountW:]
	l.bo.PutUint16(entry[0:2], tiffC2PATag)
	l.bo.PutUint16(entry[2:4], tiffUndefined)
	l.putW(entry[4:4+l.entryCountW], l.entryCountW, int64(len(store)))
	valueAt := appendAt + l.ifdCountW + 4 + l.entryCountW
	var excl []byteRange
	if len(store) <= l.offW {
		copy(entry[4+l.entryCountW:], store)
		excl = []byteRange{{start: appendAt + l.ifdCountW + 4, length: l.entryCountW}, {start: valueAt, length: len(store)}}
		out = append(out, ifd...)
	} else {
		l.putW(entry[4+l.entryCountW:4+l.entryCountW+l.offW], l.offW, int64(storeAt))
		excl = []byteRange{{start: appendAt + l.ifdCountW + 4, length: l.entryCountW}, {start: storeAt, length: len(store)}}
		out = append(out, ifd...)
		out = append(out, store...)
	}
	last := chain[len(chain)-1]
	l.putW(out[last.nextPtrAt:last.nextPtrAt+l.offW], l.offW, int64(appendAt))
	return out, excl, nil
}

// tiffOwnTrailer reports whether ifd is this writer's own trailing layout: a
// one-entry 0xCD41 IFD whose store follows it to the end of the file.
func tiffOwnTrailer(l tiffLayout, data []byte, ifd tiffIFD) bool {
	if ifd.count != 1 || ifd.next != 0 {
		return false
	}
	e := ifd.entriesAt
	if int(l.bo.Uint16(data[e+2:e+4])) != tiffUndefined {
		return false
	}
	size := l.readW(data[e+4:e+4+l.entryCountW], l.entryCountW)
	valAt := e + 4 + l.entryCountW
	if size <= int64(l.offW) {
		return ifd.nextPtrAt+l.offW == len(data)
	}
	off := l.readW(data[valAt:valAt+l.offW], l.offW)
	return off == int64(ifd.nextPtrAt+l.offW) && off+size == int64(len(data))
}
