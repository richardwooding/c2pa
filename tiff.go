package c2pa

import (
	"context"
	"encoding/binary"
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
