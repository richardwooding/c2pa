package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
)

// BMFF container support: locating the C2PA manifest inside an ISO Base Media
// File Format file (MP4, MOV, M4A, HEIC, HEIF, AVIF) and parsing the box tree
// the c2pa.hash.bmff verifier needs. Per C2PA spec §A.5 the manifest store
// lives in a top-level `uuid` box with the extended type below, laid out as a
// FullBox (1-byte version + 3-byte flags), a NUL-terminated purpose string
// ("manifest", "original", "update", or "merkle"), an 8-byte big-endian offset
// to the first merkle-purpose box (for the non-merkle purposes), and then the
// raw JUMBF manifest store, optionally zero-padded.

// c2paBoxUUID is the extended type of the C2PA ContentProvenanceBox
// (spec §A.5.1.1).
var c2paBoxUUID = [16]byte{
	0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C,
	0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
}

// maxBMFFDepth caps box-tree recursion. Real files nest ~6 deep
// (moov/trak/mdia/minf/stbl/stco); adversarial nesting of container boxes
// (each consuming only an 8-byte header) could otherwise recurse
// ~len(data)/8 levels. Same rationale as maxJUMBFDepth.
const maxBMFFDepth = 32

// bmffBox is one parsed box. start/end/headerLen are absolute offsets into the
// asset bytes, so the hash verifier can sub-slice the original file — never
// re-encode.
type bmffBox struct {
	typ       string   // 4-character box type
	start     int      // offset of the box's size field
	end       int      // start + size (size==0 → end of data)
	headerLen int      // size+type (8), +8 for largesize, +16 for uuid usertype
	usertype  [16]byte // extended type; uuid boxes only
	children  []*bmffBox
}

// bmffContainers are the pure container boxes the parser descends into: their
// payload is a sequence of child boxes with no extra fields. Count-prefixed
// pseudo-containers (iinf, stsd, dref, ipro, …) are deliberately treated as
// leaves — walking their payload as a box list would misparse the count field.
// Real-world c2pa.hash.bmff exclusions target top-level boxes (/uuid, /ftyp,
// /mfra), so exclusions addressing children of those pseudo-containers are the
// documented limitation.
var bmffContainers = map[string]bool{
	"moov": true, "trak": true, "edts": true, "mdia": true, "minf": true,
	"dinf": true, "stbl": true, "mvex": true, "moof": true, "traf": true,
	"mfra": true, "udta": true, "iprp": true, "ipco": true, "sinf": true,
	"schi": true,
}

// bmffFullBoxContainers are container boxes that are also FullBoxes: their
// children start after a 4-byte version/flags field. `meta` (HEIC/HEIF
// metadata) is the one that matters for path matching.
var bmffFullBoxContainers = map[string]bool{
	"meta": true,
}

// parseBMFFBoxes parses the top-level box tree of an ISOBMFF asset.
// Best-effort and never panics: malformed sizes end the affected level.
func parseBMFFBoxes(ctx context.Context, data []byte) []*bmffBox {
	return parseBMFFLevel(ctx, data, 0, len(data), 0)
}

// parseBMFFLevel parses the sequence of sibling boxes in data[start:end],
// recursing into known container boxes up to maxBMFFDepth.
func parseBMFFLevel(ctx context.Context, data []byte, start, end, depth int) []*bmffBox {
	if depth > maxBMFFDepth || start < 0 || end > len(data) {
		return nil
	}
	var out []*bmffBox
	i := start
	for i+8 <= end {
		if ctx.Err() != nil {
			return out
		}
		size := int64(binary.BigEndian.Uint32(data[i : i+4]))
		typ := string(data[i+4 : i+8])
		headerLen := 8
		switch size {
		case 0: // box extends to the end of the enclosing space
			size = int64(end - i)
		case 1: // 64-bit largesize follows the type
			if i+16 > end {
				return out
			}
			size64 := binary.BigEndian.Uint64(data[i+8 : i+16])
			if size64 > uint64(end-i) {
				return out
			}
			size = int64(size64)
			headerLen = 16
		}
		if size < int64(headerLen) || int64(i)+size > int64(end) {
			return out // malformed size — stop this level
		}
		b := &bmffBox{typ: typ, start: i, end: i + int(size), headerLen: headerLen}
		if typ == "uuid" {
			if b.start+b.headerLen+16 > b.end {
				return out
			}
			copy(b.usertype[:], data[b.start+b.headerLen:])
			b.headerLen += 16
		}
		switch {
		case bmffContainers[typ]:
			b.children = parseBMFFLevel(ctx, data, b.start+b.headerLen, b.end, depth+1)
		case bmffFullBoxContainers[typ]:
			if b.start+b.headerLen+4 <= b.end {
				b.children = parseBMFFLevel(ctx, data, b.start+b.headerLen+4, b.end, depth+1)
			}
		}
		out = append(out, b)
		i = b.end
	}
	return out
}

// bmffJUMBF locates the C2PA manifest store in a BMFF asset and returns its
// raw JUMBF bytes. It prefers a box with purpose "manifest", falling back to
// the first C2PA uuid box of any non-merkle purpose (best-effort, mirroring
// the other extractors). Returns nil when no manifest is present.
func bmffJUMBF(ctx context.Context, data []byte) []byte {
	var fallback []byte
	for _, b := range parseBMFFBoxes(ctx, data) {
		if ctx.Err() != nil {
			return nil
		}
		if b.typ != "uuid" || b.usertype != c2paBoxUUID {
			continue
		}
		purpose, jumbf := c2paBoxPayload(data, b)
		if len(jumbf) == 0 {
			continue
		}
		if purpose == "manifest" {
			return jumbf
		}
		if purpose != "merkle" && fallback == nil {
			fallback = jumbf
		}
	}
	return fallback
}

// bmffHasUpdateManifest reports whether the asset carries a C2PA uuid box with
// purpose "update" (an update manifest, which this validator does not
// evaluate).
func bmffHasUpdateManifest(ctx context.Context, data []byte) bool {
	for _, b := range parseBMFFBoxes(ctx, data) {
		if b.typ != "uuid" || b.usertype != c2paBoxUUID {
			continue
		}
		if purpose, _ := c2paBoxPayload(data, b); purpose == "update" {
			return true
		}
	}
	return false
}

// c2paBoxPayload decodes a C2PA uuid box: FullBox version/flags, the
// NUL-terminated purpose string, the 8-byte merkle offset (non-merkle
// purposes), then the JUMBF store trimmed to its own superbox length (the box
// may be zero-padded). If skipping the merkle-offset field does not land on a
// plausible JUMBF superbox, it retries without the skip — a wrong assumption
// about the field's presence then self-corrects instead of shifting the whole
// parse by 8 bytes.
func c2paBoxPayload(data []byte, b *bmffBox) (purpose string, jumbf []byte) {
	p := b.start + b.headerLen + 4 // skip FullBox version(1)+flags(3)
	if p >= b.end {
		return "", nil
	}
	nul := bytes.IndexByte(data[p:b.end], 0)
	if nul < 0 {
		return "", nil
	}
	purpose = string(data[p : p+nul])
	p += nul + 1
	if purpose == "merkle" {
		return purpose, nil // CBOR merkle payload, not JUMBF
	}
	withSkip := p + 8
	switch {
	case looksLikeJUMBF(data, withSkip, b.end):
		p = withSkip
	case looksLikeJUMBF(data, p, b.end):
		// no merkle-offset field; proceed at p
	default:
		return purpose, nil
	}
	// Trim zero padding using the JUMBF superbox's own length.
	ln := int(binary.BigEndian.Uint32(data[p : p+4]))
	if ln < 8 || p+ln > b.end {
		return purpose, nil
	}
	return purpose, data[p : p+ln]
}

// looksLikeJUMBF reports whether data[p:end] plausibly starts a JUMBF
// superbox: a 4-byte length >= 8 that fits, followed by the type "jumb".
func looksLikeJUMBF(data []byte, p, end int) bool {
	if p < 0 || p+8 > end {
		return false
	}
	ln := int(binary.BigEndian.Uint32(data[p : p+4]))
	return ln >= 8 && p+ln <= end && string(data[p+4:p+8]) == "jumb"
}
