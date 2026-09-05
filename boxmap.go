package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
)

// The asset side of c2pa.hash.boxes (see boxeshash.go for the verifier): a
// container's own named, hashable regions, in file order. A box-hash assertion
// is a list of hashes over these regions, so the names and the byte ranges here
// are a wire format shared with whoever signed the asset — they are the
// signer's conventions, not this reader's, and changing one silently breaks
// verification of already-signed files.
//
// Only the containers whose box naming C2PA actually defines are enumerated:
// JPEG segments, PNG chunks and GIF blocks. Everything else reports "no box map"
// and the verifier says so rather than guessing at a structure.

// c2paBoxName is the reserved name for the region holding the C2PA manifest
// store. Its bytes are never hashed — they hold the manifest doing the binding,
// so hashing them would be circular — and an assertion entry naming it may name
// nothing else.
const c2paBoxName = "C2PA"

// pngHeaderBoxName is PNG's 8-byte signature, which has no chunk type of its
// own and so is given this synthetic name.
const pngHeaderBoxName = "PNGh"

// exclusionKind says why a byte range inside a box may legitimately be left out
// of that box's hash. Only these two reasons exist: the spec (§15.12.3) lets a
// box hash exclude the manifest store itself and asset metadata, and nothing
// else — an exclusion that lands anywhere else is how a forged assertion would
// carve tampered pixels out of the binding.
type exclusionKind int

const (
	// exclManifestOrPadding is the C2PA manifest store, or padding reserved
	// around it. Excluding it is the baseline every box hash does.
	exclManifestOrPadding exclusionKind = iota
	// exclAssetMetadata is EXIF/XMP/IPTC-equivalent metadata (spec §9.2.6),
	// which a producer may leave editable after signing.
	exclAssetMetadata
)

// allowedExclusion is a box-relative byte range that the container's own
// structure says may be excluded from the box's hash.
type allowedExclusion struct {
	start, length int
	kind          exclusionKind
}

// contains reports whether the box-relative range [start, end) lies entirely
// inside this permitted range.
func (a allowedExclusion) contains(start, end int) bool {
	return start >= a.start && end <= a.start+a.length
}

// boundedBy reports whether this permitted range itself stays inside a box of
// boxLen bytes. The box map is this package's own, but the check is kept
// independent so a bug in one enumerator cannot widen what an assertion is
// allowed to exclude.
func (a allowedExclusion) boundedBy(boxLen int) bool {
	return a.start >= 0 && a.length >= 0 && a.start+a.length <= boxLen
}

// assetBox is one named, hashable region of the asset.
type assetBox struct {
	name          string
	start, length int
	// allowed is the set of box-relative ranges an assertion may exclude from
	// this box's hash. Empty means the box must be hashed whole.
	allowed []allowedExclusion
}

func (b assetBox) end() int { return b.start + b.length }

// wholeBoxAllowed permits excluding the box in its entirety, which is what the
// C2PA store's own box gets.
func wholeBoxAllowed(length int) []allowedExclusion {
	return []allowedExclusion{{start: 0, length: length, kind: exclManifestOrPadding}}
}

// metadataAfterHeader permits excluding everything past a fixed-size structural
// header — the shape every metadata-carrying chunk or segment takes, where the
// framing stays hashed and the payload does not.
func metadataAfterHeader(headerLen, boxLen int) []allowedExclusion {
	if boxLen <= headerLen {
		return nil
	}
	return []allowedExclusion{{start: headerLen, length: boxLen - headerLen, kind: exclAssetMetadata}}
}

// assetBoxMap enumerates the asset's named boxes in file order. ok is false for
// a container whose box naming C2PA does not define, which is different from a
// container whose bytes would not parse (ok, empty slice).
func assetBoxMap(ctx context.Context, container Container, data []byte) (boxes []assetBox, ok bool) {
	switch container {
	case JPEG:
		return jpegBoxMap(ctx, data), true
	case PNG:
		return pngBoxMap(ctx, data), true
	case GIF:
		return gifBoxMap(ctx, data), true
	}
	return nil, false
}

// jpegBoxMap enumerates a JPEG's segments. Names are the marker mnemonics —
// SOI, APP0…APP15, DQT, DHT, SOF0…SOF15, SOS, COM, EOI — and a run of APP11
// segments carrying the C2PA store collapses into a single box named "C2PA".
//
// Three conventions here are the signer's and must not drift:
//   - a box starts at its 0xFF marker byte, so the 2-byte marker and the
//     2-byte length field are hashed along with the payload;
//   - the SOS box runs past its own header to the end of the entropy-coded
//     scan, swallowing every stuffed 0xFF00 and restart marker, so the image
//     data is bound by the SOS box rather than left unnamed;
//   - a marker without a length field (SOI, EOI, RSTn) is a 2-byte box.
//
// A structure that does not walk cleanly returns nil: reporting a partial box
// map would let an assertion match a prefix of a file this reader failed to
// understand.
func jpegBoxMap(ctx context.Context, data []byte) []assetBox {
	var out []assetBox
	cai := -1        // index in out of the C2PA run being extended, -1 when none
	var caiEn []byte // that run's 2-byte box instance number
	for i := 0; i+1 < len(data); {
		if ctx.Err() != nil {
			return nil
		}
		if data[i] != 0xFF {
			return nil // not on a marker boundary
		}
		m := data[i+1]
		name := jpegMarkerName(m)
		if name == "" {
			return nil // a marker this reader cannot name
		}
		if m == 0xD9 { // EOI ends the image
			return append(out, assetBox{name: name, start: i, length: 2})
		}
		if !jpegMarkerHasLength(m) {
			out = append(out, assetBox{name: name, start: i, length: 2})
			cai = -1
			i += 2
			continue
		}
		if i+4 > len(data) {
			return nil
		}
		ln := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if ln < 2 || ln > len(data)-i-2 {
			return nil
		}
		size := 2 + ln
		payload := data[i+4 : i+2+ln]
		if m == 0xDA { // SOS: the box covers the entropy-coded scan too
			n := jpegEntropySize(data[i+size:])
			if n < 0 {
				return nil // the scan never reaches a terminating marker
			}
			size += n
		}
		if m == 0xEB { // APP11, the C2PA store's carrier
			if en, isCAI := jpegCAISegment(payload, caiEn, cai >= 0); isCAI {
				if cai < 0 {
					out = append(out, assetBox{name: c2paBoxName, start: i})
					cai = len(out) - 1
				}
				out[cai].length += size
				out[cai].allowed = wholeBoxAllowed(out[cai].length)
				caiEn = en
				i += size
				continue
			}
		}
		out = append(out, assetBox{
			name:    name,
			start:   i,
			length:  size,
			allowed: jpegAllowedExclusions(name, payload, size),
		})
		cai = -1
		i += size
	}
	return out
}

// jpegMarkerHasLength reports whether the marker is followed by a 2-byte
// segment length. Standalone markers (SOI, EOI, RSTn, TEM) are not.
func jpegMarkerHasLength(m byte) bool {
	switch {
	case m >= 0xC0 && m <= 0xCF: // SOFn, DHT, JPG, DAC
		return true
	case m >= 0xE0 && m <= 0xEF: // APPn
		return true
	}
	return m == 0xDA || m == 0xDB || m == 0xDD || m == 0xFE // SOS, DQT, DRI, COM
}

// jpegMarkerName maps a marker code to its mnemonic, or "" when this reader has
// no name for it.
func jpegMarkerName(m byte) string {
	switch {
	case m >= 0xE0 && m <= 0xEF:
		return "APP" + strconv.Itoa(int(m-0xE0))
	case m >= 0xD0 && m <= 0xD7:
		return "RST" + strconv.Itoa(int(m-0xD0))
	case m >= 0xF0 && m <= 0xFD:
		return "JPG" + strconv.Itoa(int(m-0xF0))
	}
	switch m {
	case 0x01:
		return "TEM"
	case 0xC4:
		return "DHT"
	case 0xC8:
		return "JPG"
	case 0xCC:
		return "DAC"
	case 0xD8:
		return "SOI"
	case 0xD9:
		return "EOI"
	case 0xDA:
		return "SOS"
	case 0xDB:
		return "DQT"
	case 0xDC:
		return "DNL"
	case 0xDD:
		return "DRI"
	case 0xDE:
		return "DHP"
	case 0xDF:
		return "EXP"
	case 0xFE:
		return "COM"
	}
	if m >= 0xC0 && m <= 0xCF {
		return "SOF" + strconv.Itoa(int(m-0xC0))
	}
	return ""
}

// jpegEntropySize measures the entropy-coded scan starting at rest, returning
// the number of bytes before the next real marker. A 0xFF inside the scan is
// either stuffed (0xFF00) or a restart marker (0xFFD0…0xFFD7); anything else
// ends it. Returns -1 when the scan runs off the end of the data, which means
// the file is truncated and its box map cannot be trusted.
func jpegEntropySize(rest []byte) int {
	for i := 0; i < len(rest); {
		if rest[i] != 0xFF {
			i++
			continue
		}
		if i+1 >= len(rest) {
			return -1
		}
		if n := rest[i+1]; n != 0x00 && (n < 0xD0 || n > 0xD7) {
			return i
		}
		i += 2
	}
	return -1
}

// jpegCAISegment reports whether an APP11 segment's payload belongs to the C2PA
// store, and returns its box instance number so the rest of the run can be
// recognised. The first segment of a run is identified by the "c2pa" JUMBF type
// at payload offset 24 (past CI+En+Z, the jumb header and the jumd header); the
// rest by repeating that segment's instance number.
//
// Unlike c2pa-rs this requires the run to be contiguous — the caller drops the
// run at any intervening segment — so a stray later APP11 sharing an instance
// number cannot silently extend the box's byte range across unrelated segments.
func jpegCAISegment(payload, runEn []byte, inRun bool) (en []byte, ok bool) {
	// CI (2) + En (2) + Z (4), then at least the jumb and jumd headers.
	if len(payload) <= 16 || binary.BigEndian.Uint16(payload[:2]) != 0x4A50 { // "JP"
		return nil, false
	}
	en = payload[2:4]
	if inRun && bytes.Equal(en, runEn) {
		return en, true
	}
	if len(payload) >= 28 && string(payload[24:28]) == "c2pa" {
		return en, true
	}
	return nil, false
}

// JPEG metadata signatures. An APPn marker is only a convention — any
// application may use APP1 for anything — so a segment counts as metadata only
// when its payload actually carries the signature.
var (
	jpegEXIFSignature      = []byte("Exif\x00\x00")
	jpegXMPSignature       = []byte("http://ns.adobe.com/xap/1.0/")
	jpegPhotoshopSignature = []byte("Photoshop 3.0\x00")
)

// jpegAllowedExclusions returns what a box hash may exclude from a JPEG
// segment: the payload of a recognised metadata segment, past the 4-byte
// marker + length header. Everything else must be hashed whole.
func jpegAllowedExclusions(name string, payload []byte, size int) []allowedExclusion {
	const header = 4
	switch name {
	case "APP1":
		if bytes.HasPrefix(payload, jpegEXIFSignature) || bytes.HasPrefix(payload, jpegXMPSignature) {
			return metadataAfterHeader(header, size)
		}
	case "APP13":
		if bytes.HasPrefix(payload, jpegPhotoshopSignature) {
			return metadataAfterHeader(header, size)
		}
	case "COM":
		// A comment is free-form text with no signature to check.
		return metadataAfterHeader(header, size)
	}
	return nil
}

var pngSignatureBytes = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

// pngBoxMap enumerates a PNG's chunks. The 8-byte signature has no chunk type,
// so it becomes a synthetic "PNGh" box; every other box is named by its chunk
// type, except a caBX chunk carrying the store, which is named "C2PA".
//
// A chunk's box covers its 4-byte length, 4-byte type, data and trailing CRC.
// The CRC is inside the excludable range of a metadata chunk on purpose: it
// covers the type and data, so any legitimate edit changes it too, and leaving
// it hashed would fail every such edit.
//
// Each caBX chunk is its own "C2PA" box rather than being collapsed into one,
// matching how a store split across several chunks is signed.
func pngBoxMap(ctx context.Context, data []byte) []assetBox {
	if len(data) < 8 || !bytes.Equal(data[:8], pngSignatureBytes) {
		return nil
	}
	out := []assetBox{{name: pngHeaderBoxName, start: 0, length: 8}}
	for i := 8; i+8 <= len(data); {
		if ctx.Err() != nil {
			return nil
		}
		ln := int(binary.BigEndian.Uint32(data[i : i+4]))
		if ln < 0 || ln > len(data)-i-12 {
			return nil
		}
		typ := string(data[i+4 : i+8])
		size := 12 + ln
		name, allowed := typ, []allowedExclusion(nil)
		switch typ {
		case "caBX":
			name, allowed = c2paBoxName, wholeBoxAllowed(size)
		case "eXIf", "iTXt", "tEXt", "zTXt":
			allowed = metadataAfterHeader(8, size)
		}
		out = append(out, assetBox{name: name, start: i, length: size, allowed: allowed})
		i += size
		if typ == "IEND" {
			break
		}
	}
	return out
}

// GIF block names are the block's introducer bytes in hex, except the header,
// the logical screen descriptor and the image data, which have no introducer of
// their own.
const (
	gifLSDBoxName       = "LSD"
	gifImageDataBoxName = "TBID"
	// gifCommentLabel introduces a comment extension, whose body is the same
	// length-prefixed sub-block stream an XMP extension carries.
	gifCommentLabel = 0xFE
	// gifXMPIdentifier is the application identifier plus authentication code
	// marking the XMP application extension.
	gifXMPIdentifier = "XMP DataXMP"
	// gifAppExtHeader is the 0x21 0xFF introducer, the block-size byte and the
	// 11-byte identifier: where an application extension's sub-blocks begin.
	gifAppExtHeader = 14
	// gifCommentExtHeader is the 0x21 0xFE introducer, after which a comment
	// extension's sub-blocks begin immediately.
	gifCommentExtHeader = 2
)

// gifBoxMap enumerates a GIF's blocks. A global colour table is folded into the
// logical screen descriptor's box and a local colour table into its image
// descriptor's, because neither is separable from the block that declares its
// size. Image data — the LZW code-size byte and its sub-blocks — is one "TBID"
// box, and the C2PA application extension is named "C2PA".
func gifBoxMap(ctx context.Context, data []byte) []assetBox {
	if len(data) < 13 || string(data[:3]) != "GIF" {
		return nil
	}
	out := []assetBox{{name: string(data[:6]), start: 0, length: 6}}
	lsd := assetBox{name: gifLSDBoxName, start: 6, length: 7}
	pos := 13
	if packed := data[10]; packed&0x80 != 0 {
		n := 3 * (1 << ((packed & 0x07) + 1))
		if n > len(data)-pos {
			return nil
		}
		lsd.length += n
		pos += n
	}
	out = append(out, lsd)

	for blocks := 0; pos < len(data); blocks++ {
		if ctx.Err() != nil || blocks >= maxGIFBlocks {
			return nil
		}
		switch data[pos] {
		case gifTrailer:
			return append(out, assetBox{name: "3B", start: pos, length: 1})
		case gifExtensionIntroducer:
			if pos+2 > len(data) {
				return nil
			}
			// Every extension body — including the application extension's
			// 11-byte identifier and the plain-text extension's 12-byte header
			// — is itself a length-prefixed sub-block, so one sub-block walk
			// finds the end of any of them.
			_, next := gifSubBlocks(data, pos+2)
			if next < 0 {
				return nil
			}
			b := assetBox{name: "21" + gifHexByte(data[pos+1]), start: pos, length: next - pos}
			switch data[pos+1] {
			case gifApplicationLabel:
				b.name, b.allowed = gifAppExtName(data, pos, b.length)
			case gifCommentLabel:
				b.allowed = gifSubBlockMetadata(data, pos, gifCommentExtHeader)
			}
			out = append(out, b)
			pos = next
		case gifImageDescriptor:
			// 10-byte descriptor, an optional local colour table, then the
			// image data as its own box.
			if pos+10 > len(data) {
				return nil
			}
			packed := data[pos+9]
			desc := 10
			if packed&0x80 != 0 {
				desc += 3 * (1 << ((packed & 0x07) + 1))
			}
			if desc > len(data)-pos {
				return nil
			}
			out = append(out, assetBox{name: "2C", start: pos, length: desc})
			pos += desc
			if pos >= len(data) {
				return nil
			}
			_, next := gifSubBlocks(data, pos+1) // past the LZW minimum code size
			if next < 0 {
				return nil
			}
			out = append(out, assetBox{name: gifImageDataBoxName, start: pos, length: next - pos})
			pos = next
		default:
			return nil // not a block boundary
		}
	}
	return nil // ran out of data before the trailer
}

// gifAppExtName names an application extension by the identifier in its first
// sub-block, and says what a box hash may exclude from it: the whole box for
// the C2PA store, the XMP payload for an XMP extension.
func gifAppExtName(data []byte, pos, length int) (string, []allowedExclusion) {
	const idLen = 11
	if pos+3+idLen > len(data) || int(data[pos+2]) != idLen {
		return "21FF", nil
	}
	switch string(data[pos+3 : pos+3+idLen]) {
	case gifC2PAIdentifier:
		return c2paBoxName, wholeBoxAllowed(length)
	case gifXMPIdentifier:
		return "21FF", gifSubBlockMetadata(data, pos, gifAppExtHeader)
	}
	return "21FF", nil
}

// gifSubBlockMetadata permits excluding the data of each sub-block in the chain
// starting headerLen bytes into the box, but not the length prefixes or the
// terminator: the block's framing stays hashed, so an exclusion cannot resize
// the block it sits in.
func gifSubBlockMetadata(data []byte, boxStart, headerLen int) []allowedExclusion {
	var out []allowedExclusion
	for pos := boxStart + headerLen; pos < len(data); {
		n := int(data[pos])
		if n == 0 {
			return out
		}
		if n > len(data)-pos-1 {
			return nil
		}
		out = append(out, allowedExclusion{
			start:  pos + 1 - boxStart,
			length: n,
			kind:   exclAssetMetadata,
		})
		pos += 1 + n
	}
	return nil
}

// gifHexByte formats a block label as the two uppercase hex digits GIF box
// names use.
func gifHexByte(b byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[b>>4], digits[b&0x0F]})
}
