package c2pa

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
)

// maxRIFFChunks bounds the top-level chunk walk. A RIFF file of nothing but
// empty 8-byte chunks would otherwise cost one iteration per 8 bytes; the cap
// is far above any real file's top-level chunk count.
const maxRIFFChunks = 1 << 16

// riffC2PAChunk is the FourCC of the chunk carrying the manifest store.
const riffC2PAChunk = "C2PA"

// riffJUMBF returns the raw JUMBF manifest store from a RIFF asset — WebP, WAV
// or AVI — or nil when there is none.
//
// The store is a top-level chunk with FourCC C2PA, sitting directly inside the
// outer RIFF container alongside the format's own chunks. WebP's VP8X flags
// matter only when writing; a reader just finds the chunk. An AVI larger than
// 1 GB continues into further RIFF/AVIX containers, but the store is in the
// first, so only that one is walked.
//
// Nothing here trusts a declared size: a chunk claiming more bytes than the
// file holds is where a RIFF reader gets exploited.
func riffJUMBF(ctx context.Context, data []byte) []byte {
	// "RIFF" + size + form type, then the chunks.
	if len(data) < 12 || string(data[:4]) != "RIFF" {
		return nil
	}
	// The declared RIFF size covers everything after it, but a truncated or
	// lying file is normal input here — the real bytes are the only bound.
	end := len(data)
	if declared := int64(binary.LittleEndian.Uint32(data[4:8])) + 8; declared >= 12 && declared < int64(end) {
		end = int(declared)
	}

	for pos, chunks := 12, 0; pos+8 <= end && chunks < maxRIFFChunks; chunks++ {
		if ctx.Err() != nil {
			return nil
		}
		id := string(data[pos : pos+4])
		size := int64(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		body := int64(pos) + 8
		if body+size > int64(end) {
			return nil // declared past the end: stop rather than read into whatever follows
		}
		if id == riffC2PAChunk {
			return data[body : body+size]
		}
		// Chunks are word-aligned: an odd-sized body is followed by a pad byte.
		pos = int(body + size + size%2)
	}
	return nil
}

// --- writing ------------------------------------------------------------------

// riffEmbedder writes the store as a C2PA chunk that is the LAST child of the
// top-level RIFF container (spec §A.3.6: "for compatibility reasons, this C2PA
// chunk shall appear at the end of the RIFF chunk"), rewriting the container's
// size. A simple-format WebP gains the VP8X chunk the extended format needs
// before a decoder will tolerate an unknown chunk.
type riffEmbedder struct{}

// riffChild is one top-level chunk: start is its FourCC's offset, size its
// declared body size.
type riffChild struct {
	id          string
	start, size int
}

// riffPlan parses the first RIFF container. Bytes past its declared end (an
// AVI's further RIFF/AVIX containers, trailing junk) are left alone.
func riffPlan(ctx context.Context, data []byte) (form string, riffEnd int, children []riffChild, err error) {
	if len(data) < 12 || string(data[:4]) != "RIFF" {
		return "", 0, nil, fmt.Errorf("%w: not a RIFF file", errCarrierMalformed)
	}
	declared := int64(binary.LittleEndian.Uint32(data[4:8])) + 8
	if declared < 12 || declared > int64(len(data)) {
		return "", 0, nil, fmt.Errorf("%w: RIFF size %d does not fit the %d-byte file", errCarrierMalformed, declared, len(data))
	}
	riffEnd = int(declared)
	form = string(data[8:12])
	for pos, n := 12, 0; pos+8 <= riffEnd && n < maxRIFFChunks; n++ {
		if err := ctx.Err(); err != nil {
			return "", 0, nil, err
		}
		size := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		if size < 0 || pos+8+size > riffEnd {
			return "", 0, nil, fmt.Errorf("%w: RIFF chunk at %d overruns the container", errCarrierMalformed, pos)
		}
		children = append(children, riffChild{id: string(data[pos : pos+4]), start: pos, size: size})
		pos += 8 + size + size%2
	}
	return form, riffEnd, children, nil
}

func (riffEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	form, riffEnd, children, err := riffPlan(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	var edits []edit
	bodyLen := riffEnd - 8
	hasVP8X := false
	var first *riffChild
	for i := range children {
		c := &children[i]
		switch c.id {
		case riffC2PAChunk:
			end := min(c.start+8+c.size+c.size%2, riffEnd)
			edits = append(edits, edit{at: c.start, remove: end - c.start})
			bodyLen -= end - c.start
		case "VP8X":
			hasVP8X = true
		case "VP8 ", "VP8L":
			if first == nil {
				first = c
			}
		}
	}
	if form == "WEBP" && !hasVP8X {
		// Simple-format WebP: only VP8X's flags tell a decoder that unknown
		// chunks may follow. Synthesise one from the bitstream's dimensions.
		if first == nil {
			return nil, nil, fmt.Errorf("%w: WebP has no VP8/VP8L bitstream to size a VP8X from", errCarrierUnsupported)
		}
		vp8x, err := webpVP8X(first.id, asset[first.start+8:first.start+8+first.size])
		if err != nil {
			return nil, nil, err
		}
		edits = append(edits, edit{at: 12, insert: vp8x})
		bodyLen += len(vp8x)
	}
	chunk := riffChunk(riffC2PAChunk, store)
	edits = append(edits, edit{at: riffEnd, insert: chunk})
	bodyLen += len(chunk)
	if int64(bodyLen) > math.MaxUint32 {
		return nil, nil, fmt.Errorf("%w: RIFF body would exceed 4 GiB", errCarrierUnsupported)
	}
	out, placed, _, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	binary.LittleEndian.PutUint32(out[4:8], uint32(bodyLen))
	// Header and body; the pad byte, if any, stays hashed (c2pa-rs parity).
	return out, []byteRange{{start: placed[len(edits)-1], length: 8 + len(store)}}, nil
}

// webpVP8X builds the extended-format header chunk for a simple WebP: flags,
// three reserved bytes, then width-1 and height-1 as 24-bit little-endian —
// read from the VP8 key frame header or the VP8L stream header. A VP8L alpha
// bit sets the VP8X alpha flag, so a decoder keeps honouring transparency.
func webpVP8X(id string, payload []byte) ([]byte, error) {
	var w, h uint32
	var flags byte
	switch id {
	case "VP8 ":
		if len(payload) < 10 || payload[0]&1 != 0 || payload[3] != 0x9D || payload[4] != 0x01 || payload[5] != 0x2A {
			return nil, fmt.Errorf("%w: VP8 bitstream has no key frame header", errCarrierUnsupported)
		}
		w = uint32(binary.LittleEndian.Uint16(payload[6:8]) & 0x3FFF)
		h = uint32(binary.LittleEndian.Uint16(payload[8:10]) & 0x3FFF)
	case "VP8L":
		if len(payload) < 5 || payload[0] != 0x2F {
			return nil, fmt.Errorf("%w: VP8L bitstream has no signature", errCarrierUnsupported)
		}
		bits := binary.LittleEndian.Uint32(payload[1:5])
		w = bits&0x3FFF + 1
		h = (bits>>14)&0x3FFF + 1
		if bits>>28&1 != 0 {
			flags |= 0x10 // alpha
		}
	}
	if w == 0 || h == 0 {
		return nil, fmt.Errorf("%w: WebP has zero dimensions", errCarrierUnsupported)
	}
	body := []byte{flags, 0, 0, 0}
	body = append(body, byte(w-1), byte((w-1)>>8), byte((w-1)>>16))
	body = append(body, byte(h-1), byte((h-1)>>8), byte((h-1)>>16))
	return riffChunk("VP8X", body), nil
}

// riffChunk frames payload as a RIFF chunk: FourCC, little-endian size, body,
// then a pad byte when the size is odd.
func riffChunk(id string, payload []byte) []byte {
	out := make([]byte, 0, 8+len(payload)+1)
	out = append(out, id...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, payload...)
	if len(payload)%2 == 1 {
		out = append(out, 0)
	}
	return out
}
