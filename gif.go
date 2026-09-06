package c2pa

import (
	"bytes"
	"context"
	"fmt"
)

const (
	gifExtensionIntroducer = 0x21
	gifApplicationLabel    = 0xFF
	gifImageDescriptor     = 0x2C
	gifTrailer             = 0x3B
	// gifC2PAIdentifier is the 8-byte application identifier plus its 3-byte
	// authentication code, which together mark the C2PA application extension.
	gifC2PAIdentifier = "C2PA_GIF\x01\x00\x00"
	// maxGIFBlocks bounds the block walk over adversarial input.
	maxGIFBlocks = 1 << 16
)

// gifJUMBF returns the raw JUMBF manifest store from a GIF, or nil when there
// is none.
//
// The store rides in an application extension introduced by 0x21 0xFF, whose
// 11-byte header is the identifier "C2PA_GIF" and the authentication code
// 01 00 00. Its payload is split across data sub-blocks of at most 255 bytes,
// so it has to be reassembled rather than sliced.
//
// The block structure is walked properly rather than scanned for the marker:
// image data is arbitrary LZW bytes and can spell anything, so a scan would
// happily find a "store" inside a frame.
func gifJUMBF(ctx context.Context, data []byte) []byte {
	// "GIF" + version, then the logical screen descriptor.
	if len(data) < 13 || string(data[:3]) != "GIF" {
		return nil
	}
	pos := 13
	// A global colour table, when the packed field's high bit is set, is
	// 3 * 2^(n+1) bytes and sits before the first block.
	if packed := data[10]; packed&0x80 != 0 {
		pos += 3 * (1 << ((packed & 0x07) + 1))
	}

	for blocks := 0; pos < len(data) && blocks < maxGIFBlocks; blocks++ {
		if ctx.Err() != nil {
			return nil
		}
		switch data[pos] {
		case gifTrailer:
			return nil
		case gifExtensionIntroducer:
			if pos+2 > len(data) {
				return nil
			}
			label := data[pos+1]
			pos += 2
			if label == gifApplicationLabel {
				// The 11-byte identifier block is itself a sub-block.
				if pos < len(data) && int(data[pos]) == len(gifC2PAIdentifier) &&
					pos+1+len(gifC2PAIdentifier) <= len(data) &&
					string(data[pos+1:pos+1+len(gifC2PAIdentifier)]) == gifC2PAIdentifier {
					store, _ := gifSubBlocks(data, pos+1+len(gifC2PAIdentifier))
					return store
				}
			}
			_, next := gifSubBlocks(data, pos)
			if next < 0 {
				return nil
			}
			pos = next
		case gifImageDescriptor:
			// 10-byte descriptor, an optional local colour table, the LZW code
			// size byte, then the image's own sub-blocks.
			if pos+10 > len(data) {
				return nil
			}
			packed := data[pos+9]
			pos += 10
			if packed&0x80 != 0 {
				pos += 3 * (1 << ((packed & 0x07) + 1))
			}
			pos++ // LZW minimum code size
			_, next := gifSubBlocks(data, pos)
			if next < 0 {
				return nil
			}
			pos = next
		default:
			return nil // not a block boundary: stop rather than guess
		}
	}
	return nil
}

// gifSubBlocks reassembles the data sub-block chain starting at pos, returning
// the joined payload and the offset just past the terminating empty block.
// A chain that runs off the end returns next = -1.
func gifSubBlocks(data []byte, pos int) (payload []byte, next int) {
	var out bytes.Buffer
	for range maxGIFBlocks {
		if pos >= len(data) {
			return nil, -1
		}
		n := int(data[pos])
		if n == 0 {
			return out.Bytes(), pos + 1
		}
		if pos+1+n > len(data) {
			return nil, -1
		}
		out.Write(data[pos+1 : pos+1+n])
		pos += 1 + n
	}
	return nil, -1
}

// --- writing ------------------------------------------------------------------

// gifEmbedder writes the store as the C2PA application extension (spec
// §A.3.7) right after the header, logical screen descriptor and global colour
// table — before the first image descriptor — and forces the version to 89a,
// which is the first version with application extensions.
type gifEmbedder struct{}

// gifPlan walks the block stream the way gifJUMBF does and reports where the
// preamble ends and which blocks are existing C2PA extensions. A stream that
// cannot be walked to its trailer is not one a store can be written into.
func gifPlan(ctx context.Context, data []byte) (preambleEnd int, cuts []edit, err error) {
	if len(data) < 13 || string(data[:3]) != "GIF" || (string(data[3:6]) != "87a" && string(data[3:6]) != "89a") {
		return 0, nil, fmt.Errorf("%w: not a GIF", errCarrierMalformed)
	}
	pos := 13
	if packed := data[10]; packed&0x80 != 0 {
		pos += 3 * (1 << ((packed & 0x07) + 1))
	}
	if pos > len(data) {
		return 0, nil, fmt.Errorf("%w: GIF header overruns the file", errCarrierMalformed)
	}
	preambleEnd = pos
	for blocks := 0; pos < len(data) && blocks < maxGIFBlocks; blocks++ {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		switch data[pos] {
		case gifTrailer:
			return preambleEnd, cuts, nil
		case gifExtensionIntroducer:
			if pos+2 > len(data) {
				return 0, nil, fmt.Errorf("%w: truncated GIF extension", errCarrierMalformed)
			}
			start, label := pos, data[pos+1]
			pos += 2
			isC2PA := label == gifApplicationLabel && pos+1+len(gifC2PAIdentifier) <= len(data) &&
				int(data[pos]) == len(gifC2PAIdentifier) &&
				string(data[pos+1:pos+1+len(gifC2PAIdentifier)]) == gifC2PAIdentifier
			_, next := gifSubBlocks(data, pos)
			if next < 0 {
				return 0, nil, fmt.Errorf("%w: GIF extension sub-blocks run off the end", errCarrierMalformed)
			}
			if isC2PA {
				cuts = append(cuts, edit{at: start, remove: next - start})
			}
			pos = next
		case gifImageDescriptor:
			if pos+10 > len(data) {
				return 0, nil, fmt.Errorf("%w: truncated GIF image descriptor", errCarrierMalformed)
			}
			packed := data[pos+9]
			pos += 10
			if packed&0x80 != 0 {
				pos += 3 * (1 << ((packed & 0x07) + 1))
			}
			pos++ // LZW minimum code size
			_, next := gifSubBlocks(data, pos)
			if next < 0 {
				return 0, nil, fmt.Errorf("%w: GIF image data runs off the end", errCarrierMalformed)
			}
			pos = next
		default:
			return 0, nil, fmt.Errorf("%w: byte 0x%02X at offset %d is not a GIF block", errCarrierMalformed, data[pos], pos)
		}
	}
	return 0, nil, fmt.Errorf("%w: GIF has no trailer", errCarrierMalformed)
}

func (gifEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	preambleEnd, cuts, err := gifPlan(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	ext := []byte{gifExtensionIntroducer, gifApplicationLabel, byte(len(gifC2PAIdentifier))}
	ext = append(ext, gifC2PAIdentifier...)
	ext = append(ext, gifSubBlockChain(store)...)
	edits := append(cuts, edit{at: preambleEnd, insert: ext})
	out, placed, _, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	out[4] = '9' // GIF87a → GIF89a: application extensions need 89a
	return out, []byteRange{{start: placed[len(edits)-1], length: len(ext)}}, nil
}

// gifSubBlockChain splits payload into data sub-blocks of at most 255 bytes,
// each prefixed by its length, and appends the empty terminator block.
func gifSubBlockChain(payload []byte) []byte {
	out := make([]byte, 0, len(payload)+len(payload)/255+2)
	for len(payload) > 0 {
		n := min(255, len(payload))
		out = append(out, byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return append(out, 0)
}
