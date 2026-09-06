package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

const (
	// id3C2PAMime is the GEOB frame's MIME type; the deprecated spelling is
	// still written by older producers.
	id3C2PAMime           = "application/c2pa"
	id3C2PAMimeDeprecated = "application/x-c2pa-manifest-store"
	// maxID3Frames bounds the frame walk.
	maxID3Frames = 4096
)

// mp3JUMBF returns the raw JUMBF manifest store from an MP3's ID3v2 tag, or nil
// when there is none.
//
// The store is a GEOB (general encapsulated object) frame whose MIME type is
// application/c2pa. GEOB's body is an encoding byte, then three
// terminated strings — MIME, filename, description — and only then the object,
// so the payload's offset depends on text the file controls.
//
// Unsynchronisation (ID3's defence against false MPEG frame syncs — a 0x00
// stuffed after every 0xFF on write) is reversed rather than refused: in v2.3
// the tag-level flag covers the whole tag body, so it is de-unsynchronised
// before the frame walk; in v2.4 it is per-frame (format flag 0x02) and each
// flagged frame body is restored before the GEOB parse. Frame sizes always
// measure the on-wire, still-stuffed bytes.
func mp3JUMBF(ctx context.Context, data []byte) []byte {
	if len(data) < 10 || string(data[:3]) != "ID3" {
		return nil
	}
	major, flags := data[3], data[5]
	if major < 3 || major > 4 {
		return nil
	}
	size := id3Synchsafe(data[6:10])
	end := min(10+size, len(data))
	body := data[10:end]
	if major == 3 && flags&0x80 != 0 {
		body = id3DeUnsync(body)
	}

	pos := 0
	if flags&0x40 != 0 { // extended header, whose own size prefix is skipped
		if pos+4 > len(body) {
			return nil
		}
		extSize := id3Synchsafe(body[pos : pos+4])
		if major == 3 {
			extSize = int(binary.BigEndian.Uint32(body[pos:pos+4])) + 4
		}
		pos += extSize
	}

	for frames := 0; frames < maxID3Frames && pos >= 0 && pos+10 <= len(body); frames++ {
		if ctx.Err() != nil {
			return nil
		}
		id := string(body[pos : pos+4])
		if id == "\x00\x00\x00\x00" {
			return nil // padding: the frames are done
		}
		// v2.4 sizes are synchsafe; v2.3 sizes are plain big-endian.
		frameSize := int(binary.BigEndian.Uint32(body[pos+4 : pos+8]))
		if major == 4 {
			frameSize = id3Synchsafe(body[pos+4 : pos+8])
		}
		frameFlags := body[pos+9]
		start := pos + 10
		if frameSize <= 0 || start+frameSize > len(body) {
			return nil
		}
		if id == "GEOB" {
			frame := id3GEOBObject(major, frameFlags, body[start:start+frameSize])
			if store := id3GEOBStore(frame); store != nil {
				return store
			}
		}
		pos = start + frameSize
	}
	return nil
}

// id3DeUnsync reverses ID3v2 unsynchronisation: every 0x00 that follows a 0xFF
// was stuffed on write and is dropped. Output is never longer than the input.
func id3DeUnsync(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		out = append(out, b[i])
		if b[i] == 0xFF && i+1 < len(b) && b[i+1] == 0x00 {
			i++
		}
	}
	return out
}

// id3GEOBStore returns the object bytes of a GEOB frame body when its MIME type
// marks it as a C2PA manifest store, or nil otherwise.
func id3GEOBStore(body []byte) []byte {
	if len(body) < 2 {
		return nil
	}
	encoding := body[0]
	rest := body[1:]

	// The MIME type is ISO-8859-1 and NUL-terminated whatever the encoding byte
	// says — only filename and description follow the declared encoding.
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil
	}
	mime := string(rest[:i])
	if mime != id3C2PAMime && mime != id3C2PAMimeDeprecated {
		return nil
	}
	rest = rest[i+1:]

	for range 2 { // filename, then description
		n := id3TerminatorLen(encoding)
		j := id3IndexTerminator(rest, n)
		if j < 0 {
			return nil
		}
		rest = rest[j+n:]
	}
	if len(rest) == 0 {
		return nil
	}
	return rest
}

// id3TerminatorLen is 2 for the UTF-16 encodings, whose NUL is two bytes.
func id3TerminatorLen(encoding byte) int {
	if encoding == 1 || encoding == 2 {
		return 2
	}
	return 1
}

// id3IndexTerminator finds a terminator of n bytes, aligned to n.
func id3IndexTerminator(b []byte, n int) int {
	for i := 0; i+n <= len(b); i += n {
		if bytes.Equal(b[i:i+n], make([]byte, n)) {
			return i
		}
	}
	return -1
}

// id3Synchsafe decodes ID3's 7-bits-per-byte integer, whose high bits are
// always clear so the value can never look like a frame sync.
func id3Synchsafe(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(b[0]&0x7F)<<21 | int(b[1]&0x7F)<<14 | int(b[2]&0x7F)<<7 | int(b[3]&0x7F)
}

// --- writing ------------------------------------------------------------------

// mp3Embedder writes the store as a GEOB frame (spec §A.3.4) with MIME type
// application/c2pa, placed last in a rebuilt ID3v2 tag whose other frames are
// copied verbatim. The tag's major version is preserved: c2pa-rs always emits
// v2.4, but only because its id3 crate re-models v2.3 frames on read —
// copying v2.3 frame bytes under a v2.4 header would mis-declare every frame's
// size encoding. An asset with no tag gets a fresh v2.4 one.
type mp3Embedder struct{}

// id3Parsed is an ID3v2 tag taken apart for rewriting: its frames, each as the
// verbatim 10-byte header plus body, and where the audio begins.
type id3Parsed struct {
	major  byte
	frames [][]byte
	end    int
}

// parseID3ForWrite reads the leading ID3v2 tag. The extended header and footer
// are dropped (their sizes and CRC would go stale), a v2.3 unsynchronised tag
// is restored so its frame sizes mean what they say, and existing C2PA GEOB
// frames are left out.
func parseID3ForWrite(ctx context.Context, data []byte) (id3Parsed, error) {
	if len(data) < 10 || string(data[:3]) != "ID3" {
		return id3Parsed{major: 4}, nil
	}
	major, flags := data[3], data[5]
	if major < 3 || major > 4 {
		return id3Parsed{}, fmt.Errorf("%w: ID3v2.%d tags are not written into", errCarrierUnsupported, major)
	}
	size := id3Synchsafe(data[6:10])
	end := 10 + size
	if major == 4 && flags&0x10 != 0 {
		end += 10 // footer
	}
	if end > len(data) {
		return id3Parsed{}, fmt.Errorf("%w: ID3 tag size %d overruns the file", errCarrierMalformed, size)
	}
	body := data[10 : 10+size]
	if major == 3 && flags&0x80 != 0 {
		body = id3DeUnsync(body)
	}
	pos := 0
	if flags&0x40 != 0 {
		if pos+4 > len(body) {
			return id3Parsed{}, fmt.Errorf("%w: truncated ID3 extended header", errCarrierMalformed)
		}
		ext := id3Synchsafe(body[pos : pos+4])
		if major == 3 {
			ext = int(binary.BigEndian.Uint32(body[pos:pos+4])) + 4
		}
		if ext < 0 || pos+ext > len(body) {
			return id3Parsed{}, fmt.Errorf("%w: ID3 extended header overruns the tag", errCarrierMalformed)
		}
		pos += ext
	}
	p := id3Parsed{major: major, end: end}
	for n := 0; n < maxID3Frames && pos+10 <= len(body); n++ {
		if err := ctx.Err(); err != nil {
			return id3Parsed{}, err
		}
		id := body[pos : pos+4]
		if string(id) == "\x00\x00\x00\x00" {
			break // padding
		}
		for _, c := range id {
			if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return id3Parsed{}, fmt.Errorf("%w: ID3 frame id %q", errCarrierMalformed, id)
			}
		}
		frameSize := int(binary.BigEndian.Uint32(body[pos+4 : pos+8]))
		if major == 4 {
			frameSize = id3Synchsafe(body[pos+4 : pos+8])
		}
		start := pos + 10
		if frameSize <= 0 || frameSize > len(body)-start {
			return id3Parsed{}, fmt.Errorf("%w: ID3 frame %q overruns the tag", errCarrierMalformed, id)
		}
		frame := body[pos : start+frameSize]
		if string(id) == "GEOB" && id3GEOBStore(id3GEOBObject(major, body[pos+9], body[start:start+frameSize])) != nil {
			pos = start + frameSize
			continue // an existing store; the new tag gets a fresh one
		}
		p.frames = append(p.frames, frame)
		pos = start + frameSize
	}
	return p, nil
}

// id3GEOBObject undoes what a v2.4 frame's format flags did to its body —
// per-frame unsynchronisation, a data-length indicator — so the GEOB fields can
// be read; v2.3 bodies are already plain by the time the tag is de-unsynced.
func id3GEOBObject(major, frameFlags byte, body []byte) []byte {
	if major != 4 {
		return body
	}
	if frameFlags&0x02 != 0 {
		body = id3DeUnsync(body)
	}
	if frameFlags&0x01 != 0 && len(body) >= 4 {
		body = body[4:]
	}
	return body
}

// id3C2PAGEOB frames store as the GEOB frame c2pa-rs writes: text encoding
// (UTF-8 in v2.4, ISO-8859-1 in v2.3 — 0x03 is not valid there), MIME
// application/c2pa, filename "c2pa", description "c2pa manifest store", then
// the object. It returns the frame and the object's offset within it.
func id3C2PAGEOB(major byte, store []byte) (frame []byte, objectAt int) {
	enc := byte(0x03)
	if major == 3 {
		enc = 0x00
	}
	body := []byte{enc}
	body = append(body, id3C2PAMime...)
	body = append(body, 0)
	body = append(body, "c2pa"...)
	body = append(body, 0)
	body = append(body, "c2pa manifest store"...)
	body = append(body, 0)
	objectAt = 10 + len(body)
	body = append(body, store...)
	frame = []byte("GEOB")
	if major == 4 {
		frame = append(frame, id3AppendSynchsafe(len(body))...)
	} else {
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(body)))
	}
	frame = append(frame, 0, 0)
	return append(frame, body...), objectAt
}

func (mp3Embedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	tag, err := parseID3ForWrite(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	geob, objectAt := id3C2PAGEOB(tag.major, store)
	bodyLen := len(geob)
	for _, f := range tag.frames {
		bodyLen += len(f)
	}
	if bodyLen >= 1<<28 {
		return nil, nil, fmt.Errorf("%w: ID3 tag would exceed the 256 MiB synchsafe limit", errCarrierUnsupported)
	}
	out := make([]byte, 0, 10+bodyLen+len(asset)-tag.end)
	out = append(out, 'I', 'D', '3', tag.major, 0, 0)
	out = append(out, id3AppendSynchsafe(bodyLen)...)
	for _, f := range tag.frames {
		out = append(out, f...)
	}
	geobAt := len(out)
	out = append(out, geob...)
	out = append(out, asset[tag.end:]...)
	// The object bytes only (c2pa-rs parity); the tag and frame sizes around
	// them depend on the store's length alone.
	return out, []byteRange{{start: geobAt + objectAt, length: len(store)}}, nil
}

// id3AppendSynchsafe appends n as ID3's 4-byte, 7-bits-per-byte integer.
func id3AppendSynchsafe(n int) []byte {
	return []byte{byte(n>>21) & 0x7F, byte(n>>14) & 0x7F, byte(n>>7) & 0x7F, byte(n) & 0x7F}
}
