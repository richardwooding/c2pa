package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
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
			frame := body[start : start+frameSize]
			if major == 4 {
				if frameFlags&0x02 != 0 { // per-frame unsynchronisation
					frame = id3DeUnsync(frame)
				}
				if frameFlags&0x01 != 0 && len(frame) >= 4 { // data-length indicator
					frame = frame[4:]
				}
			}
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
