package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// id3Tag frames frames as an ID3v2 tag of the given major version.
func id3Tag(major byte, flags byte, frames []byte) []byte {
	out := append([]byte("ID3"), major, 0, flags)
	out = append(out, id3AppendSynchsafe(len(frames))...)
	return append(out, frames...)
}

// id3Frame frames a body with the size encoding the major version implies.
func id3Frame(major byte, id string, body []byte) []byte {
	out := []byte(id)
	if major == 4 {
		out = append(out, id3AppendSynchsafe(len(body))...)
	} else {
		out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	}
	out = append(out, 0, 0)
	return append(out, body...)
}

// geobBody builds a GEOB frame body: encoding, MIME, filename, description, object.
func geobBody(encoding byte, mime string, store []byte) []byte {
	term := make([]byte, id3TerminatorLen(encoding))
	out := []byte{encoding}
	out = append(out, mime...)
	out = append(out, 0) // the MIME field is latin1-terminated whatever the encoding
	out = append(out, term...)
	out = append(out, term...)
	return append(out, store...)
}

func TestMP3JUMBF_BothVersionsAndMimeSpellings(t *testing.T) {
	store := []byte("\x00\x00\x00\x10jumbthe-store-here")
	for _, major := range []byte{3, 4} {
		for _, mime := range []string{id3C2PAMime, id3C2PAMimeDeprecated} {
			t.Run(string(rune('0'+major))+"/"+mime, func(t *testing.T) {
				data := id3Tag(major, 0, id3Frame(major, "GEOB", geobBody(0, mime, store)))
				if got := mp3JUMBF(context.Background(), data); !bytes.Equal(got, store) {
					t.Errorf("got %q, want %q", got, store)
				}
			})
		}
	}
}

// TestMP3JUMBF_UTF16TerminatorsAreTwoBytes is the subtle one: with a UTF-16
// encoding the filename and description end on a two-byte NUL, so a one-byte
// scan lands mid-string and the store starts in the wrong place.
func TestMP3JUMBF_UTF16TerminatorsAreTwoBytes(t *testing.T) {
	store := []byte("the real store")
	data := id3Tag(4, 0, id3Frame(4, "GEOB", geobBody(1, id3C2PAMime, store)))
	if got := mp3JUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q", got, store)
	}
}

func TestMP3JUMBF_SkipsFramesBeforeGEOB(t *testing.T) {
	store := []byte("after the title frame")
	frames := append(id3Frame(4, "TIT2", []byte{0, 'a', 'b'}), id3Frame(4, "GEOB", geobBody(0, id3C2PAMime, store))...)
	if got := mp3JUMBF(context.Background(), id3Tag(4, 0, frames)); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q", got, store)
	}
}

func TestMP3JUMBF_WrongMimeIsNotAStore(t *testing.T) {
	data := id3Tag(4, 0, id3Frame(4, "GEOB", geobBody(0, "image/png", []byte("cover art"))))
	if got := mp3JUMBF(context.Background(), data); got != nil {
		t.Errorf("a non-C2PA GEOB must yield nil, got %q", got)
	}
}

// id3Unsync applies ID3v2 unsynchronisation the way a writer does: a 0x00 is
// stuffed after every 0xFF, so the byte stream can never contain a false MPEG
// frame sync.
func id3Unsync(b []byte) []byte {
	var out []byte
	for _, c := range b {
		out = append(out, c)
		if c == 0xFF {
			out = append(out, 0x00)
		}
	}
	return out
}

// TestMP3JUMBF_TagLevelUnsynchronisation: v2.3 unsynchronises the whole tag
// body, so every frame offset shifts. The store deliberately contains 0xFF
// bytes so the transform is not a no-op.
func TestMP3JUMBF_TagLevelUnsynchronisation(t *testing.T) {
	store := []byte{0xFF, 0xE0, 'r', 'e', 'a', 'l', 0xFF, 0xFF, 's', 't', 'o', 'r', 'e'}
	frames := id3Frame(3, "GEOB", geobBody(0, id3C2PAMime, store))
	body := id3Unsync(frames)

	tag := append([]byte("ID3"), 3, 0, 0x80)
	tag = append(tag, id3AppendSynchsafe(len(body))...)
	tag = append(tag, body...)

	if got := mp3JUMBF(context.Background(), tag); !bytes.Equal(got, store) {
		t.Errorf("got % x, want % x", got, store)
	}
}

// TestMP3JUMBF_PerFrameUnsynchronisation: v2.4 unsynchronises per frame (format
// flag 0x02), with the frame size measuring the still-stuffed bytes.
func TestMP3JUMBF_PerFrameUnsynchronisation(t *testing.T) {
	store := []byte{0xFF, 0x00, 0xFF, 0xE7, 'p', 'a', 'y', 'l', 'o', 'a', 'd'}
	raw := geobBody(0, id3C2PAMime, store)
	stuffed := id3Unsync(raw)

	frame := append([]byte("GEOB"), id3AppendSynchsafe(len(stuffed))...)
	frame = append(frame, 0, 0x02)
	frame = append(frame, stuffed...)

	if got := mp3JUMBF(context.Background(), id3Tag(4, 0x80, frame)); !bytes.Equal(got, store) {
		t.Errorf("got % x, want % x", got, store)
	}
}

// TestMP3JUMBF_V24TagFlagWithoutFrameFlag: in v2.4 the tag-level bit only says
// frames MAY be unsynchronised; the frame's own flag governs, so an unflagged
// frame is read as-is.
func TestMP3JUMBF_V24TagFlagWithoutFrameFlag(t *testing.T) {
	store := []byte("no ff bytes here at all")
	data := id3Tag(4, 0x80, id3Frame(4, "GEOB", geobBody(0, id3C2PAMime, store)))
	if got := mp3JUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("got %q, want %q", got, store)
	}
}

func TestMP3JUMBF_NotID3(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("ID3"), []byte("\xff\xfb\x90\x00 raw mpeg"), []byte("ID3\x02\x00\x00\x00\x00\x00\x00")} {
		if got := mp3JUMBF(context.Background(), in); got != nil {
			t.Errorf("input %q: got %q, want nil", in, got)
		}
	}
}

func TestMP3JUMBF_ForgedFrameSize(t *testing.T) {
	body := geobBody(0, id3C2PAMime, []byte("small"))
	frame := append([]byte("GEOB"), id3AppendSynchsafe(0x0FFFFFFF)...)
	frame = append(frame, 0, 0)
	frame = append(frame, body...)
	if got := mp3JUMBF(context.Background(), id3Tag(4, 0, frame)); got != nil {
		t.Errorf("a frame claiming more than the tag holds must yield nil, got %d bytes", len(got))
	}
}

func TestMP3JUMBF_EveryTruncation(t *testing.T) {
	store := []byte("\x00\x00\x00\x08jumbpayload")
	full := id3Tag(4, 0, id3Frame(4, "GEOB", geobBody(0, id3C2PAMime, store)))

	for n := range len(full) {
		if got := mp3JUMBF(context.Background(), full[:n]); got != nil && !bytes.Equal(got, store) {
			t.Fatalf("truncation at %d produced a store that is not the real one: %q", n, got)
		}
	}
	if got := mp3JUMBF(context.Background(), full); !bytes.Equal(got, store) {
		t.Fatalf("the untruncated file must still yield the store, got %q", got)
	}
}

func TestMP3JUMBF_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := id3Tag(4, 0, id3Frame(4, "GEOB", geobBody(0, id3C2PAMime, []byte("store"))))
	if got := mp3JUMBF(ctx, data); got != nil {
		t.Errorf("cancelled context must yield nil, got %q", got)
	}
}

func FuzzMP3Parse(f *testing.F) {
	f.Add(id3Tag(4, 0, id3Frame(4, "GEOB", geobBody(0, id3C2PAMime, []byte("\x00\x00\x00\x08jumb")))))
	f.Add(id3Tag(3, 0, id3Frame(3, "GEOB", geobBody(1, id3C2PAMimeDeprecated, []byte("store")))))
	f.Add(id3Tag(4, 0, id3Frame(4, "TIT2", []byte{0, 'x'})))
	f.Add([]byte("ID3\x04\x00\x00\x7f\x7f\x7f\x7fGEOB\x7f\x7f\x7f\x7f\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		store := mp3JUMBF(context.Background(), data)
		if store == nil {
			return
		}
		if len(store) > len(data) {
			t.Fatalf("returned %d bytes from a %d-byte input", len(store), len(data))
		}
	})
}
