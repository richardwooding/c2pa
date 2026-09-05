package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// tiffDoc builds a classic TIFF with a single IFD holding one entry.
type tiffDoc struct {
	bigEndian bool
	tag       uint16
	fieldType uint16
	payload   []byte
	// nextIFD overrides the next-IFD offset, for building a circular chain.
	nextIFD uint32
	// declaredSize overrides the entry's value count, for forging a length.
	declaredSize uint32
	forceOffset  bool
}

func (d tiffDoc) build() []byte {
	bo := binary.AppendByteOrder(binary.LittleEndian)
	order := []byte{'I', 'I'}
	if d.bigEndian {
		bo, order = binary.BigEndian, []byte{'M', 'M'}
	}
	size := d.declaredSize
	if size == 0 {
		size = uint32(len(d.payload))
	}

	out := append([]byte{}, order...)
	out = bo.AppendUint16(out, 42)
	out = bo.AppendUint32(out, 8) // first IFD immediately after the header

	const storeOffset = 8 + 2 + 12 + 4
	out = bo.AppendUint16(out, 1)
	out = bo.AppendUint16(out, d.tag)
	out = bo.AppendUint16(out, d.fieldType)
	out = bo.AppendUint32(out, size)
	if len(d.payload) <= 4 && !d.forceOffset {
		inline := append([]byte{}, d.payload...)
		for len(inline) < 4 {
			inline = append(inline, 0)
		}
		out = append(out, inline...)
	} else {
		out = bo.AppendUint32(out, storeOffset)
	}
	out = bo.AppendUint32(out, d.nextIFD)
	return append(out, d.payload...)
}

func TestTIFFJUMBF_BothByteOrders(t *testing.T) {
	store := []byte("\x00\x00\x00\x10jumbthe-store-here")
	for _, be := range []bool{false, true} {
		name := "little-endian"
		if be {
			name = "big-endian"
		}
		t.Run(name, func(t *testing.T) {
			data := tiffDoc{bigEndian: be, tag: tiffC2PATag, fieldType: tiffUndefined, payload: store}.build()
			if got := tiffJUMBF(context.Background(), data); !bytes.Equal(got, store) {
				t.Errorf("got %q, want %q", got, store)
			}
		})
	}
}

func TestTIFFJUMBF_InlineValue(t *testing.T) {
	// A store of four bytes or fewer lives in the entry's value field rather
	// than at an offset. Reading the field as an offset would return garbage.
	store := []byte{1, 2, 3, 4}
	data := tiffDoc{tag: tiffC2PATag, fieldType: tiffUndefined, payload: store}.build()
	if got := tiffJUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("got % x, want % x", got, store)
	}
}

func TestTIFFJUMBF_WrongTagOrType(t *testing.T) {
	store := []byte("a manifest store, allegedly")
	cases := []struct {
		name      string
		tag       uint16
		fieldType uint16
	}{
		{"another tag", 0x0100, tiffUndefined},
		{"right tag, wrong field type", tiffC2PATag, 2 /* ASCII */},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tiffDoc{tag: tc.tag, fieldType: tc.fieldType, payload: store}.build()
			if got := tiffJUMBF(context.Background(), data); got != nil {
				t.Errorf("got %q, want nil", got)
			}
		})
	}
}

func TestTIFFJUMBF_NotTIFF(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("II"),
		[]byte("\xff\xd8\xff\xe0 jpeg"),
		{'I', 'I', 43, 0, 4, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0}, // BigTIFF with a nonsense offset size
		{'X', 'Y', 42, 0, 8, 0, 0, 0},
	} {
		if got := tiffJUMBF(context.Background(), in); got != nil {
			t.Errorf("input % x: got %q, want nil", in, got)
		}
	}
}

// TestTIFFJUMBF_ForgedValueCount is the TIFF analogue of the RIFF forged-size
// case: the entry claims far more payload than the file holds.
func TestTIFFJUMBF_ForgedValueCount(t *testing.T) {
	data := tiffDoc{
		tag: tiffC2PATag, fieldType: tiffUndefined,
		payload: []byte("small"), declaredSize: 0xFFFFFF00, forceOffset: true,
	}.build()
	if got := tiffJUMBF(context.Background(), data); got != nil {
		t.Errorf("a forged value count must yield nil, got %d bytes", len(got))
	}
}

// TestTIFFJUMBF_CircularIFDChainTerminates is the failure mode unique to TIFF:
// a next-IFD offset may point backwards, so a naive walk never returns.
func TestTIFFJUMBF_CircularIFDChainTerminates(t *testing.T) {
	data := tiffDoc{tag: 0x0100, fieldType: tiffUndefined, payload: []byte("no store"), nextIFD: 8}.build()

	done := make(chan []byte, 1)
	go func() { done <- tiffJUMBF(context.Background(), data) }()
	select {
	case got := <-done:
		if got != nil {
			t.Errorf("got %q, want nil", got)
		}
	case <-t.Context().Done():
		t.Fatal("tiffJUMBF did not terminate on a self-referential IFD chain")
	}
}

func TestTIFFJUMBF_EveryTruncation(t *testing.T) {
	store := []byte("\x00\x00\x00\x08jumbpayload")
	full := tiffDoc{tag: tiffC2PATag, fieldType: tiffUndefined, payload: store}.build()

	for n := range len(full) {
		if got := tiffJUMBF(context.Background(), full[:n]); got != nil && !bytes.Equal(got, store) {
			t.Fatalf("truncation at %d produced a store that is not the real one: %q", n, got)
		}
	}
	if got := tiffJUMBF(context.Background(), full); !bytes.Equal(got, store) {
		t.Fatalf("the untruncated file must still yield the store, got %q", got)
	}
}

func TestTIFFJUMBF_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := tiffDoc{tag: tiffC2PATag, fieldType: tiffUndefined, payload: []byte("store")}.build()
	if got := tiffJUMBF(ctx, data); got != nil {
		t.Errorf("cancelled context must yield nil, got %q", got)
	}
}

// bigTIFFDoc builds a BigTIFF with a single IFD holding one entry, mirroring
// tiffDoc at the wider field widths: 8-byte offsets and counts, 20-byte entries.
func bigTIFFDoc(bigEndian bool, tag, fieldType uint16, payload []byte, declaredSize uint64) []byte {
	bo := binary.AppendByteOrder(binary.LittleEndian)
	order := []byte{'I', 'I'}
	if bigEndian {
		bo, order = binary.BigEndian, []byte{'M', 'M'}
	}
	size := declaredSize
	if size == 0 {
		size = uint64(len(payload))
	}

	out := append([]byte{}, order...)
	out = bo.AppendUint16(out, 43)
	out = bo.AppendUint16(out, 8)  // offset size
	out = bo.AppendUint16(out, 0)  // reserved
	out = bo.AppendUint64(out, 16) // first IFD right after the header

	const storeOffset = 16 + 8 + 20 + 8 // header, count, one entry, next-IFD
	out = bo.AppendUint64(out, 1)
	out = bo.AppendUint16(out, tag)
	out = bo.AppendUint16(out, fieldType)
	out = bo.AppendUint64(out, size)
	if len(payload) <= 8 && declaredSize == 0 {
		inline := append([]byte{}, payload...)
		for len(inline) < 8 {
			inline = append(inline, 0)
		}
		out = append(out, inline...)
	} else {
		out = bo.AppendUint64(out, storeOffset)
	}
	out = bo.AppendUint64(out, 0) // no next IFD
	return append(out, payload...)
}

func TestBigTIFFJUMBF_BothByteOrders(t *testing.T) {
	store := []byte("\x00\x00\x00\x10jumbthe-bigtiff-store")
	for _, be := range []bool{false, true} {
		name := "little-endian"
		if be {
			name = "big-endian"
		}
		t.Run(name, func(t *testing.T) {
			data := bigTIFFDoc(be, tiffC2PATag, tiffUndefined, store, 0)
			if got := tiffJUMBF(context.Background(), data); !bytes.Equal(got, store) {
				t.Errorf("got %q, want %q", got, store)
			}
		})
	}
}

// TestBigTIFFJUMBF_InlineValue: BigTIFF inlines up to EIGHT bytes in the value
// field, not four — a store of 5-8 bytes is inline here and offset in classic.
func TestBigTIFFJUMBF_InlineValue(t *testing.T) {
	store := []byte{1, 2, 3, 4, 5, 6, 7}
	data := bigTIFFDoc(false, tiffC2PATag, tiffUndefined, store, 0)
	if got := tiffJUMBF(context.Background(), data); !bytes.Equal(got, store) {
		t.Errorf("got % x, want % x", got, store)
	}
}

// TestBigTIFFJUMBF_ForgedCounts: both eight-byte counts an adversary controls —
// the IFD's entry count and the entry's element count — claiming more than the
// file holds.
func TestBigTIFFJUMBF_ForgedCounts(t *testing.T) {
	forgedSize := bigTIFFDoc(false, tiffC2PATag, tiffUndefined, []byte("small"), 1<<40)
	if got := tiffJUMBF(context.Background(), forgedSize); got != nil {
		t.Errorf("a forged element count must yield nil, got %d bytes", len(got))
	}

	forgedEntries := bigTIFFDoc(false, tiffC2PATag, tiffUndefined, []byte("small"), 0)
	binary.LittleEndian.PutUint64(forgedEntries[16:24], 1<<50) // IFD claims 2^50 entries
	if got := tiffJUMBF(context.Background(), forgedEntries); got != nil {
		t.Errorf("a forged IFD entry count must yield nil, got %d bytes", len(got))
	}
}

func TestBigTIFFJUMBF_EveryTruncation(t *testing.T) {
	store := []byte("\x00\x00\x00\x08jumbpayload")
	full := bigTIFFDoc(false, tiffC2PATag, tiffUndefined, store, 0)
	for n := range len(full) {
		if got := tiffJUMBF(context.Background(), full[:n]); got != nil && !bytes.Equal(got, store) {
			t.Fatalf("truncation at %d produced a store that is not the real one: %q", n, got)
		}
	}
	if got := tiffJUMBF(context.Background(), full); !bytes.Equal(got, store) {
		t.Fatalf("the untruncated file must still yield the store, got %q", got)
	}
}

func FuzzTIFFParse(f *testing.F) {
	f.Add(tiffDoc{tag: tiffC2PATag, fieldType: tiffUndefined, payload: []byte("\x00\x00\x00\x08jumb")}.build())
	f.Add(tiffDoc{bigEndian: true, tag: tiffC2PATag, fieldType: tiffUndefined, payload: []byte("store")}.build())
	f.Add(tiffDoc{tag: 0x0100, fieldType: 3, payload: []byte{1, 2}, nextIFD: 8}.build())
	f.Add([]byte{'I', 'I', 42, 0, 0xff, 0xff, 0xff, 0xff})
	f.Add(bigTIFFDoc(false, tiffC2PATag, tiffUndefined, []byte("\x00\x00\x00\x08jumb"), 0))
	f.Add(bigTIFFDoc(true, 0x0100, 3, []byte{1, 2}, 0))

	f.Fuzz(func(t *testing.T, data []byte) {
		store := tiffJUMBF(context.Background(), data)
		if store == nil {
			return
		}
		if len(store) > len(data) {
			t.Fatalf("returned %d bytes from a %d-byte input", len(store), len(data))
		}
	})
}

// TestBigTIFFJUMBF_FirstIFDOverflow pins the nightly fuzzer's find: a bare
// BigTIFF header whose first-IFD pointer is MaxInt64-4. The addition-form
// bounds check (next+ifdCountW > len) wrapped past MaxInt64 to MinInt64+3,
// passed, and the IFD slice panicked with that exact negative bound. Only the
// 8-byte widths can express this — a classic TIFF offset is 32-bit.
func TestBigTIFFJUMBF_FirstIFDOverflow(t *testing.T) {
	data := append([]byte{'I', 'I'}, 43, 0, 8, 0, 0, 0)
	data = binary.LittleEndian.AppendUint64(data, 1<<63-5)
	if got := tiffJUMBF(context.Background(), data); got != nil {
		t.Errorf("got %q, want nil", got)
	}
	// The same wrap through a next-IFD pointer: a valid empty first IFD whose
	// next pointer is the huge value.
	data2 := append([]byte{'I', 'I'}, 43, 0, 8, 0, 0, 0)
	data2 = binary.LittleEndian.AppendUint64(data2, 16) // first IFD right here
	data2 = binary.LittleEndian.AppendUint64(data2, 0)  // zero entries
	data2 = binary.LittleEndian.AppendUint64(data2, 1<<63-5)
	if got := tiffJUMBF(context.Background(), data2); got != nil {
		t.Errorf("next-IFD wrap: got %q, want nil", got)
	}
}
