package c2pa

import (
	"bytes"
	"context"
	"testing"
)

// FuzzSign runs the whole writer over arbitrary bytes for every supported
// container. Contract: never panic; when Sign succeeds the output validates
// with the signer's own root; when it fails nothing is written.
func FuzzSign(f *testing.F) {
	s, sc := newTestSigner(f)
	f.Add(unsignedJPEG(f), uint8(0))
	f.Add(unsignedPNG(f), uint8(1))
	f.Add(fixtureBytes(f, "c2pa_signed.jpg"), uint8(0))
	f.Add(unsignedGIF(f), uint8(2))
	f.Add(unsignedWebP(), uint8(3))
	f.Add(unsignedWAV(), uint8(3))
	f.Add(unsignedTIFF(false), uint8(4))
	f.Add(unsignedTIFF(true), uint8(4))
	f.Add(unsignedMP3(), uint8(5))
	f.Add(unsignedSVG(), uint8(6))
	f.Add(minimalMP4(false), uint8(7))
	f.Add(minimalAVIF(true), uint8(7))
	f.Add(unsignedPDF(false), uint8(8))
	f.Add(unsignedPDF(true), uint8(8))
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9}, uint8(0))
	f.Add([]byte{}, uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, which uint8) {
		if len(data) > 1<<20 {
			return
		}
		c := signableContainers[int(which)%len(signableContainers)]
		var out bytes.Buffer
		err := s.Sign(context.Background(), c, bytes.NewReader(data), &out, openedManifest("fuzz"))
		if err != nil {
			if out.Len() != 0 {
				t.Fatalf("wrote %d bytes on error %v", out.Len(), err)
			}
			return
		}
		res := Validate(context.Background(), c, bytes.NewReader(out.Bytes()), WithSigningTrust(sc.roots), WithOnlineRevocation(false), WithMaxIngredientDepth(0))
		if !res.Valid {
			t.Fatalf("signed output does not validate: %v", codes(res))
		}
	})
}

// FuzzEmbedStore targets the embedders alone: arbitrary asset bytes and an
// arbitrary store payload must never panic, and a success must read back.
func FuzzEmbedStore(f *testing.F) {
	f.Add(unsignedJPEG(f), []byte{0xA0}, uint8(0))
	f.Add(unsignedPNG(f), []byte{0xA0}, uint8(1))
	f.Add(fixtureBytes(f, "c2pa_signed.jpg"), bytes.Repeat([]byte{7}, 70000), uint8(0))
	f.Add(unsignedGIF(f), bytes.Repeat([]byte{7}, 600), uint8(2))
	f.Add(unsignedWebP(), []byte{0xA0}, uint8(3))
	f.Add(unsignedTIFF(true), []byte{0xA0}, uint8(4))
	f.Add(unsignedMP3(), []byte{0xA0}, uint8(5))
	f.Add(unsignedSVG(), []byte{0xA0}, uint8(6))
	f.Add(minimalMP4(true), []byte{0xA0}, uint8(7))
	f.Add(minimalAVIF(false), []byte{0xA0}, uint8(7))
	f.Add(unsignedPDF(true), []byte{0xA0}, uint8(8))
	f.Fuzz(func(t *testing.T, asset, payload []byte, which uint8) {
		if len(asset) > 1<<20 || len(payload) > 1<<17 {
			return
		}
		c := signableContainers[int(which)%len(signableContainers)]
		store := storeBox(superBox(uuidC2MA, "urn:c2pa:fuzz", assertionBox("com.fuzz", payload)))
		out, excl, err := embedStore(context.Background(), c, asset, store)
		if err != nil {
			return
		}
		for _, r := range excl {
			if r.start < 0 || r.length < 0 || r.start+r.length > len(out) {
				t.Fatalf("exclusion %v outside %d bytes", r, len(out))
			}
		}
		if !bytes.Equal(extractJUMBF(context.Background(), c, out), store) {
			t.Fatalf("store did not read back")
		}
	})
}

// FuzzBMFFEmbed targets the offset rewrite alone: mutated MP4/AVIF bytes must
// never panic, and whenever the embedder succeeds every chunk and item offset
// must still address the bytes it did before.
func FuzzBMFFEmbed(f *testing.F) {
	store := storeBox(superBox(uuidC2MA, "urn:c2pa:fuzz", assertionBox("com.fuzz", []byte{0xA0})))
	f.Add(minimalMP4(false))
	f.Add(minimalMP4(true))
	f.Add(minimalAVIF(false))
	f.Add(minimalAVIF(true))
	f.Add(fixtureBytes(f, "video_no_manifest.mp4")[:4096])
	f.Fuzz(func(t *testing.T, asset []byte) {
		if len(asset) > 1<<20 {
			return
		}
		out, _, err := embedStore(context.Background(), BMFF, asset, store)
		if err != nil {
			return
		}
		before, after := bmffAbsoluteOffsets(t, asset), bmffAbsoluteOffsets(t, out)
		if len(before) != len(after) {
			t.Fatalf("%d offsets became %d", len(before), len(after))
		}
		tables := bmffOffsetTables(asset)
		inOneBox := bmffWithinOneTopLevelBox(asset)
		for i := range before {
			o, n := before[i], after[i]
			if o < 0 || n < 0 || o+8 > len(asset) || n+8 > len(out) {
				continue // an offset that never addressed anything in bounds
			}
			if tables(o, o+8) || !inOneBox(o, o+8) {
				// Garbage input: an offset into a table the rewrite itself changes,
				// or a window straddling a top-level box boundary, which the
				// inserted box legitimately splits. No real chunk does either.
				continue
			}
			if !bytes.Equal(asset[o:o+8], out[n:n+8]) {
				t.Fatalf("offset %d → %d no longer addresses the same bytes", o, n)
			}
		}
	})
}

// bmffOffsetTables reports whether [start, end) overlaps a box the rewrite
// patches — stco, co64, saio, iloc — in data. Real files never point their
// offsets at their own tables; fuzzed ones do.
func bmffOffsetTables(data []byte) func(start, end int) bool {
	var spans [][2]int
	var walk func(boxes []*bmffBox)
	walk = func(boxes []*bmffBox) {
		for _, b := range boxes {
			switch b.typ {
			case "stco", "co64", "saio", "iloc":
				spans = append(spans, [2]int{b.start, b.end})
			}
			walk(b.children)
		}
	}
	walk(parseBMFFBoxes(context.Background(), data))
	return func(start, end int) bool {
		for _, s := range spans {
			if start < s[1] && end > s[0] {
				return true
			}
		}
		return false
	}
}

// bmffWithinOneTopLevelBox reports whether [start, end) lies inside a single
// top-level box of data.
func bmffWithinOneTopLevelBox(data []byte) func(start, end int) bool {
	top := parseBMFFBoxes(context.Background(), data)
	return func(start, end int) bool {
		for _, b := range top {
			if start >= b.start && end <= b.end {
				return true
			}
		}
		return false
	}
}
