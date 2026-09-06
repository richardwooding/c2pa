package c2pa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// TestEmbedFixtureOracle is the byte-exact oracle: strip the store out of a
// file c2pa-rs wrote and put it back, and the file must come back identical —
// same position, same segmenting, same header fields.
func TestEmbedFixtureOracle(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		container Container
		file      string
	}{
		{"jpeg after APP0, 64000-byte segments, En 0x0211", JPEG, "c2pa_signed.jpg"},
		{"png caBX after IHDR", PNG, "c2pa_2x_openai.png"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fixtureBytes(t, tc.file)
			store := extractJUMBF(ctx, tc.container, fixture)
			if len(store) == 0 {
				t.Fatal("fixture has no store")
			}
			out, excl, err := embedStore(ctx, tc.container, fixture, store)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, fixture) {
				t.Errorf("re-embedding the fixture's own store did not reproduce it (len %d vs %d)", len(out), len(fixture))
			}
			// The exclusion must be exactly the fixture's own c2pa.hash.data range.
			var ranges []byteRange
			for _, a := range parseStore(ctx, store).active().assertions {
				if a.label == "c2pa.hash.data" {
					var m map[string]any
					if err := decMode.Unmarshal(a.data, &m); err != nil {
						t.Fatal(err)
					}
					ranges, _ = exclusionRanges(m["exclusions"], len(fixture))
				}
			}
			if !sameRanges(excl, ranges) {
				t.Errorf("exclusion %v differs from the fixture's %v", excl, ranges)
			}
		})
	}
}

// TestEmbedProperties pins the contract the signing pipeline relies on.
func TestEmbedProperties(t *testing.T) {
	ctx := context.Background()
	storeA := storeBox(superBox(uuidC2MA, "urn:c2pa:a", assertionBox("com.a", []byte{0xA0})))
	storeB := storeBox(superBox(uuidC2MA, "urn:c2pa:b", assertionBox("com.b", bytes.Repeat([]byte{1}, 70000))))
	for _, c := range signableContainers {
		t.Run(string(c), func(t *testing.T) {
			asset := unsignedInput(t, c)
			outA, exclA, err := embedStore(ctx, c, asset, storeA)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range exclA {
				if r.start < 0 || r.start+r.length > len(outA) {
					t.Fatalf("exclusion %v out of bounds", exclA)
				}
			}
			// For the pure insertions, everything outside the exclusion is the
			// original asset. RIFF rewrites its size (and adds VP8X), TIFF appends
			// an IFD and relinks, MP3 rebuilds the tag, SVG binds a prefix.
			if c == JPEG || c == PNG {
				rest := append(append([]byte(nil), outA[:exclA[0].start]...), outA[exclA[0].start+exclA[0].length:]...)
				if !bytes.Equal(rest, asset) {
					t.Errorf("bytes outside the exclusion are not the original asset")
				}
			}
			// Re-embedding replaces rather than accumulates.
			outAB, _, err := embedStore(ctx, c, outA, storeB)
			if err != nil {
				t.Fatal(err)
			}
			outB, _, err := embedStore(ctx, c, asset, storeB)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(outAB, outB) {
				t.Errorf("embed(embed(a, A), B) != embed(a, B)")
			}
			// One C2PA box in the map, for the containers that have one.
			boxes, ok := assetBoxMap(ctx, c, outB)
			if !ok {
				return
			}
			n := 0
			for _, name := range boxNames(boxes) {
				if name == "C2PA" {
					n++
				}
			}
			if n != 1 {
				t.Errorf("C2PA named %d times: %v", n, boxNames(boxes))
			}
		})
	}
}

// TestEmbedRefuses: garbage, the wrong container, and a store that is not one.
func TestEmbedRefuses(t *testing.T) {
	ctx := context.Background()
	good := storeBox(superBox(uuidC2MA, "urn:c2pa:a", assertionBox("com.a", []byte{0xA0})))
	if _, _, err := embedStore(ctx, JPEG, []byte("nope"), good); err == nil {
		t.Error("garbage accepted as JPEG")
	}
	if _, _, err := embedStore(ctx, PNG, unsignedJPEG(t), good); err == nil {
		t.Error("a JPEG accepted as PNG")
	}
	if _, _, err := embedStore(ctx, JPEG, unsignedJPEG(t), []byte("not a store")); err == nil {
		t.Error("a non-store accepted")
	}
	jpg := unsignedJPEG(t)
	if _, _, err := embedStore(ctx, JPEG, jpg[:len(jpg)/2], good); err == nil {
		t.Error("a JPEG with no start of scan accepted")
	}
	if _, _, err := embedStore(ctx, BMFF, fixtureBytes(t, "video_no_manifest.mp4"), good); err == nil {
		t.Error("a container without an embedder accepted")
	}
}

// storeOf is a small valid store carrying one assertion of the given size.
func storeOf(payloadLen int) []byte {
	return storeBox(superBox(uuidC2MA, "urn:c2pa:test", assertionBox("com.test", bytes.Repeat([]byte{0x42}, payloadLen))))
}

// TestEmbedGIF pins the GIF specifics: the version is forced to 89a, the
// extension lands after the global colour table and before the first image,
// and an existing C2PA extension is replaced.
func TestEmbedGIF(t *testing.T) {
	ctx := context.Background()
	store := storeOf(600)                                     // three sub-blocks
	gif87 := append([]byte("GIF87a"), 1, 0, 1, 0, 0x80, 0, 0) // global colour table of 2 entries
	gif87 = append(gif87, 1, 2, 3, 4, 5, 6)
	gif87 = append(gif87, gifImage([]byte{0x44, 0x01})...)
	gif87 = append(gif87, gifTrailer)
	out, excl, err := embedStore(ctx, GIF, gif87, store)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:6]) != "GIF89a" {
		t.Errorf("version not forced to 89a: %q", out[:6])
	}
	if excl[0].start != 13+6 {
		t.Errorf("extension at %d, want right after the colour table at 19", excl[0].start)
	}
	if out[excl[0].start] != gifExtensionIntroducer || out[excl[0].start+excl[0].length-1] != 0 {
		t.Errorf("exclusion does not span introducer through terminator")
	}
	again, _, err := embedStore(ctx, GIF, out, storeOf(10))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(again, []byte(gifC2PAIdentifier)) != 1 {
		t.Errorf("re-sign left %d C2PA extensions", bytes.Count(again, []byte(gifC2PAIdentifier)))
	}
	if _, _, err := embedStore(ctx, GIF, gif87[:len(gif87)-1], store); err == nil {
		t.Error("a GIF without a trailer accepted")
	}
}

// TestEmbedRIFF pins the RIFF specifics across its three formats.
func TestEmbedRIFF(t *testing.T) {
	ctx := context.Background()
	store := storeOf(100)
	if len(store)%2 == 0 {
		store = storeOf(101)
	}
	// An odd-length store: the chunk gets a pad byte, which stays hashed.
	t.Run("simple webp gains VP8X", func(t *testing.T) {
		out, excl, err := embedStore(ctx, RIFF, unsignedWebP(), store)
		if err != nil {
			t.Fatal(err)
		}
		_, end, children, err := riffPlan(ctx, out)
		if err != nil {
			t.Fatal(err)
		}
		if len(children) != 3 || children[0].id != "VP8X" || children[1].id != "VP8L" || children[2].id != riffC2PAChunk {
			t.Fatalf("children = %+v", children)
		}
		vp8x := out[children[0].start+8 : children[0].start+8+10]
		if vp8x[0] != 0 || vp8x[4] != 0 || vp8x[7] != 0 { // flags none; 1×1 → w-1 = h-1 = 0
			t.Errorf("VP8X = % x", vp8x)
		}
		if end != len(out) || excl[0].length != 8+len(store) || excl[0].start+excl[0].length != len(out)-1 {
			t.Errorf("C2PA chunk should be last with its pad byte outside the exclusion: end %d len %d excl %v", end, len(out), excl)
		}
		if got := binary.LittleEndian.Uint32(out[4:8]); int(got)+8 != len(out) {
			t.Errorf("RIFF size %d does not cover the %d-byte file", got, len(out))
		}
		// Alpha in the VP8L header sets the VP8X alpha flag.
		alpha := riffFile("WEBP", riffChunk("VP8L", []byte{0x2F, 0x00, 0x00, 0x00, 0x10}))
		out2, _, err := embedStore(ctx, RIFF, alpha, store)
		if err != nil {
			t.Fatal(err)
		}
		if out2[12+8] != 0x10 {
			t.Errorf("VP8X flags = %#x, want the alpha bit", out2[12+8])
		}
	})
	t.Run("extended webp keeps its VP8X", func(t *testing.T) {
		in := riffFile("WEBP", riffChunk("VP8X", make([]byte, 10)), riffChunk("VP8L", []byte{0x2F, 0, 0, 0, 0}))
		out, _, err := embedStore(ctx, RIFF, in, store)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(out, []byte("VP8X")) != 1 {
			t.Errorf("VP8X count = %d", bytes.Count(out, []byte("VP8X")))
		}
	})
	t.Run("wave", func(t *testing.T) {
		if _, _, err := embedStore(ctx, RIFF, unsignedWAV(), store); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("avi with a trailing AVIX container", func(t *testing.T) {
		avix := riffFile("AVIX", riffChunk("movi", []byte{9, 9, 9, 9}))
		avix[0], avix[1], avix[2], avix[3] = 'R', 'I', 'F', 'F'
		in := append(riffFile("AVI ", riffChunk("hdrl", []byte{1, 2, 3, 4})), avix...)
		out, _, err := embedStore(ctx, RIFF, in, store)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasSuffix(out, avix) {
			t.Errorf("the AVIX container was not preserved verbatim")
		}
	})
	t.Run("existing chunk replaced", func(t *testing.T) {
		in := riffFile("WAVE", riffChunk(riffC2PAChunk, []byte("old")), riffChunk("data", []byte{1, 2}))
		out, _, err := embedStore(ctx, RIFF, in, store)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("old")) || bytes.Count(out, []byte(riffC2PAChunk)) != 1 {
			t.Errorf("old chunk not removed")
		}
	})
	t.Run("refusals", func(t *testing.T) {
		bad := riffFile("WEBP", riffChunk("VP8L", []byte{0x2F, 0, 0, 0, 0}))
		binary.LittleEndian.PutUint32(bad[4:8], 1<<30) // size past the file
		if _, _, err := embedStore(ctx, RIFF, bad, store); err == nil {
			t.Error("RIFF size past the file accepted")
		}
		if _, _, err := embedStore(ctx, RIFF, riffFile("WEBP", riffChunk("ICCP", []byte{1})), store); err == nil {
			t.Error("WebP with no bitstream accepted")
		}
	})
}

// TestEmbedTIFF pins the TIFF specifics: a new last IFD holding only the tag,
// both byte orders and BigTIFF, the two exclusion ranges, and the two ways an
// existing entry is neutralised.
func TestEmbedTIFF(t *testing.T) {
	ctx := context.Background()
	store := storeOf(50)
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"little-endian", unsignedTIFF(false)},
		{"big-endian", unsignedTIFF(true)},
		{"bigtiff", bigTIFFDoc(false, 256, 3, []byte{1, 0}, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, excl, err := embedStore(ctx, TIFF, tc.in, store)
			if err != nil {
				t.Fatal(err)
			}
			l, _ := parseTIFFLayout(out)
			chain, err := l.ifds(ctx, out)
			if err != nil {
				t.Fatal(err)
			}
			last := chain[len(chain)-1]
			if last.count != 1 || len(chain) != 2 {
				t.Errorf("last IFD has %d entries in a %d-IFD chain; want 1 in 2", last.count, len(chain))
			}
			if len(excl) != 2 || excl[0].start != last.entriesAt+4 || excl[0].length != l.entryCountW || excl[1].length != len(store) {
				t.Errorf("exclusions %v", excl)
			}
			if excl[1].start+excl[1].length != len(out) {
				t.Errorf("the store should end the file")
			}
			// Re-signing our own output truncates the old trailer: size is stable.
			again, _, err := embedStore(ctx, TIFF, out, store)
			if err != nil {
				t.Fatal(err)
			}
			if len(again) != len(out) {
				t.Errorf("re-sign grew the file from %d to %d", len(out), len(again))
			}
		})
	}
	t.Run("entry shared with other tags (c2pa-rs IFD0 placement)", func(t *testing.T) {
		// A store in IFD0 next to the image tags: case B removes the entry in place.
		in := unsignedTIFF(false)
		first, _, err := embedStore(ctx, TIFF, in, store)
		if err != nil {
			t.Fatal(err)
		}
		// Forge IFD0 with an extra 0xCD41 entry pointing at the appended store.
		l, _ := parseTIFFLayout(first)
		chain, _ := l.ifds(ctx, first)
		ifd0 := chain[0]
		entry := make([]byte, 12)
		l.bo.PutUint16(entry[0:2], tiffC2PATag)
		l.bo.PutUint16(entry[2:4], tiffUndefined)
		l.bo.PutUint32(entry[4:8], uint32(len(store)))
		l.bo.PutUint32(entry[8:12], uint32(len(first)-len(store)))
		// Insert the entry at the end of IFD0's table, bumping the count; the
		// bytes after shift, so rebuild: header, IFD0 (+1 entry), rest.
		forged := append(append(append([]byte(nil), first[:ifd0.nextPtrAt]...), entry...), first[ifd0.nextPtrAt:]...)
		l.bo.PutUint16(forged[ifd0.at:ifd0.at+2], uint16(ifd0.count+1))
		// Every offset after IFD0 moved by 12: fix the strip offset, the next-IFD
		// pointer and the forged entry's store offset.
		nextAt := ifd0.nextPtrAt + 12
		l.bo.PutUint32(forged[nextAt:nextAt+4], uint32(chain[1].at+12))
		l.bo.PutUint32(forged[ifd0.nextPtrAt+8:ifd0.nextPtrAt+12], uint32(len(first)-len(store)+12))
		for e := 0; e < ifd0.count; e++ {
			at := ifd0.entriesAt + e*12
			if l.bo.Uint16(forged[at:at+2]) == 273 {
				l.bo.PutUint32(forged[at+8:at+12], l.bo.Uint32(forged[at+8:at+12])+12)
			}
		}
		out, _, err := embedStore(ctx, TIFF, forged, storeOf(60))
		if err != nil {
			t.Fatal(err)
		}
		l2, _ := parseTIFFLayout(out)
		chain2, err := l2.ifds(ctx, out)
		if err != nil {
			t.Fatal(err)
		}
		if chain2[0].count != ifd0.count {
			t.Errorf("IFD0 has %d entries after neutralising, want %d", chain2[0].count, ifd0.count)
		}
		if got := extractJUMBF(ctx, TIFF, out); len(got) != len(storeOf(60)) {
			t.Errorf("the new store is not the one found")
		}
	})
	t.Run("refusals", func(t *testing.T) {
		if _, _, err := embedStore(ctx, TIFF, []byte("II*\x00\x08\x00\x00\x00"), store); err == nil {
			t.Error("a TIFF whose IFD is past the end accepted")
		}
		circular := tiffDoc{tag: 256, fieldType: 3, payload: []byte{1, 0}, nextIFD: 8}.build()
		if _, _, err := embedStore(ctx, TIFF, circular, store); err == nil {
			t.Error("a circular IFD chain accepted")
		}
	})
}

// TestEmbedMP3 pins the ID3 specifics: the tag's version is preserved, other
// frames are copied verbatim, unsynchronisation and the extended header and
// footer are handled, a missing tag is created, and v2.2 is refused.
func TestEmbedMP3(t *testing.T) {
	ctx := context.Background()
	store := storeOf(40)
	audio := []byte{0xFF, 0xFB, 0x90, 0x00, 1, 2, 3}
	title3 := id3Frame(3, "TIT2", []byte{0, 't'})
	title4 := id3Frame(4, "TIT2", []byte{3, 't'})
	cases := []struct {
		name      string
		in        []byte
		wantMajor byte
		keeps     []byte
	}{
		{"v2.4", append(id3Tag(4, 0, title4), audio...), 4, title4},
		{"v2.3", append(id3Tag(3, 0, title3), audio...), 3, title3},
		{"v2.3 unsynchronised", append(id3Tag(3, 0x80, id3Unsync(id3Frame(3, "TIT2", []byte{0, 0xFF, 't'}))), audio...), 3, nil},
		{"v2.4 with footer", append(append(id3Tag(4, 0x10, title4), []byte("3DI\x04\x00\x10\x00\x00\x00\x00")...), audio...), 4, title4},
		{"no tag", audio, 4, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, excl, err := embedStore(ctx, MP3, tc.in, store)
			if err != nil {
				t.Fatal(err)
			}
			if out[3] != tc.wantMajor || out[5] != 0 {
				t.Errorf("tag header: major %d flags %#x", out[3], out[5])
			}
			if tc.keeps != nil && !bytes.Contains(out, tc.keeps) {
				t.Errorf("the title frame was not copied verbatim")
			}
			if !bytes.HasSuffix(out, audio) {
				t.Errorf("audio not preserved")
			}
			if !bytes.Equal(out[excl[0].start:excl[0].start+excl[0].length], store) {
				t.Errorf("exclusion does not cover exactly the store")
			}
			tagEnd := 10 + id3Synchsafe(out[6:10])
			if !bytes.Equal(out[tagEnd:], audio) {
				t.Errorf("tag size does not end at the audio")
			}
		})
	}
	unsync := append(id3Tag(3, 0x80, id3Unsync(id3Frame(3, "TIT2", []byte{0, 0xFF, 't'}))), audio...)
	out, _, err := embedStore(ctx, MP3, unsync, store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte{0, 0xFF, 't'}) {
		t.Errorf("v2.3 unsynchronisation was not undone before the frame was copied")
	}
	if _, _, err := embedStore(ctx, MP3, append(id3Tag(2, 0, nil), audio...), store); err == nil {
		t.Error("ID3v2.2 accepted")
	}
	if _, _, err := embedStore(ctx, MP3, id3Tag(4, 0, make([]byte, 100))[:40], store); err == nil {
		t.Error("a tag longer than the file accepted")
	}
}

// TestEmbedSVG pins the XML specifics: prolog and formatting preserved, the
// prefix bound on the root only when absent, <metadata> reused or created, a
// prefixed root, self-closing elements, an existing manifest replaced, a
// conflicting prefix refused.
func TestEmbedSVG(t *testing.T) {
	ctx := context.Background()
	store := storeOf(30)
	encoded := base64.StdEncoding.EncodeToString(store)
	cases := []struct {
		name string
		in   string
		want string // the output, with ENC standing for the base64
	}{
		{"prolog and no metadata", "<?xml version=\"1.0\"?>\n<!-- c -->\n<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>\n",
			"<?xml version=\"1.0\"?>\n<!-- c -->\n<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>ENC</c2pa:manifest></metadata><rect/></svg>\n"},
		{"existing metadata and prefix", "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><x/></metadata></svg>",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>ENC</c2pa:manifest><x/></metadata></svg>"},
		{"self-closing metadata", "<svg xmlns=\"http://www.w3.org/2000/svg\"><metadata/></svg>",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>ENC</c2pa:manifest></metadata></svg>"},
		{"self-closing root", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>ENC</c2pa:manifest></metadata></svg>"},
		{"prefixed root", "<s:svg xmlns:s=\"http://www.w3.org/2000/svg\"><s:rect/></s:svg>",
			"<s:svg xmlns:s=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><s:metadata><c2pa:manifest>ENC</c2pa:manifest></s:metadata><s:rect/></s:svg>"},
		{"existing manifest replaced", "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>AAAA</c2pa:manifest></metadata></svg>",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>ENC</c2pa:manifest></metadata></svg>"},
		{"metadata nested elsewhere is not the target", "<svg xmlns=\"http://www.w3.org/2000/svg\"><g><metadata/></g></svg>",
			"<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"http://c2pa.org/manifest\"><metadata><c2pa:manifest>ENC</c2pa:manifest></metadata><g><metadata/></g></svg>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, excl, err := embedStore(ctx, SVG, []byte(tc.in), store)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.ReplaceAll(tc.want, "ENC", encoded)
			if string(out) != want {
				t.Errorf("got\n%s\nwant\n%s", out, want)
			}
			if string(out[excl[0].start:excl[0].start+excl[0].length]) != encoded {
				t.Errorf("exclusion does not cover the base64 text")
			}
		})
	}
	for name, in := range map[string]string{
		"not svg":           "<html/>",
		"prefix conflict":   "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:c2pa=\"urn:other\"/>",
		"unclosed root":     "<svg xmlns=\"http://www.w3.org/2000/svg\">",
		"not xml":           "hello",
		"non-utf8 encoding": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><svg/>",
	} {
		if _, _, err := embedStore(ctx, SVG, []byte(in), store); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestApplyEdits pins the splice semantics the embedders build on.
func TestApplyEdits(t *testing.T) {
	asset := []byte("0123456789")
	out, placed, remap, err := applyEdits(asset, []edit{
		{at: 7, remove: 2},            // drop "78"
		{at: 2, insert: []byte("AB")}, // before "2"
		{at: 2, remove: 3},            // drop "234" — the insert at 2 lands before it
		{at: 10, insert: []byte("Z")}, // at the very end
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "01AB569Z" {
		t.Errorf("out = %q", out)
	}
	if placed[1] != 2 || placed[3] != len(out)-1 {
		t.Errorf("placed = %v", placed)
	}
	if got, ok := remap(6); !ok || out[got] != '6' {
		t.Errorf("remap(6) = %d,%v", got, ok)
	}
	if _, ok := remap(3); ok {
		t.Errorf("remap inside a removed span should fail")
	}
	if got, ok := remap(9); !ok || out[got] != '9' {
		t.Errorf("remap(9) = %d,%v", got, ok)
	}
	if _, _, _, err := applyEdits(asset, []edit{{at: 2, remove: 3}, {at: 4, remove: 1}}); err == nil {
		t.Error("overlapping removals accepted")
	}
	if _, _, _, err := applyEdits(asset, []edit{{at: 9, remove: 3}}); err == nil {
		t.Error("removal past the end accepted")
	}
}
