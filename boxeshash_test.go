package c2pa

import (
	"bytes"
	"context"
	"testing"

	"github.com/veraison/go-cose"
)

// boxHashEntriesFor derives a conforming c2pa.hash.boxes boxes[] array from an
// asset: one entry per box, in file order, each hashing that box's bytes. The
// entry for the C2PA store carries an empty hash, since its bytes are never
// hashed.
func boxHashEntriesFor(t testing.TB, boxes []assetBox, asset []byte, alg string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(boxes))
	for _, b := range boxes {
		hash := []byte{}
		if b.name != c2paBoxName {
			hash = hashOf(t, alg, asset[b.start:b.end()])
		}
		out = append(out, map[string]any{
			"names": []any{b.name},
			"hash":  hash,
			"pad":   []byte{},
		})
	}
	return out
}

// buildBoxHashAsset builds a signed asset whose only hard binding is a
// c2pa.hash.boxes assertion.
//
// It builds twice. The first pass has no hard binding at all and exists only to
// lay out the container so its box map can be read; the second embeds the
// box-hash assertion derived from it. That works because a box hash covers box
// CONTENT, not offsets: adding the assertion grows the C2PA store's box — whose
// bytes are never hashed — and shifts everything after it, but changes no other
// box's bytes. The builder asserts the box map really did survive the second
// pass rather than assuming it.
//
// mutate, when non-nil, may rewrite the derived entries to build a negative
// case; it gets the first-pass asset and its box map so it can recompute a hash
// over whatever it changes.
func buildBoxHashAsset(t testing.TB, container Container, frame assetFraming, spec manifestSpec,
	mutate func(asset []byte, boxes []assetBox, entries []map[string]any) []map[string]any,
) []byte {
	t.Helper()
	alg := spec.dataHashAlg
	if alg == "" {
		alg = "sha256"
	}
	base := spec
	base.noHardBinding = true

	first := buildFramedAsset(t, frame, base)
	boxes, ok := assetBoxMap(context.Background(), container, first)
	if !ok {
		t.Fatalf("container %s has no box map", container)
	}
	if len(boxes) == 0 {
		t.Fatal("first-pass asset produced an empty box map")
	}
	entries := boxHashEntriesFor(t, boxes, first, alg)
	if mutate != nil {
		entries = mutate(first, boxes, entries)
	}

	withBoxHash := base
	withBoxHash.extraBinding = &assertionSpec{
		label: "c2pa.hash.boxes",
		value: map[string]any{"boxes": entries},
	}
	asset := buildFramedAsset(t, frame, withBoxHash)

	// The store's own box grows by exactly the assertion just added — that is
	// the point, and its bytes are never hashed. Every OTHER box must come
	// through the second pass byte-identical, or the hashes derived from the
	// first pass describe an asset that no longer exists.
	final, _ := assetBoxMap(context.Background(), container, asset)
	if len(final) != len(boxes) {
		t.Fatalf("box map changed between passes: %v then %v", boxNames(boxes), boxNames(final))
	}
	for i := range final {
		if final[i].name != boxes[i].name {
			t.Fatalf("box map changed between passes: %v then %v", boxNames(boxes), boxNames(final))
		}
		if final[i].name == c2paBoxName {
			continue
		}
		if final[i].length != boxes[i].length ||
			!bytes.Equal(asset[final[i].start:final[i].end()], first[boxes[i].start:boxes[i].end()]) {
			t.Fatalf("box %d (%q) changed between passes", i, boxes[i].name)
		}
	}
	return asset
}

func standardFraming(container Container) assetFraming {
	return func(store []byte) ([]byte, int, int) { return assembleAsset(container, store) }
}

// pngTextFraming frames the store in a PNG that also carries a tEXt chunk, so
// the metadata-exclusion path has something legitimate to exclude.
func pngTextFraming(store []byte) (asset []byte, exclStart, exclLen int) {
	asset = append(asset, pngSignature...)
	asset = append(asset, pngChunk("IHDR", []byte{
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00})...)
	exclStart = len(asset)
	asset = append(asset, pngCaBX(store)...)
	exclLen = len(asset) - exclStart
	asset = append(asset, pngChunk("tEXt", []byte("Comment\x00a caption"))...)
	asset = append(asset, pngChunk("IDAT", []byte{0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01})...)
	asset = append(asset, pngChunk("IEND", nil)...)
	return asset, exclStart, exclLen
}

// indexOfBox finds the entry naming the given box, or fails the test.
func indexOfBox(t testing.TB, boxes []assetBox, name string) int {
	t.Helper()
	for i := range boxes {
		if boxes[i].name == name {
			return i
		}
	}
	t.Fatalf("no %q box in %v", name, boxNames(boxes))
	return -1
}

func boxNames(boxes []assetBox) []string {
	out := make([]string, len(boxes))
	for i := range boxes {
		out[i] = boxes[i].name
	}
	return out
}

// TestBoxHashPositive validates an asset bound by a box hash in each container
// whose box naming C2PA defines.
func TestBoxHashPositive(t *testing.T) {
	for _, container := range []Container{JPEG, PNG, GIF} {
		t.Run(string(container), func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			asset := buildBoxHashAsset(t, container, standardFraming(container), manifestSpec{
				signer:     sb,
				assertions: []assertionSpec{markerAssertion()},
			}, nil)

			res := runCorpus(t, container, asset, sb)
			if !res.Valid {
				t.Fatalf("expected valid, got %v", codes(res))
			}
			if !res.Has(StatusAssertionBoxesHashMatch) {
				t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMatch, codes(res))
			}
			if res.Has(StatusAssertionBoxesHashAdditionalExclusions) {
				t.Errorf("unexpected %s with no exclusions declared", StatusAssertionBoxesHashAdditionalExclusions)
			}
			if res.Has(StatusUnsupported) {
				t.Errorf("box hash reported unsupported; got %v", codes(res))
			}
		})
	}
}

// TestBoxHashDetectsTamperedContent is the point of a hard binding: editing a
// byte the manifest does not cover must break it.
func TestBoxHashDetectsTamperedContent(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildBoxHashAsset(t, PNG, standardFraming(PNG), manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion()},
	}, nil)

	boxes, _ := assetBoxMap(context.Background(), PNG, asset)
	idat := boxes[indexOfBox(t, boxes, "IDAT")]
	tampered := append([]byte(nil), asset...)
	tampered[idat.start+9] ^= 0xFF // inside the chunk's data

	res := runCorpus(t, PNG, tampered, sb)
	if res.Valid {
		t.Fatalf("expected invalid after editing IDAT, got %v", codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashMismatch) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMismatch, codes(res))
	}
}

// TestBoxHashUnknownBox covers the two ways the assertion can fail to describe
// the asset: a name that does not match, and a box left uncovered.
func TestBoxHashUnknownBox(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(asset []byte, boxes []assetBox, entries []map[string]any) []map[string]any
	}{
		{
			name: "renamed box",
			mutate: func(_ []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
				entries[indexOfBox(t, boxes, "IDAT")]["names"] = []any{"IHDR"}
				return entries
			},
		},
		{
			name: "trailing box uncovered",
			mutate: func(_ []byte, _ []assetBox, entries []map[string]any) []map[string]any {
				return entries[:len(entries)-1]
			},
		},
		{
			name: "leading box uncovered",
			mutate: func(_ []byte, _ []assetBox, entries []map[string]any) []map[string]any {
				// Dropping PNGh is legitimate (producers may omit it); dropping
				// PNGh and IHDR both leaves a real chunk unbound.
				return entries[2:]
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			asset := buildBoxHashAsset(t, PNG, standardFraming(PNG), manifestSpec{
				signer:     sb,
				assertions: []assertionSpec{markerAssertion()},
			}, tc.mutate)

			res := runCorpus(t, PNG, asset, sb)
			if res.Valid {
				t.Fatalf("expected invalid, got %v", codes(res))
			}
			if !res.Has(StatusAssertionBoxesHashUnknownBox) {
				t.Errorf("missing %s; got %v", StatusAssertionBoxesHashUnknownBox, codes(res))
			}
		})
	}
}

// TestBoxHashOmittedPNGHeader checks the one box a producer may legitimately
// leave out: PNG's signature, which predates the box-hash convention.
func TestBoxHashOmittedPNGHeader(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildBoxHashAsset(t, PNG, standardFraming(PNG), manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion()},
	}, func(_ []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
		if boxes[0].name != pngHeaderBoxName {
			t.Fatalf("expected the first box to be %s, got %s", pngHeaderBoxName, boxes[0].name)
		}
		return entries[1:]
	})

	res := runCorpus(t, PNG, asset, sb)
	if !res.Valid {
		t.Fatalf("expected valid without the PNGh entry, got %v", codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashMatch) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMatch, codes(res))
	}
}

// TestBoxHashMalformed covers the structural rejections, which are reported as
// malformed rather than as a mismatch because nothing was compared.
func TestBoxHashMalformed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(asset []byte, boxes []assetBox, entries []map[string]any) []map[string]any
	}{
		{
			name: "C2PA grouped with a following box",
			mutate: func(_ []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
				i := indexOfBox(t, boxes, c2paBoxName)
				entries[i]["names"] = []any{c2paBoxName, boxes[i+1].name}
				return append(entries[:i+1], entries[i+2:]...)
			},
		},
		{
			// The store must not be smuggled in behind another name either:
			// grouping it after a box would take that box out of the hash.
			name: "C2PA grouped behind a preceding box",
			mutate: func(_ []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
				i := indexOfBox(t, boxes, c2paBoxName)
				entries[i-1]["names"] = []any{boxes[i-1].name, c2paBoxName}
				return append(entries[:i], entries[i+1:]...)
			},
		},
		{
			name: "empty exclusions array",
			mutate: func(_ []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
				entries[indexOfBox(t, boxes, "IDAT")]["exclusions"] = []any{}
				return entries
			},
		},
		{
			name: "exclusions without boxIndex on a multi-box entry",
			mutate: func(asset []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
				i := indexOfBox(t, boxes, "IDAT")
				entries[i]["names"] = []any{boxes[i].name, boxes[i+1].name}
				entries[i]["hash"] = hashOf(t, "sha256", asset[boxes[i].start:boxes[i+1].end()])
				entries[i]["exclusions"] = []any{map[string]any{"start": 8, "length": 1}}
				return append(entries[:i+1], entries[i+2:]...)
			},
		},
		{
			name:   "no boxes",
			mutate: func([]byte, []assetBox, []map[string]any) []map[string]any { return nil },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			asset := buildBoxHashAsset(t, PNG, standardFraming(PNG), manifestSpec{
				signer:     sb,
				assertions: []assertionSpec{markerAssertion()},
			}, tc.mutate)

			res := runCorpus(t, PNG, asset, sb)
			if res.Valid {
				t.Fatalf("expected invalid, got %v", codes(res))
			}
			if !res.Has(StatusAssertionBoxesHashMalformed) {
				t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMalformed, codes(res))
			}
		})
	}
}

// TestBoxHashExclusionOutsidePermittedRange is the attack the permitted-range
// check exists for: an assertion that carves image data out of its own hash so
// the bytes it leaves behind are never bound.
func TestBoxHashExclusionOutsidePermittedRange(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildBoxHashAsset(t, PNG, standardFraming(PNG), manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion()},
	}, func(asset []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
		i := indexOfBox(t, boxes, "IDAT")
		b := boxes[i]
		if len(b.allowed) != 0 {
			t.Fatalf("IDAT should permit no exclusions, got %v", b.allowed)
		}
		// Hash the chunk with its data carved out, so the ONLY thing standing
		// between this assertion and a pass is the permitted-range check.
		h, _ := hashByName("sha256")
		writeGaps(asset, b.start, b.end(), []byteRange{{start: b.start + 8, length: 4}}, h)
		entries[i]["hash"] = h.Sum(nil)
		entries[i]["exclusions"] = []any{map[string]any{"start": 8, "length": 4}}
		return entries
	})

	res := runCorpus(t, PNG, asset, sb)
	if res.Valid {
		t.Fatalf("expected invalid, got %v", codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashMismatch) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMismatch, codes(res))
	}
}

// TestBoxHashMetadataExclusion checks the exclusion that IS permitted: a tEXt
// chunk's payload, which a producer may leave editable after signing. It
// validates, and says so.
func TestBoxHashMetadataExclusion(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildBoxHashAsset(t, PNG, pngTextFraming, manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion()},
	}, func(asset []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
		i := indexOfBox(t, boxes, "tEXt")
		b := boxes[i]
		if len(b.allowed) != 1 || b.allowed[0].kind != exclAssetMetadata {
			t.Fatalf("tEXt should permit one metadata exclusion, got %v", b.allowed)
		}
		excl := b.allowed[0]
		h, _ := hashByName("sha256")
		writeGaps(asset, b.start, b.end(),
			[]byteRange{{start: b.start + excl.start, length: excl.length}}, h)
		entries[i]["hash"] = h.Sum(nil)
		entries[i]["exclusions"] = []any{
			map[string]any{"start": excl.start, "length": excl.length},
		}
		return entries
	})

	res := runCorpus(t, PNG, asset, sb)
	if !res.Valid {
		t.Fatalf("expected valid, got %v", codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashMatch) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMatch, codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashAdditionalExclusions) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashAdditionalExclusions, codes(res))
	}

	// The excluded payload really is unbound: editing it keeps the asset valid.
	boxes, _ := assetBoxMap(context.Background(), PNG, asset)
	text := boxes[indexOfBox(t, boxes, "tEXt")]
	edited := append([]byte(nil), asset...)
	edited[text.start+text.length-1] ^= 0xFF
	if res := runCorpus(t, PNG, edited, sb); !res.Valid {
		t.Errorf("editing the excluded payload should stay valid, got %v", codes(res))
	}
}

// TestBoxHashWholeBoxExcluded covers "excluded": true on a box that is not the
// store, which is permitted but reported.
func TestBoxHashWholeBoxExcluded(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildBoxHashAsset(t, PNG, pngTextFraming, manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion()},
	}, func(_ []byte, boxes []assetBox, entries []map[string]any) []map[string]any {
		i := indexOfBox(t, boxes, "tEXt")
		entries[i]["excluded"] = true
		entries[i]["hash"] = []byte{}
		return entries
	})

	res := runCorpus(t, PNG, asset, sb)
	if !res.Valid {
		t.Fatalf("expected valid, got %v", codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashAdditionalExclusions) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashAdditionalExclusions, codes(res))
	}
}

// TestBoxHashAlgFallback checks that an entry with no alg of its own falls back
// to the claim's, rather than being reported as unsupported.
func TestBoxHashAlgFallback(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildBoxHashAsset(t, PNG, standardFraming(PNG), manifestSpec{
		signer:      sb,
		dataHashAlg: "sha384",
		assertions:  []assertionSpec{markerAssertion()},
	}, nil)

	res := runCorpus(t, PNG, asset, sb)
	if !res.Valid {
		t.Fatalf("expected valid, got %v", codes(res))
	}
	if !res.Has(StatusAssertionBoxesHashMatch) {
		t.Errorf("missing %s; got %v", StatusAssertionBoxesHashMatch, codes(res))
	}
}

// TestBoxHashUnsupportedContainer checks that a box hash on a container with no
// defined box naming is reported as unverified rather than quietly passed or
// falsely failed.
func TestBoxHashUnsupportedContainer(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildAsset(t, RIFF, manifestSpec{
		signer:        sb,
		noHardBinding: true,
		assertions:    []assertionSpec{markerAssertion()},
		extraBinding: &assertionSpec{
			label: "c2pa.hash.boxes",
			value: map[string]any{"boxes": []map[string]any{
				{"names": []any{"RIFF"}, "hash": hashOf(t, "sha256", nil), "pad": []byte{}},
			}},
		},
	})

	res := runCorpus(t, RIFF, asset, sb)
	if !res.Has(StatusUnsupported) {
		t.Errorf("missing %s; got %v", StatusUnsupported, codes(res))
	}
	if res.Has(StatusAssertionBoxesHashMismatch) || res.Has(StatusAssertionBoxesHashMatch) {
		t.Errorf("unverifiable box hash should report neither match nor mismatch; got %v", codes(res))
	}
}

func TestJPEGBoxMap(t *testing.T) {
	// SOI, APP0, a COM segment, SOS with an entropy scan holding a stuffed
	// 0xFF00 and a restart marker, then EOI.
	var asset []byte
	asset = append(asset, 0xFF, 0xD8)
	asset = append(asset, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00)
	asset = append(asset, 0xFF, 0xFE, 0x00, 0x06, 'h', 'i', '!', '!')
	asset = append(asset, 0xFF, 0xDA, 0x00, 0x04, 0x01, 0x01)
	asset = append(asset, 0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD0, 0x33)
	asset = append(asset, 0xFF, 0xD9)

	boxes := jpegBoxMap(context.Background(), asset)
	want := []struct {
		name          string
		start, length int
	}{
		{"SOI", 0, 2},
		{"APP0", 2, 6},
		{"COM", 8, 8},
		{"SOS", 16, 6 + 7},
		{"EOI", 29, 2},
	}
	if len(boxes) != len(want) {
		t.Fatalf("got %v, want %d boxes", boxNames(boxes), len(want))
	}
	for i, w := range want {
		if boxes[i].name != w.name || boxes[i].start != w.start || boxes[i].length != w.length {
			t.Errorf("box %d: got %q [%d,%d), want %q [%d,%d)", i,
				boxes[i].name, boxes[i].start, boxes[i].length, w.name, w.start, w.length)
		}
	}
	// The COM segment's payload is excludable metadata; nothing else here is.
	com := boxes[2]
	if len(com.allowed) != 1 || com.allowed[0].start != 4 || com.allowed[0].kind != exclAssetMetadata {
		t.Errorf("COM allowed exclusions: got %v", com.allowed)
	}
	if len(boxes[3].allowed) != 0 {
		t.Errorf("SOS should permit no exclusions, got %v", boxes[3].allowed)
	}
}

func TestJPEGBoxMapCollapsesC2PARun(t *testing.T) {
	// A store large enough to need two APP11 segments must collapse into one
	// C2PA box, or the box map will not match what the signer wrote.
	store := storeBox(make([]byte, 70000))
	asset, exclStart, exclLen := assembleAsset(JPEG, store)

	boxes := jpegBoxMap(context.Background(), asset)
	i := indexOfBox(t, boxes, c2paBoxName)
	if boxes[i].start != exclStart || boxes[i].length != exclLen {
		t.Errorf("C2PA box: got [%d,+%d), want [%d,+%d)",
			boxes[i].start, boxes[i].length, exclStart, exclLen)
	}
	if n := len(boxes[i].allowed); n != 1 || boxes[i].allowed[0].length != exclLen {
		t.Errorf("C2PA box should be excludable whole, got %v", boxes[i].allowed)
	}
	for j := range boxes {
		if j != i && boxes[j].name == c2paBoxName {
			t.Errorf("C2PA run was not collapsed: %v", boxNames(boxes))
		}
	}
}

func TestPNGBoxMap(t *testing.T) {
	asset, _, _ := pngTextFraming(storeBox(make([]byte, 200)))
	boxes := pngBoxMap(context.Background(), asset)
	want := []string{pngHeaderBoxName, "IHDR", c2paBoxName, c2paBoxName, "tEXt", "IDAT", "IEND"}
	if got := boxNames(boxes); len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if boxes[i].name != w {
			t.Fatalf("got %v, want %v", boxNames(boxes), want)
		}
	}
	// The boxes must tile the file exactly: any gap is a byte the hash misses.
	pos := 0
	for _, b := range boxes {
		if b.start != pos {
			t.Fatalf("box %q starts at %d, want %d", b.name, b.start, pos)
		}
		pos = b.end()
	}
	if pos != len(asset) {
		t.Errorf("boxes cover %d of %d bytes", pos, len(asset))
	}
	text := boxes[4]
	if len(text.allowed) != 1 || text.allowed[0].start != 8 ||
		text.allowed[0].length != text.length-8 || text.allowed[0].kind != exclAssetMetadata {
		t.Errorf("tEXt allowed exclusions: got %v", text.allowed)
	}
	if len(boxes[1].allowed) != 0 {
		t.Errorf("IHDR should permit no exclusions, got %v", boxes[1].allowed)
	}
}

func TestGIFBoxMap(t *testing.T) {
	// Header, logical screen descriptor with a global colour table, a comment
	// extension, the C2PA application extension, one image, then the trailer.
	var asset []byte
	asset = append(asset, "GIF89a"...)
	asset = append(asset, 1, 0, 1, 0, 0x80, 0, 0) // GCT flag set, size field 0 → 6 bytes
	asset = append(asset, 1, 2, 3, 4, 5, 6)
	commentStart := len(asset)
	asset = append(asset, gifExtensionIntroducer, gifCommentLabel)
	asset = append(asset, gifSubBlockChain([]byte("a comment"))...)
	c2paStart := len(asset)
	asset = append(asset, gifExtensionIntroducer, gifApplicationLabel, byte(len(gifC2PAIdentifier)))
	asset = append(asset, gifC2PAIdentifier...)
	asset = append(asset, gifSubBlockChain([]byte("store"))...)
	imageStart := len(asset)
	asset = append(asset, gifImageDescriptor, 0, 0, 0, 0, 1, 0, 1, 0, 0)
	dataStart := len(asset)
	asset = append(asset, 0x02) // LZW minimum code size
	asset = append(asset, gifSubBlockChain([]byte{0x44, 0x01})...)
	trailerStart := len(asset)
	asset = append(asset, gifTrailer)

	boxes := gifBoxMap(context.Background(), asset)
	want := []struct {
		name  string
		start int
	}{
		{"GIF89a", 0},
		{gifLSDBoxName, 6},
		{"21FE", commentStart},
		{c2paBoxName, c2paStart},
		{"2C", imageStart},
		{gifImageDataBoxName, dataStart},
		{"3B", trailerStart},
	}
	if len(boxes) != len(want) {
		t.Fatalf("got %v, want %d boxes", boxNames(boxes), len(want))
	}
	for i, w := range want {
		if boxes[i].name != w.name || boxes[i].start != w.start {
			t.Errorf("box %d: got %q at %d, want %q at %d", i, boxes[i].name, boxes[i].start, w.name, w.start)
		}
	}
	if boxes[1].length != 7+6 {
		t.Errorf("the global colour table should fold into the LSD box, got length %d", boxes[1].length)
	}
	if n := len(boxes[3].allowed); n != 1 || boxes[3].allowed[0].kind != exclManifestOrPadding {
		t.Errorf("the C2PA extension should be excludable whole, got %v", boxes[3].allowed)
	}
	// The comment's sub-block data is excludable; its length prefix is not.
	comment := boxes[2]
	if len(comment.allowed) != 1 || comment.allowed[0].start != gifCommentExtHeader+1 ||
		comment.allowed[0].length != len("a comment") {
		t.Errorf("comment allowed exclusions: got %v", comment.allowed)
	}
	if boxes[len(boxes)-1].end() != len(asset) {
		t.Errorf("boxes cover %d of %d bytes", boxes[len(boxes)-1].end(), len(asset))
	}
}

// TestBoxMapUnparseable checks that a structure this reader cannot walk yields
// no box map at all, rather than a prefix an assertion could match against.
func TestBoxMapUnparseable(t *testing.T) {
	tests := []struct {
		name      string
		container Container
		data      []byte
	}{
		{"jpeg not on a marker", JPEG, []byte{0x00, 0x01, 0x02, 0x03}},
		{"jpeg truncated segment", JPEG, []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x40, 0x01}},
		{"jpeg scan never ends", JPEG, []byte{0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x04, 0x01, 0x01, 0x11, 0x22}},
		{"png bad signature", PNG, make([]byte, 32)},
		{"png chunk past end", PNG, append(append([]byte{}, pngSignature...),
			0xFF, 0xFF, 0xFF, 0xFF, 'I', 'H', 'D', 'R')},
		{"gif too short", GIF, []byte("GIF89a")},
		{"gif no trailer", GIF, append([]byte("GIF89a"), 1, 0, 1, 0, 0, 0, 0)},
		{"gif bad block", GIF, append([]byte("GIF89a"), 1, 0, 1, 0, 0, 0, 0, 0x7F)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			boxes, ok := assetBoxMap(context.Background(), tc.container, tc.data)
			if !ok {
				t.Fatalf("%s should have a box map", tc.container)
			}
			if len(boxes) != 0 {
				t.Errorf("expected no boxes, got %v", boxNames(boxes))
			}
		})
	}
}

// TestBoxMapCancellation checks the walkers honour a cancelled context, which
// is what keeps a large adversarial asset from pinning a caller.
func TestBoxMapCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	jpeg, _, _ := assembleAsset(JPEG, storeBox(make([]byte, 64)))
	png, _, _ := assembleAsset(PNG, storeBox(make([]byte, 64)))
	gif, _, _ := assembleAsset(GIF, storeBox(make([]byte, 64)))
	for _, tc := range []struct {
		container Container
		data      []byte
	}{{JPEG, jpeg}, {PNG, png}, {GIF, gif}} {
		if boxes, _ := assetBoxMap(ctx, tc.container, tc.data); len(boxes) != 0 {
			t.Errorf("%s: expected no boxes on a cancelled context, got %v", tc.container, boxNames(boxes))
		}
	}
}

// TestBoxMapNoContainer checks that containers without a defined box naming say
// so, rather than returning an empty map that reads as "unparseable".
func TestBoxMapNoContainer(t *testing.T) {
	for _, container := range []Container{BMFF, RIFF, TIFF, MP3, SVG, PDF} {
		if _, ok := assetBoxMap(context.Background(), container, nil); ok {
			t.Errorf("%s should report no box map", container)
		}
	}
}

// TestJPEGEntropySize pins the scan-termination rule: stuffed bytes and restart
// markers stay inside the scan, any other marker ends it.
func TestJPEGEntropySize(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"ends at EOI", []byte{0x11, 0x22, 0xFF, 0xD9}, 2},
		{"stuffed byte stays in", []byte{0xFF, 0x00, 0x11, 0xFF, 0xD9}, 3},
		{"restart marker stays in", []byte{0xFF, 0xD0, 0x11, 0xFF, 0xD9}, 3},
		{"fill byte ends the scan", []byte{0x11, 0xFF, 0xFF}, 1},
		{"never terminates", []byte{0x11, 0x22, 0x33}, -1},
		{"truncated after 0xFF", []byte{0x11, 0xFF}, -1},
		{"empty", nil, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := jpegEntropySize(tc.in); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestBoxHashExclusionOrdering pins the "increasing, non-overlapping as given"
// rule: a list that would only make sense sorted is malformed.
func TestBoxHashExclusionOrdering(t *testing.T) {
	boxes := []assetBox{{
		name:    "tEXt",
		start:   100,
		length:  40,
		allowed: []allowedExclusion{{start: 8, length: 32, kind: exclAssetMetadata}},
	}}
	tests := []struct {
		name string
		in   []boxExclusion
		want StatusCode
	}{
		{"in order", []boxExclusion{{start: 8, length: 4}, {start: 16, length: 4}}, ""},
		{"out of order", []boxExclusion{{start: 16, length: 4}, {start: 8, length: 4}},
			StatusAssertionBoxesHashMalformed},
		{"overlapping", []boxExclusion{{start: 8, length: 8}, {start: 12, length: 4}},
			StatusAssertionBoxesHashMalformed},
		{"past the permitted range", []boxExclusion{{start: 8, length: 33}},
			StatusAssertionBoxesHashMismatch},
		{"before the permitted range", []boxExclusion{{start: 0, length: 8}},
			StatusAssertionBoxesHashMismatch},
		{"negative length", []boxExclusion{{start: 8, length: -1}},
			StatusAssertionBoxesHashMalformed},
		{"box index out of range", []boxExclusion{{start: 8, length: 4, boxIndex: 3, hasBoxIndex: true}},
			StatusAssertionBoxesHashMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, got := boxHashExclusionRanges(boxes, 100, 140, tc.in)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
