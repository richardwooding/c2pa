package c2pa

import (
	"bytes"
	"context"
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
			if len(exclA) != 1 || exclA[0].start+exclA[0].length > len(outA) {
				t.Fatalf("exclusion %v out of bounds", exclA)
			}
			// Everything outside the exclusion is the original asset.
			rest := append(append([]byte(nil), outA[:exclA[0].start]...), outA[exclA[0].start+exclA[0].length:]...)
			if !bytes.Equal(rest, asset) {
				t.Errorf("bytes outside the exclusion are not the original asset")
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
			// One C2PA box in the map.
			boxes, ok := assetBoxMap(ctx, c, outB)
			if !ok {
				t.Fatal("no box map")
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
	if _, _, err := embedStore(ctx, RIFF, riffFile("WEBP", nil), good); err == nil {
		t.Error("a container without an embedder accepted")
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
