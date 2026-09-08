package c2pa

import (
	"testing"
)

// TestSoftBindingRegistry pins the embedded snapshot. The counts are asserted
// so a botched refresh is a red test rather than a silent change of verdict:
// every algorithm the snapshot loses starts reporting softBinding.alg.unlisted,
// and the writer starts refusing it.
func TestSoftBindingRegistry(t *testing.T) {
	algs := SoftBindingAlgorithms()
	// The counts recorded in softbindings/README.md for commit a9d96990 (2026-08-20).
	const (
		wantTotal        = 53
		wantWatermarks   = 44
		wantFingerprints = 9
	)
	if len(algs) != wantTotal {
		t.Fatalf("snapshot holds %d algorithms, want %d — refresh softbindings/README.md and this test together", len(algs), wantTotal)
	}
	byType := map[string]int{}
	ids := map[int]string{}
	seen := map[string]bool{}
	for _, a := range algs {
		byType[a.Type]++
		switch a.Type {
		case "watermark", "fingerprint":
		default:
			t.Errorf("%s: type %q is neither watermark nor fingerprint", a.Alg, a.Type)
		}
		if prev, dup := ids[a.Identifier]; dup {
			t.Errorf("identifier %d used by both %s and %s", a.Identifier, prev, a.Alg)
		}
		ids[a.Identifier] = a.Alg
		if seen[a.Alg] {
			t.Errorf("%s appears twice", a.Alg)
		}
		seen[a.Alg] = true
		if a.Alg == "" {
			t.Error("an entry has no alg")
		}
		// Every entry must say what it applies to, one way or the other: the
		// registry uses two keys with two vocabularies and an entry may carry
		// either or both, but never neither.
		if len(a.DecodedMediaTypes) == 0 && len(a.EncodedMediaTypes) == 0 {
			t.Errorf("%s names no media types under either key", a.Alg)
		}
	}
	if byType["watermark"] != wantWatermarks || byType["fingerprint"] != wantFingerprints {
		t.Errorf("snapshot has %d watermark / %d fingerprint, want %d / %d",
			byType["watermark"], byType["fingerprint"], wantWatermarks, wantFingerprints)
	}
}

// TestLookupSoftBindingAlgorithm covers the two entries the library's own
// documentation names: the open ISO standard, and the one that shows how low
// the registration bar is.
func TestLookupSoftBindingAlgorithm(t *testing.T) {
	iscc, ok := LookupSoftBindingAlgorithm("io.iscc.v0")
	if !ok {
		t.Fatal("io.iscc.v0 (ISO 24138) is not in the snapshot")
	}
	if iscc.Type != "fingerprint" || iscc.Identifier != 3 {
		t.Errorf("io.iscc.v0 = %+v, want a fingerprint with identifier 3", iscc)
	}
	if len(iscc.DecodedMediaTypes) == 0 {
		t.Error("io.iscc.v0 names no decoded media types")
	}
	if _, ok := LookupSoftBindingAlgorithm("com.joinmonolith.sha256"); !ok {
		t.Error("com.joinmonolith.sha256 is not in the snapshot")
	}
	// The spec's own worked example uses this, and it is NOT registered —
	// which is why an unlisted algorithm is informational rather than a failure.
	if _, ok := LookupSoftBindingAlgorithm("phash"); ok {
		t.Error(`"phash" is now registered; the reasoning in softbindings/README.md needs revisiting`)
	}
	if _, ok := LookupSoftBindingAlgorithm(""); ok {
		t.Error("the empty algorithm resolved")
	}
	// The snapshot date is public because "unlisted" is only meaningful with it.
	if SoftBindingListSnapshot == "" {
		t.Error("SoftBindingListSnapshot is empty")
	}
}

// TestSoftBindingAlgorithmsIsACopy pins that package data cannot be mutated
// through the accessor.
func TestSoftBindingAlgorithmsIsACopy(t *testing.T) {
	first := SoftBindingAlgorithms()
	if len(first) == 0 {
		t.Fatal("no algorithms")
	}
	want := first[0].Alg
	first[0].Alg = "mutated"
	if again := SoftBindingAlgorithms(); again[0].Alg != want {
		t.Errorf("mutating the result changed the package data: %q", again[0].Alg)
	}
}
