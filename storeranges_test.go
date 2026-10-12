package c2pa

import (
	"context"
	"os"
	"testing"

	"github.com/veraison/go-cose"
)

// TestStoreRangesMatchEmbedder holds each container's locator to its embedder:
// what storeRanges finds in an asset the embedder wrote must be exactly the
// exclusions the embedder returned. That is the invariant the §15.12.1.1
// adjustment rests on — "the current length of the entire C2PA Manifest Store
// plus any file format specific extras" is whatever a writer would exclude,
// and the two halves of that convention live in one place per container.
func TestStoreRangesMatchEmbedder(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ctx := context.Background()
	small := storeBox(buildManifest(t, manifestSpec{
		signer: sb, label: "urn:uuid:00000000-0000-4000-8000-0000000000aa",
		noHardBinding: true, assertions: []assertionSpec{markerAssertion()},
	}))
	// Past one APP11 segment, so the JPEG run has continuations to merge.
	large := storeBox(buildManifest(t, manifestSpec{
		signer: sb, label: "urn:uuid:00000000-0000-4000-8000-0000000000ab",
		noHardBinding: true,
		assertions:    []assertionSpec{{label: "com.example.bulk", raw: make([]byte, 70000)}},
	}))
	for _, c := range []Container{JPEG, PNG, GIF, RIFF, TIFF, MP3, SVG} {
		t.Run(string(c), func(t *testing.T) {
			base := unsignedCorpusAsset(c)
			if got := storeRanges(ctx, c, base); got != nil {
				t.Errorf("unsigned asset: storeRanges = %v, want nil", got)
			}
			for _, store := range [][]byte{small, large} {
				out, excl, err := embedStore(ctx, c, base, store)
				if err != nil {
					t.Fatalf("embed: %v", err)
				}
				if got := storeRanges(ctx, c, out); !sameRanges(got, excl) {
					t.Errorf("store of %d bytes: storeRanges = %v, embedder excluded %v", len(store), got, excl)
				}
				// Re-embedding a longer store over it is where the locator
				// earns its keep: same place, new length.
				grown, excl2, err := embedStore(ctx, c, out, large)
				if err != nil {
					t.Fatalf("re-embed: %v", err)
				}
				if got := storeRanges(ctx, c, grown); !sameRanges(got, excl2) {
					t.Errorf("after re-embed: storeRanges = %v, embedder excluded %v", got, excl2)
				}
			}
		})
	}
	for _, c := range []Container{BMFF, PDF} {
		if got := storeRanges(ctx, c, unsignedCorpusAsset(c)); got != nil {
			t.Errorf("%s: storeRanges = %v, want nil (no in-place store to measure)", c, got)
		}
	}
}

// TestStoreRangesMatchRealProducers pins the locators against files other
// writers produced: the exclusion each one recorded in its c2pa.hash.data is
// the range the locator finds, so the convention is c2pa-rs's and OpenAI's
// as well as this package's. The update-manifest fixture is the exception by
// design — its recorded exclusion is the stale one issue #72 is about.
func TestStoreRangesMatchRealProducers(t *testing.T) {
	ctx := context.Background()
	for _, f := range []struct {
		path string
		c    Container
	}{
		{"testdata/c2pa_signed.jpg", JPEG},
		{"testdata/cawg_x509.jpg", JPEG},
		{"testdata/cawg_ica.jpg", JPEG},
		{"testdata/c2pa_2x_openai.png", PNG},
	} {
		t.Run(f.path, func(t *testing.T) {
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			m := parseStore(ctx, extractJUMBF(ctx, f.c, data)).active()
			if m == nil {
				t.Fatal("no active manifest")
			}
			recorded := recordedExclusions(t, m)
			if got := storeRanges(ctx, f.c, data); !sameRanges(got, recorded) {
				t.Errorf("storeRanges = %v, the producer excluded %v", got, recorded)
			}
		})
	}
}
