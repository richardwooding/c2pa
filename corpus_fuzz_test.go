package c2pa

import (
	"bytes"
	"testing"

	"github.com/veraison/go-cose"
)

// corpusSeeds builds generated assets for the fuzz targets. The existing seeds
// are the real fixtures plus hand-written byte literals; these add structurally
// valid JPEG and PNG manifests the mutator can start from, so it explores box
// trees that already parse instead of spending its budget rediscovering the
// container framing.
//
// Seeds are built rather than committed, so nothing lands in testdata/.
func corpusSeeds(t testing.TB) (jpeg, png, store []byte) {
	t.Helper()
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	spec := manifestSpec{signer: sb, assertions: []assertionSpec{markerAssertion()}}
	jpeg = buildAsset(t, JPEG, spec)
	png = buildAsset(t, PNG, spec)
	store = storeBox(buildManifest(t, manifestSpec{signer: sb}))
	return jpeg, png, store
}

func FuzzCorpusRead(f *testing.F) {
	jpeg, png, store := corpusSeeds(f)
	f.Add(jpeg)
	f.Add(png)
	f.Add(store)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range []Container{JPEG, PNG, BMFF} {
			info := Read(t.Context(), c, bytes.NewReader(data))
			if !info.Present && info.ClaimGenerator != "" {
				t.Fatalf("absent manifest reported a generator %q", info.ClaimGenerator)
			}
		}
	})
}

func FuzzCorpusValidate(f *testing.F) {
	jpeg, png, store := corpusSeeds(f)
	f.Add(jpeg)
	f.Add(png)
	f.Add(store)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range []Container{JPEG, PNG, BMFF} {
			res := Validate(t.Context(), c, bytes.NewReader(data), WithOnlineRevocation(false))
			failures := 0
			for _, s := range res.Statuses {
				if s.Code == "" {
					t.Fatalf("status entry with an empty code")
				}
				if s.Severity != s.Code.Severity() {
					t.Fatalf("entry %s severity %v disagrees with Code.Severity() %v",
						s.Code, s.Severity, s.Code.Severity())
				}
				if s.Severity == SeverityFailure {
					failures++
				}
			}
			if res.Valid != (failures == 0) {
				t.Fatalf("Valid=%v with %d failure statuses", res.Valid, failures)
			}
		}
	})
}
