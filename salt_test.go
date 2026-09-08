package c2pa

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/veraison/go-cose"
)

// TestDataChildSkipsSalt: the data box is chosen by type, not position.
func TestDataChildSkipsSalt(t *testing.T) {
	salt := &box{tbox: "c2sh"}
	data := &box{tbox: "cbor"}
	cases := []struct {
		name string
		in   *box
		want *box
	}{
		{"data only", &box{children: []*box{data}}, data},
		{"salt then data", &box{children: []*box{salt, data}}, data},
		{"salt only", &box{children: []*box{salt}}, nil},
		{"no children", &box{}, nil},
	}
	for _, tc := range cases {
		if got := dataChild(tc.in); got != tc.want {
			t.Errorf("%s: dataChild = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSaltShapesValidate: both salt placements — inside the jumd as c2pa-rs
// writes it, and as a sibling c2sh box before the data box in every assertion,
// the claim and the signature — leave every payload where the reader expects
// it, so the asset validates and the assertions decode.
func TestSaltShapesValidate(t *testing.T) {
	ctx := context.Background()
	shapes := []struct {
		name    string
		apply   func(*manifestSpec)
		sibling bool
	}{
		{"salt in jumd", func(s *manifestSpec) { s.saltAll = true }, false},
		{"sibling salt", func(s *manifestSpec) { s.siblingSaltAll = true }, true},
		{"both", func(s *manifestSpec) { s.saltAll, s.siblingSaltAll = true, true }, true},
	}
	containers := []Container{JPEG, PNG, BMFF}
	for _, sh := range shapes {
		for _, c := range containers {
			for _, v2 := range []bool{false, true} {
				name := sh.name + "/" + string(c)
				if v2 {
					name += "/claimv2"
				}
				t.Run(name, func(t *testing.T) {
					sb := newCorpusSigner(t, cose.AlgorithmES256)
					spec := manifestSpec{signer: sb, claimV2: v2, assertions: []assertionSpec{markerAssertion()}}
					sh.apply(&spec)
					asset := buildAsset(t, c, spec)
					res := runCorpus(t, c, asset, sb)
					if !res.Valid {
						t.Fatalf("expected valid, got %v: %v", codes(res), res.FirstFailure())
					}
					for _, want := range []StatusCode{StatusClaimSignatureValidated, StatusAssertionHashedURIMatch, bindingMatch(c)} {
						if !res.Has(want) {
							t.Errorf("missing %s: %v", want, codes(res))
						}
					}
					if res.Info.Title != "corpus.jpg" {
						t.Errorf("claim did not decode: Info = %+v", res.Info)
					}
					// The marker assertion's payload is the CBOR box, not the salt.
					store := extractJUMBF(ctx, c, asset)
					m := parseStore(ctx, store).active()
					if m == nil {
						t.Fatal("no manifest")
					}
					var found bool
					for _, a := range m.assertions {
						if a.tbox == "c2sh" {
							t.Errorf("assertion %q read its salt as the payload", a.label)
						}
						if a.label == "com.example.marker" {
							found = true
							var got map[string]any
							if err := decMode.Unmarshal(a.data, &got); err != nil || got["marker"] != corpusMarker {
								t.Errorf("marker assertion payload = %v (%v)", got, err)
							}
						}
					}
					if !found {
						t.Error("marker assertion not found")
					}
					// A sibling salt is a box WalkBoxes surfaces; an in-jumd salt is
					// part of the description and is not.
					var saltBoxes int
					WalkBoxes(ctx, store, func(_, tbox string, _ []byte) {
						if tbox == "c2sh" {
							saltBoxes++
						}
					})
					if sh.sibling && saltBoxes < 4 { // hash binding, marker, claim, signature
						t.Errorf("WalkBoxes surfaced %d sibling salt boxes, want at least 4", saltBoxes)
					}
					if !sh.sibling && saltBoxes != 0 {
						t.Errorf("WalkBoxes surfaced %d salt boxes from inside jumd descriptions", saltBoxes)
					}
				})
			}
		}
	}
}

// TestFixturesSaltedAssertionsDecode: every real fixture carrying c2sh salts
// (c2pa-rs writes them inside the jumd) still yields the data box for every
// assertion, and a decodable claim and signature.
func TestFixturesSaltedAssertionsDecode(t *testing.T) {
	ctx := context.Background()
	fixtures := []struct {
		name string
		c    Container
	}{
		{"c2pa_signed.jpg", JPEG}, {"cawg_x509.jpg", JPEG}, {"c2pa_2x_openai.png", PNG},
		{"c2pa_signed_video.mp4", BMFF}, {"legacy_bmff_v1.mp4", BMFF}, {"dash/dashinit.mp4", BMFF},
	}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + fx.name)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte("c2sh")) {
				t.Fatalf("%s carries no salt box; the fixture census is out of date", fx.name)
			}
			store := extractJUMBF(ctx, fx.c, data)
			st := parseStore(ctx, store)
			if len(st.manifests) == 0 {
				t.Fatal("no manifest parsed")
			}
			for _, m := range st.manifests {
				if m.claim == nil || len(m.signature) == 0 {
					t.Errorf("manifest %s: claim decoded %v, signature %d bytes", m.label, m.claim != nil, len(m.signature))
				}
				for _, a := range m.assertions {
					if a.tbox == "c2sh" || len(a.data) == 0 {
						t.Errorf("manifest %s assertion %q: tbox %q, %d bytes", m.label, a.label, a.tbox, len(a.data))
					}
				}
			}
		})
	}
}
