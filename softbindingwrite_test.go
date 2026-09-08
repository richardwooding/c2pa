package c2pa

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// iscc is the open registered fingerprint the tests write with.
const testSoftAlg = "io.iscc.v0"

// TestSignSoftBinding round-trips soft bindings through the writer and this
// package's own reader. Two containers, not nine: the assertion is
// container-independent, so two prove the plumbing rather than the embedders.
func TestSignSoftBinding(t *testing.T) {
	armBindHook(t)
	ctx := context.Background()
	s, sc := newTestSigner(t)

	for _, c := range []Container{JPEG, BMFF} {
		t.Run(string(c), func(t *testing.T) {
			m := createdManifest("soft bound")
			m.SoftBindings = []SoftBindingInfo{
				{
					Algorithm: testSoftAlg,
					Name:      "whole image",
					Params:    []byte{0xa1, 0x61, 0x6b, 0x01},
					Blocks:    []SoftBindingBlockInfo{{Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}}},
				},
				{
					Algorithm: "com.joinmonolith.sha256",
					Blocks: []SoftBindingBlockInfo{
						{Value: []byte{9, 9}, Timespan: &SoftBindingTimespan{Start: 0, End: 1000}},
						{Value: []byte{8, 8}, Timespan: &SoftBindingTimespan{Start: 1000, End: 2000}},
					},
				},
			}
			out := signBytes(t, s, c, unsignedInput(t, c), m)
			res := Validate(ctx, c, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))

			if !res.Valid {
				t.Fatalf("valid = false: %v", codes(res))
			}
			if res.Binding != BindingVerified {
				t.Errorf("Binding = %s, want verified", res.Binding)
			}
			if len(res.SoftBindings) != 2 {
				t.Fatalf("read back %d soft bindings, want 2: %v", len(res.SoftBindings), codes(res))
			}

			first, second := res.SoftBindings[0], res.SoftBindings[1]
			switch {
			case first.Label != softBindingLabel:
				t.Errorf("first label = %q", first.Label)
			case second.Label != softBindingLabel+"__1":
				t.Errorf("second label = %q, want the __1 instance form", second.Label)
			case first.Algorithm != testSoftAlg || !first.AlgorithmRegistered || first.AlgorithmType != "fingerprint":
				t.Errorf("first = %+v", first)
			case first.AlgorithmFromClaim:
				t.Error("AlgorithmFromClaim is true, but alg was written on the assertion")
			case first.Name != "whole image":
				t.Errorf("name = %q", first.Name)
			case !bytes.Equal(first.Params, []byte{0xa1, 0x61, 0x6b, 0x01}):
				t.Errorf("params = %x — the CDDL asks for a byte string", first.Params)
			case !first.WellFormed || !second.WellFormed:
				t.Error("not well-formed on read-back")
			case len(first.Blocks) != 1 || !bytes.Equal(first.Blocks[0].Value, []byte{1, 2, 3, 4, 5, 6, 7, 8}):
				t.Errorf("first blocks = %+v", first.Blocks)
			case len(second.Blocks) != 2:
				t.Errorf("second blocks = %d, want 2", len(second.Blocks))
			}
			if ts := second.Blocks[1].Scope.Timespan; ts == nil || ts.Start != 1000 || ts.End != 2000 {
				t.Errorf("second block timespan = %+v", ts)
			}
			// Optional fields we did not set must be absent, not empty: a nil
			// []byte would have encoded as CBOR null and read back malformed.
			if second.Name != "" || second.Params != nil || second.URL != "" {
				t.Errorf("unset optionals came back as %q %x %q", second.Name, second.Params, second.URL)
			}
			if second.Blocks[0].Scope.Region != nil || second.Blocks[0].Scope.Extent != nil {
				t.Error("unset scope fields came back present")
			}
			// Both are reported unevaluated — the writer does not get to claim
			// more than the reader can prove.
			for _, sb := range res.SoftBindings {
				if !hasAt(res, StatusSoftBindingUnevaluated, sb.URI) {
					t.Errorf("no softBinding.unevaluated at %s", sb.URI)
				}
			}
		})
	}
}

// TestSignSoftBindingRegion pins that a caller-supplied region of interest is
// carried through verbatim — the library models none, so the bytes are theirs.
func TestSignSoftBindingRegion(t *testing.T) {
	armBindHook(t)
	s, sc := newTestSigner(t)
	region := mustMarshalCBOR(t, map[string]any{"type": "rectangle", "x": 1, "y": 2})

	m := createdManifest("region")
	m.SoftBindings = []SoftBindingInfo{{
		Algorithm: testSoftAlg,
		Blocks:    []SoftBindingBlockInfo{{Value: []byte{7}, Region: region}},
	}}
	out := signBytes(t, s, JPEG, unsignedJPEG(t), m)
	res := Validate(context.Background(), JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))

	if !res.Valid || len(res.SoftBindings) != 1 {
		t.Fatalf("valid=%v soft bindings=%d: %v", res.Valid, len(res.SoftBindings), codes(res))
	}
	if got := res.SoftBindings[0].Blocks[0].Scope.Region; !bytes.Equal(got, region) {
		t.Errorf("region round-tripped as %x, want %x", got, region)
	}
}

// TestSignSoftBindingRefused walks every refusal. Each must be
// ErrManifestInvalid and must write nothing.
func TestSignSoftBindingRefused(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestSigner(t)
	jpg := unsignedJPEG(t)

	cases := []struct {
		name   string
		sbs    []SoftBindingInfo
		expect string
	}{
		{"no algorithm", []SoftBindingInfo{{Blocks: []SoftBindingBlockInfo{{Value: []byte{1}}}}}, "no algorithm"},
		{"unlisted algorithm", []SoftBindingInfo{{Algorithm: "phash", Blocks: []SoftBindingBlockInfo{{Value: []byte{1}}}}}, "not in the C2PA soft binding algorithm list"},
		{"no blocks", []SoftBindingInfo{{Algorithm: testSoftAlg}}, "no blocks"},
		{"empty value", []SoftBindingInfo{{Algorithm: testSoftAlg, Blocks: []SoftBindingBlockInfo{{Value: nil}}}}, "no value"},
		{"second one bad", []SoftBindingInfo{
			{Algorithm: testSoftAlg, Blocks: []SoftBindingBlockInfo{{Value: []byte{1}}}},
			{Algorithm: "made.up.v1", Blocks: []SoftBindingBlockInfo{{Value: []byte{2}}}},
		}, "soft binding 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := createdManifest("refused")
			m.SoftBindings = tc.sbs
			var out bytes.Buffer
			err := s.Sign(ctx, JPEG, bytes.NewReader(jpg), &out, m)
			if !errors.Is(err, ErrManifestInvalid) {
				t.Fatalf("err = %v, want ErrManifestInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("err = %q, want it to mention %q", err, tc.expect)
			}
			if out.Len() != 0 {
				t.Errorf("wrote %d bytes on refusal", out.Len())
			}
		})
	}
}

// TestSoftBindingLabelIsReserved pins the one behaviour change: the untyped
// path cannot write a soft binding any more, because it cannot get the byte
// strings, the pad or the algorithm check right.
func TestSoftBindingLabelIsReserved(t *testing.T) {
	s, _ := newTestSigner(t)
	m := createdManifest("raw")
	m.Assertions = []Assertion{{Label: softBindingLabel, Value: map[string]any{"alg": testSoftAlg}}}
	var out bytes.Buffer
	err := s.Sign(context.Background(), JPEG, bytes.NewReader(unsignedJPEG(t)), &out, m)
	if !errors.Is(err, ErrManifestInvalid) || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err = %v, want a reserved-label refusal", err)
	}
	// …and the instance form too.
	m.Assertions[0].Label = softBindingLabel + "__1"
	if err := s.Sign(context.Background(), JPEG, bytes.NewReader(unsignedJPEG(t)), &out, m); !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("instance label not reserved: %v", err)
	}
}

// TestSignSoftBindingResign carries soft bindings across a re-sign: the new
// manifest writes its own, and the prior manifest keeps the ones it had.
func TestSignSoftBindingResign(t *testing.T) {
	armBindHook(t)
	ctx := context.Background()
	s, sc := newTestSigner(t)

	first := createdManifest("first")
	first.SoftBindings = []SoftBindingInfo{{Algorithm: testSoftAlg, Blocks: []SoftBindingBlockInfo{{Value: []byte{1, 1}}}}}
	once := signBytes(t, s, JPEG, unsignedJPEG(t), first)

	second := openedManifest("second")
	second.SoftBindings = []SoftBindingInfo{{Algorithm: "com.joinmonolith.sha256", Blocks: []SoftBindingBlockInfo{{Value: []byte{2, 2}}}}}
	twice := signBytes(t, s, JPEG, once, second)

	res := Validate(ctx, JPEG, bytes.NewReader(twice), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Valid {
		t.Fatalf("valid = false: %v", codes(res))
	}
	// Only the ACTIVE manifest's are listed, so the ingredient's soft binding
	// does not appear here even though it is still in the store.
	if len(res.SoftBindings) != 1 {
		t.Fatalf("SoftBindings = %d, want 1 (the active manifest's)", len(res.SoftBindings))
	}
	if got := res.SoftBindings[0]; got.Algorithm != "com.joinmonolith.sha256" || !bytes.Equal(got.Blocks[0].Value, []byte{2, 2}) {
		t.Errorf("active soft binding = %+v", got)
	}
	if !res.Has(StatusIngredientManifestValidated) {
		t.Errorf("the prior manifest did not validate as an ingredient: %v", codes(res))
	}
}
