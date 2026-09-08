package c2pa

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/veraison/go-cose"
)

// armBindHook fails the test on a second, different binding decision in one
// call — the double the first-wins rule would otherwise hide.
func armBindHook(t *testing.T) {
	t.Helper()
	bindHook = func(prev, next BindingState) {
		t.Errorf("binding decided twice: %s then %s", prev, next)
	}
	t.Cleanup(func() { bindHook = nil })
}

func TestBindingStateString(t *testing.T) {
	for s, want := range map[BindingState]string{BindingNone: "none", BindingVerified: "verified", BindingFailed: "failed", BindingUnevaluated: "unevaluated", BindingState(9): "unknown"} {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(s), got, want)
		}
	}
}

// TestBindingStates: every site that decides the hard binding's verdict, and
// the state it records.
func TestBindingStates(t *testing.T) {
	armBindHook(t)
	ctx := context.Background()
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	marker := []assertionSpec{markerAssertion()}
	jpegFrame := func(store []byte) ([]byte, []byteRange) { return assembleAsset(JPEG, store) }
	s, sc := newTestSigner(t)
	signedOpts := []ValidateOption{WithSigningTrust(sc.roots), WithOnlineRevocation(false)}

	cases := []struct {
		name string
		run  func(t *testing.T) ValidationResult
		want BindingState
	}{
		{"data hash verified", func(t *testing.T) ValidationResult {
			return runCorpus(t, JPEG, buildAsset(t, JPEG, manifestSpec{signer: sb, claimV2: true, assertions: marker}), sb)
		}, BindingVerified},
		{"data hash mismatch", func(t *testing.T) ValidationResult {
			asset := signBytes(t, s, JPEG, unsignedJPEG(t), createdManifest("b"))
			asset[tamperOutsideStore(JPEG, asset)] ^= 0xFF
			return Validate(ctx, JPEG, bytes.NewReader(asset), signedOpts...)
		}, BindingFailed},
		{"box hash verified", func(t *testing.T) ValidationResult {
			return runCorpus(t, JPEG, buildBoxHashAsset(t, JPEG, jpegFrame, manifestSpec{signer: sb, assertions: marker}, nil), sb)
		}, BindingVerified},
		{"box hash mismatch", func(t *testing.T) ValidationResult {
			asset := buildBoxHashAsset(t, JPEG, jpegFrame, manifestSpec{signer: sb, assertions: marker}, nil)
			asset[len(asset)-1] ^= 0xFF
			return runCorpus(t, JPEG, asset, sb)
		}, BindingFailed},
		{"bmff flat hash verified", func(t *testing.T) ValidationResult {
			asset := signBytes(t, s, BMFF, minimalMP4(false), createdManifest("b"))
			return Validate(ctx, BMFF, bytes.NewReader(asset), signedOpts...)
		}, BindingVerified},
		{"no hard binding", func(t *testing.T) ValidationResult {
			return runCorpus(t, JPEG, buildAsset(t, JPEG, manifestSpec{signer: sb, noHardBinding: true, assertions: marker}), sb)
		}, BindingNone},
		{"v1 bmff binding only", func(t *testing.T) ValidationResult {
			return Validate(ctx, BMFF, bytes.NewReader(fixtureBytes(t, "legacy_bmff_v1.mp4")), WithOnlineRevocation(false))
		}, BindingNone},
		{"update manifest rejected", func(t *testing.T) ValidationResult {
			return runCorpus(t, JPEG, updatedJPEG(t, sb, assertionSpec{label: "c2pa.thumbnail.claim.jpeg", value: map[string]any{"x": 1}}), sb)
		}, BindingNone},
		{"update manifest accepted binds through its parent", func(t *testing.T) ValidationResult {
			return runCorpus(t, JPEG, updatedJPEG(t, sb), sb)
		}, BindingVerified},
		{"no manifest", func(t *testing.T) ValidationResult {
			return Validate(ctx, JPEG, bytes.NewReader(unsignedJPEG(t)))
		}, BindingNone},
		{"scan cap reached", func(t *testing.T) ValidationResult {
			asset := buildAsset(t, JPEG, manifestSpec{signer: sb, claimV2: true, assertions: marker})
			return runCorpus(t, JPEG, asset, sb, WithMaxScan(len(asset)))
		}, BindingUnevaluated},
		{"object-level PDF manifest", func(t *testing.T) ValidationResult {
			pool, data := fixtureSigningPool(t)
			store := extractJUMBF(ctx, JPEG, data)
			return Validate(ctx, PDF, bytes.NewReader(pdfObjectLevelDoc(store, store, false)), WithSigningTrust(pool), WithOnlineRevocation(false))
		}, BindingUnevaluated},
		{"cancelled", func(t *testing.T) ValidationResult {
			asset := buildAsset(t, JPEG, manifestSpec{signer: sb, claimV2: true, assertions: marker})
			return Validate(newCountingContext(3), JPEG, bytes.NewReader(asset), WithSigningTrust(sb.roots))
		}, BindingUnevaluated},
		{"identity failure leaves the binding verified", func(t *testing.T) ValidationResult {
			claimSB, idSB := identitySigners(t)
			res := runCorpus(t, JPEG, identityAsset(t, claimSB, idSB, idBadSig()), claimSB)
			if res.Valid {
				t.Fatal("a bad identity signature must fail the asset")
			}
			return res
		}, BindingVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.run(t)
			if res.Binding != tc.want {
				t.Errorf("Binding = %s, want %s: %v", res.Binding, tc.want, codes(res))
			}
		})
	}
}

// TestBindingStatesFragmented: the split-file paths.
func TestBindingStatesFragmented(t *testing.T) {
	armBindHook(t)
	ctx := context.Background()
	s, sc := newTestSigner(t)
	opts := []ValidateOption{WithSigningTrust(sc.roots), WithOnlineRevocation(false)}
	init, frags := unsignedFragmentedSet(4, fragOpts{})
	outInit, outFrags := signFragmentedSet(t, s, init, frags, createdManifest("frag"))

	if res := ValidateFragmented(ctx, bytes.NewReader(outInit), readersOf(outFrags...), opts...); res.Binding != BindingVerified {
		t.Errorf("full set: %s %v", res.Binding, codes(res))
	}
	if res := ValidateFragmented(ctx, bytes.NewReader(outInit), readersOf(outFrags[:2]...), opts...); res.Binding != BindingUnevaluated {
		t.Errorf("partial set: %s %v", res.Binding, codes(res))
	}
	if res := ValidateFragmented(ctx, bytes.NewReader(outInit), nil, opts...); res.Binding != BindingUnevaluated {
		t.Errorf("no fragments: %s %v", res.Binding, codes(res))
	}
	tampered := append([]byte(nil), outFrags[1]...)
	tampered[len(tampered)-1] ^= 0xFF
	if res := ValidateFragmented(ctx, bytes.NewReader(outInit), readersOf(outFrags[0], tampered, outFrags[2], outFrags[3]), opts...); res.Binding != BindingFailed {
		t.Errorf("tampered fragment: %s %v", res.Binding, codes(res))
	}
	if res := ValidateFragmented(ctx, bytes.NewReader(outInit), []io.Reader{nil, nil, nil, nil}, opts...); res.Binding != BindingUnevaluated {
		t.Errorf("unreadable fragments: %s %v", res.Binding, codes(res))
	}
	// The init alone through Validate: proven as far as it goes, the rest is
	// in other files.
	if res := Validate(ctx, BMFF, bytes.NewReader(outInit), opts...); res.Binding != BindingUnevaluated {
		t.Errorf("init alone: %s %v", res.Binding, codes(res))
	}
}

// TestBindingStatesMerkle: the flat merkle file, through the step itself.
func TestBindingStatesMerkle(t *testing.T) {
	armBindHook(t)
	run := func(asset []byte, assertion map[string]any) ValidationResult {
		v := &validator{ctx: context.Background(), cfg: validateConfig{maxScan: ValidateMaxScan}, container: BMFF, data: asset}
		start := len(v.res.Statuses)
		v.verifyBMFFHash(&rawAssertion{label: "c2pa.hash.bmff.v3", data: mustMarshalCBOR(t, assertion)}, "urn:test")
		v.bindFromStep(start, StatusAssertionBMFFHashMatch)
		return v.finish()
	}
	ff := fragmentedFlatAsset(t, 4, 1, 1, 1, nil)
	if res := run(ff.asset, ff.assertion); res.Binding != BindingVerified {
		t.Errorf("flat merkle: %s %v", res.Binding, codes(res))
	}
	tampered := append([]byte(nil), ff.asset...)
	tampered[ff.mdatStart[2]+12] ^= 0xFF
	if res := run(tampered, ff.assertion); res.Binding != BindingFailed {
		t.Errorf("tampered chunk: %s %v", res.Binding, codes(res))
	}
}
