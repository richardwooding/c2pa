package c2pa

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// softBindingMap is a well-formed soft binding, before any mutation.
func softBindingMap() map[string]any {
	return map[string]any{
		"alg": "io.iscc.v0",
		"pad": []byte{},
		"blocks": []any{
			map[string]any{
				"scope": map[string]any{},
				"value": []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04},
			},
		},
	}
}

// softBindingSpec boxes a soft binding assertion, applying mutations in order.
// It needs no derived hook: a soft binding references nothing else, so it is
// static and length-stable across the fixpoint's passes by construction.
func softBindingSpec(mutate ...func(map[string]any)) assertionSpec {
	m := softBindingMap()
	for _, f := range mutate {
		f(m)
	}
	return assertionSpec{label: softBindingLabel, value: m}
}

// softBindingAsset is a corpus JPEG carrying the given soft bindings.
func softBindingAsset(t testing.TB, sb *signerBundle, specs ...assertionSpec) []byte {
	t.Helper()
	return buildAsset(t, JPEG, manifestSpec{
		signer:     sb,
		claimV2:    true,
		assertions: append([]assertionSpec{markerAssertion()}, specs...),
	})
}

const softBindingURI = corpusManifestLabel + "/" + softBindingLabel

// TestSoftBindingReported is the shape of the whole feature: a well-formed soft
// binding is reported, listed, and declared unevaluated — and the hard binding
// is entirely unaffected, which is the property that keeps Binding meaning what
// it means.
func TestSoftBindingReported(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	res := runCorpus(t, JPEG, softBindingAsset(t, sb, softBindingSpec()), sb)

	if !res.Valid {
		t.Fatalf("a soft binding must not make an asset invalid: %v", codes(res))
	}
	if res.Binding != BindingVerified {
		t.Errorf("Binding = %s, want verified — a soft binding is not a content binding", res.Binding)
	}
	if len(res.SoftBindings) != 1 {
		t.Fatalf("SoftBindings = %d entries, want 1", len(res.SoftBindings))
	}
	got := res.SoftBindings[0]
	switch {
	case got.Label != softBindingLabel:
		t.Errorf("Label = %q", got.Label)
	case got.URI != softBindingURI:
		t.Errorf("URI = %q, want %q", got.URI, softBindingURI)
	case got.Algorithm != "io.iscc.v0":
		t.Errorf("Algorithm = %q", got.Algorithm)
	case got.AlgorithmFromClaim:
		t.Error("AlgorithmFromClaim is true, but the assertion carried its own alg")
	case !got.AlgorithmRegistered:
		t.Error("io.iscc.v0 is in the snapshot but AlgorithmRegistered is false")
	case got.AlgorithmType != "fingerprint":
		t.Errorf("AlgorithmType = %q, want fingerprint", got.AlgorithmType)
	case !got.WellFormed:
		t.Error("WellFormed is false")
	case len(got.Blocks) != 1 || len(got.Blocks[0].Value) != 8:
		t.Errorf("Blocks = %+v", got.Blocks)
	}
	if !hasAt(res, StatusSoftBindingUnevaluated, softBindingURI) {
		t.Errorf("no softBinding.unevaluated at %s: %v", softBindingURI, codes(res))
	}
	// The explanation must say plainly that nothing was proved.
	for _, s := range res.Statuses {
		if s.Code == StatusSoftBindingUnevaluated {
			if !strings.Contains(s.Explanation, "neither proved nor disproved") ||
				!strings.Contains(s.Explanation, "registered fingerprint") {
				t.Errorf("explanation reads %q", s.Explanation)
			}
		}
	}
}

// TestSoftBindingAlgFromClaim covers the claim's alg_soft as the default, which
// is the one place the algorithm is not in the assertion.
func TestSoftBindingAlgFromClaim(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildAsset(t, JPEG, manifestSpec{
		signer:     sb,
		claimV2:    true,
		claimExtra: map[string]any{"alg_soft": "com.joinmonolith.sha256"},
		assertions: []assertionSpec{markerAssertion(), softBindingSpec(func(m map[string]any) {
			delete(m, "alg")
		})},
	})
	res := runCorpus(t, JPEG, asset, sb)
	if !res.Valid {
		t.Fatalf("valid = false: %v", codes(res))
	}
	if len(res.SoftBindings) != 1 {
		t.Fatalf("SoftBindings = %d", len(res.SoftBindings))
	}
	got := res.SoftBindings[0]
	if got.Algorithm != "com.joinmonolith.sha256" || !got.AlgorithmFromClaim || !got.AlgorithmRegistered {
		t.Errorf("alg = %q fromClaim=%v registered=%v", got.Algorithm, got.AlgorithmFromClaim, got.AlgorithmRegistered)
	}
}

// TestSoftBindingUnlistedAlg pins the deliberate non-enforcement of §9.3.2: the
// spec's OWN example uses "phash", which nobody registered, so an unlisted
// algorithm is informational and the asset stays valid.
func TestSoftBindingUnlistedAlg(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	res := runCorpus(t, JPEG, softBindingAsset(t, sb, softBindingSpec(func(m map[string]any) {
		m["alg"] = "phash"
	})), sb)

	if !res.Valid {
		t.Fatalf("an unlisted algorithm must not fail the asset: %v", codes(res))
	}
	if !hasAt(res, StatusSoftBindingAlgUnlisted, softBindingURI) {
		t.Errorf("no softBinding.alg.unlisted: %v", codes(res))
	}
	if got := res.SoftBindings[0]; got.AlgorithmRegistered || got.AlgorithmType != "" || !got.WellFormed {
		t.Errorf("unlisted binding = %+v", got)
	}
	// The explanation must date the answer, or "unlisted" is unactionable.
	for _, s := range res.Statuses {
		if s.Code == StatusSoftBindingAlgUnlisted && !strings.Contains(s.Explanation, SoftBindingListSnapshot) {
			t.Errorf("explanation does not name the snapshot date: %q", s.Explanation)
		}
	}
}

// TestSoftBindingOptionalFields covers everything the spec allows but this
// library only carries: the deprecated url and extent, a timespan, a region,
// alg-params, a name, and pad2.
func TestSoftBindingOptionalFields(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	region := mustMarshalCBOR(t, map[string]any{"type": "rectangle", "x": 1})
	res := runCorpus(t, JPEG, softBindingAsset(t, sb, softBindingSpec(func(m map[string]any) {
		m["name"] = "cover image"
		m["alg-params"] = []byte{0x01, 0x02}
		m["url"] = "https://example.invalid/media.mp4"
		m["pad2"] = []byte{0, 0, 0}
		m["blocks"] = []any{
			map[string]any{
				"scope": map[string]any{
					"timespan": map[string]any{"start": uint64(0), "end": uint64(133016)},
					"extent":   []byte{0xaa},
					"region":   cbor.RawMessage(region),
				},
				"value": []byte{1, 2, 3, 4},
			},
			map[string]any{
				"scope": map[string]any{"timespan": map[string]any{"start": uint64(133017), "end": uint64(245009)}},
				"value": []byte{5, 6, 7, 8},
			},
		}
	})), sb)

	if !res.Valid {
		t.Fatalf("valid = false: %v", codes(res))
	}
	got := res.SoftBindings[0]
	if got.Name != "cover image" || string(got.Params) != "\x01\x02" || got.URL == "" {
		t.Errorf("optional fields: name=%q params=%x url=%q", got.Name, got.Params, got.URL)
	}
	if len(got.Blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(got.Blocks))
	}
	ts := got.Blocks[0].Scope.Timespan
	if ts == nil || ts.Start != 0 || ts.End != 133016 {
		t.Errorf("timespan = %+v", ts)
	}
	if string(got.Blocks[0].Scope.Extent) != "\xaa" {
		t.Errorf("extent = %x", got.Blocks[0].Scope.Extent)
	}
	// The region is carried verbatim and never decoded.
	if string(got.Blocks[0].Scope.Region) != string(region) {
		t.Errorf("region was not carried verbatim: %x vs %x", got.Blocks[0].Scope.Region, region)
	}
	if got.Blocks[1].Scope.Timespan == nil || got.Blocks[1].Scope.Region != nil {
		t.Errorf("second block scope = %+v", got.Blocks[1].Scope)
	}
	// Deprecated fields are named, not judged.
	var explained string
	for _, s := range res.Statuses {
		if s.Code == StatusSoftBindingUnevaluated {
			explained = s.Explanation
		}
	}
	for _, want := range []string{"url", "blocks[0].scope.extent", "its 2 blocks"} {
		if !strings.Contains(explained, want) {
			t.Errorf("explanation %q lacks %q", explained, want)
		}
	}
}

// TestSoftBindingInstances covers the multiple-instance labels, in store order.
func TestSoftBindingInstances(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	second := softBindingSpec(func(m map[string]any) {
		m["alg"] = "com.joinmonolith.sha256"
		m["blocks"] = []any{map[string]any{"scope": map[string]any{}, "value": []byte{9, 9}}}
	})
	second.label = softBindingLabel + "__1"
	res := runCorpus(t, JPEG, softBindingAsset(t, sb, softBindingSpec(), second), sb)

	if !res.Valid {
		t.Fatalf("valid = false: %v", codes(res))
	}
	if len(res.SoftBindings) != 2 {
		t.Fatalf("SoftBindings = %d, want 2", len(res.SoftBindings))
	}
	if res.SoftBindings[0].Algorithm != "io.iscc.v0" || res.SoftBindings[1].Algorithm != "com.joinmonolith.sha256" {
		t.Errorf("out of store order: %q then %q", res.SoftBindings[0].Algorithm, res.SoftBindings[1].Algorithm)
	}
	if res.SoftBindings[1].Label != softBindingLabel+"__1" {
		t.Errorf("second label = %q", res.SoftBindings[1].Label)
	}
}

// TestSoftBindingDefects walks every structural verdict. Each row must fail the
// asset — and none may disturb the hard binding, which is the assertion that
// matters most here.
func TestSoftBindingDefects(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	block := func(m map[string]any) []any { return m["blocks"].([]any) }

	cases := []struct {
		name   string
		spec   assertionSpec
		want   StatusCode
		expect string
	}{
		{"no alg anywhere", softBindingSpec(func(m map[string]any) { delete(m, "alg") }), StatusSoftBindingAlgMissing, "no default"},
		{"empty alg", softBindingSpec(func(m map[string]any) { m["alg"] = "" }), StatusSoftBindingMalformed, ""},
		{"alg not a string", softBindingSpec(func(m map[string]any) { m["alg"] = 3 }), StatusSoftBindingMalformed, ""},
		{"no blocks key", softBindingSpec(func(m map[string]any) { delete(m, "blocks") }), StatusSoftBindingMalformed, ""},
		{"blocks empty", softBindingSpec(func(m map[string]any) { m["blocks"] = []any{} }), StatusSoftBindingMalformed, ""},
		{"blocks not an array", softBindingSpec(func(m map[string]any) { m["blocks"] = "no" }), StatusSoftBindingMalformed, ""},
		{"block not a map", softBindingSpec(func(m map[string]any) { m["blocks"] = []any{"no"} }), StatusSoftBindingMalformed, ""},
		{"no value", softBindingSpec(func(m map[string]any) { delete(block(m)[0].(map[string]any), "value") }), StatusSoftBindingMalformed, ""},
		{"value not a byte string", softBindingSpec(func(m map[string]any) { block(m)[0].(map[string]any)["value"] = "text" }), StatusSoftBindingMalformed, ""},
		{"no scope", softBindingSpec(func(m map[string]any) { delete(block(m)[0].(map[string]any), "scope") }), StatusSoftBindingMalformed, ""},
		{"scope not a map", softBindingSpec(func(m map[string]any) { block(m)[0].(map[string]any)["scope"] = 1 }), StatusSoftBindingMalformed, ""},
		{"no pad", softBindingSpec(func(m map[string]any) { delete(m, "pad") }), StatusSoftBindingMalformed, ""},
		{"pad not a byte string", softBindingSpec(func(m map[string]any) { m["pad"] = "text" }), StatusSoftBindingMalformed, ""},
		{"pad2 not a byte string", softBindingSpec(func(m map[string]any) { m["pad2"] = "text" }), StatusSoftBindingMalformed, ""},
		{"name not a string", softBindingSpec(func(m map[string]any) { m["name"] = 7 }), StatusSoftBindingMalformed, ""},
		{"extent not a byte string", softBindingSpec(func(m map[string]any) {
			block(m)[0].(map[string]any)["scope"] = map[string]any{"extent": "text"}
		}), StatusSoftBindingMalformed, ""},
		{"timespan not a map", softBindingSpec(func(m map[string]any) {
			block(m)[0].(map[string]any)["scope"] = map[string]any{"timespan": 5}
		}), StatusSoftBindingMalformed, ""},
		{"pad non-zero", softBindingSpec(func(m map[string]any) { m["pad"] = []byte{1} }), StatusSoftBindingPadInvalid, "non-zero"},
		{"pad2 non-zero", softBindingSpec(func(m map[string]any) { m["pad2"] = []byte{0, 1} }), StatusSoftBindingPadInvalid, "non-zero"},
		{"json box", assertionSpec{label: softBindingLabel, json: true, raw: []byte(`{"alg":"io.iscc.v0"}`)}, StatusSoftBindingMalformed, "not a CBOR box"},
		{"not a map", assertionSpec{label: softBindingLabel, raw: mustMarshalCBOR(t, []any{1, 2})}, StatusSoftBindingMalformed, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCorpus(t, JPEG, softBindingAsset(t, sb, tc.spec), sb)
			if res.Valid {
				t.Fatalf("valid = true; want the defect to fail the asset: %v", codes(res))
			}
			if !hasAt(res, tc.want, softBindingURI) {
				t.Fatalf("no %s at %s: %v", tc.want, softBindingURI, codes(res))
			}
			// The hard binding is untouched by a broken soft binding.
			if res.Binding != BindingVerified {
				t.Errorf("Binding = %s, want verified", res.Binding)
			}
			// A failed soft binding is never well-formed, and never claims a match.
			if len(res.SoftBindings) == 1 && res.SoftBindings[0].WellFormed {
				t.Error("WellFormed is true for a defective soft binding")
			}
			if hasAt(res, StatusSoftBindingUnevaluated, softBindingURI) {
				t.Error("a defective soft binding also earned softBinding.unevaluated")
			}
			if tc.expect != "" {
				var found bool
				for _, s := range res.Statuses {
					if s.Code == tc.want && strings.Contains(s.Explanation, tc.expect) {
						found = true
					}
				}
				if !found {
					t.Errorf("no %s explanation containing %q: %v", tc.want, tc.expect, codes(res))
				}
			}
		})
	}
}

// TestSoftBindingDuplicateKeys pins the strict decode mode: a duplicate map key
// must be refused, because the decode reads keys and values in two stages and
// fxamacker keeps the last duplicate for a map and the first for a struct.
func TestSoftBindingDuplicateKeys(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	// {"alg": "io.iscc.v0", "alg": "phash", "pad": h'', "blocks": [ … ]}
	raw := []byte{0xa4}
	raw = append(raw, mustMarshalCBOR(t, "alg")...)
	raw = append(raw, mustMarshalCBOR(t, "io.iscc.v0")...)
	raw = append(raw, mustMarshalCBOR(t, "alg")...)
	raw = append(raw, mustMarshalCBOR(t, "phash")...)
	raw = append(raw, mustMarshalCBOR(t, "pad")...)
	raw = append(raw, mustMarshalCBOR(t, []byte{})...)
	raw = append(raw, mustMarshalCBOR(t, "blocks")...)
	raw = append(raw, mustMarshalCBOR(t, []any{map[string]any{"scope": map[string]any{}, "value": []byte{1}}})...)

	res := runCorpus(t, JPEG, softBindingAsset(t, sb, assertionSpec{label: softBindingLabel, raw: raw}), sb)
	if res.Valid || !hasAt(res, StatusSoftBindingMalformed, softBindingURI) {
		t.Fatalf("a duplicate map key was accepted: valid=%v %v", res.Valid, codes(res))
	}
}

// TestSoftBindingWithoutHardBinding is the §9.1 test. A soft binding may never
// be the sole content binding — and the verdict is the EXISTING
// hardBinding.missing, extended to say so, because a new code here would fail
// every correctly formed update manifest.
func TestSoftBindingWithoutHardBinding(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildAsset(t, JPEG, manifestSpec{
		signer:        sb,
		claimV2:       true,
		noHardBinding: true,
		assertions:    []assertionSpec{markerAssertion(), softBindingSpec()},
	})
	res := runCorpus(t, JPEG, asset, sb)

	if res.Valid {
		t.Fatal("a manifest bound only by a soft binding must not be valid")
	}
	if res.Binding != BindingNone {
		t.Errorf("Binding = %s, want none", res.Binding)
	}
	var explained string
	for _, s := range res.Statuses {
		if s.Code == StatusHardBindingMissing {
			explained = s.Explanation
		}
	}
	if !strings.Contains(explained, "§9.1") {
		t.Errorf("hardBinding.missing does not mention the sole-binding rule: %q", explained)
	}
	// No soft-binding-flavoured code was invented for this.
	for _, s := range res.Statuses {
		if s.Code == StatusSoftBindingMalformed || s.Code == StatusSoftBindingAlgMissing {
			t.Errorf("unexpected %s: §9.1 is the hard binding's absence", s.Code)
		}
	}
	// The soft binding itself is still reported, and still well-formed.
	if len(res.SoftBindings) != 1 || !res.SoftBindings[0].WellFormed {
		t.Errorf("SoftBindings = %+v", res.SoftBindings)
	}
}

// TestSoftBindingInIngredientNotListed pins the depth-0 scoping: an
// ingredient's soft binding identifies an earlier work, not these bytes, so it
// is checked but not listed.
func TestSoftBindingInIngredientNotListed(t *testing.T) {
	armBindHook(t)
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := updatedJPEG(t, sb, softBindingSpec())
	res := runCorpus(t, JPEG, asset, sb)

	// The update manifest is the active one and carries the soft binding; its
	// parent does not. Whatever the verdict, nothing from depth > 0 is listed.
	for _, sbg := range res.SoftBindings {
		if !strings.HasPrefix(sbg.URI, res.ActiveManifestLabel+"/") {
			t.Errorf("listed a soft binding from another manifest: %s", sbg.URI)
		}
	}
}

// FuzzSoftBinding feeds arbitrary bytes to the soft binding decoder. A new
// nested CBOR decoder with arrays of maps, a raw sub-slice retained into a
// public struct, and byte-string type discrimination is exactly the shape that
// earned FuzzIdentityAssertion its own target.
//
// The contract: never panic, and a well-formed soft binding must have earned
// the unevaluated status and no failure — the two can never disagree.
func FuzzSoftBinding(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa0}) // an empty map
	f.Add(mustMarshalCBOR(f, softBindingMap()))
	f.Add(mustMarshalCBOR(f, map[string]any{"blocks": []any{}, "pad": []byte{}}))
	f.Add(mustMarshalCBOR(f, map[string]any{"alg": "phash", "pad": []byte{1}, "blocks": []any{
		map[string]any{"scope": map[string]any{"timespan": map[string]any{"start": uint64(1), "end": uint64(0)}}, "value": []byte{1}},
	}}))
	f.Add(mustMarshalCBOR(f, map[string]any{"pad": []byte{}, "blocks": []any{
		map[string]any{"scope": map[string]any{"region": map[string]any{"type": "frame"}}, "value": []byte{}},
	}}))

	f.Fuzz(func(t *testing.T, data []byte) {
		v := &validator{ctx: t.Context(), cfg: validateConfig{maxScan: ValidateMaxScan}}
		start := len(v.res.Statuses)
		sb := v.verifySoftBinding(rawAssertion{label: softBindingLabel, tbox: "cbor", data: data}, "urn:test/"+softBindingLabel, "")

		var failed, unevaluated bool
		for _, s := range v.res.Statuses[start:] {
			if s.Code == "" {
				t.Fatal("a status with no code")
			}
			if s.Severity != s.Code.Severity() {
				t.Fatalf("%s severity %v, want %v", s.Code, s.Severity, s.Code.Severity())
			}
			switch {
			case s.Severity == SeverityFailure:
				failed = true
			case s.Code == StatusSoftBindingUnevaluated:
				unevaluated = true
			}
		}
		if sb.WellFormed != (unevaluated && !failed) {
			t.Fatalf("WellFormed = %v but failed = %v, unevaluated = %v", sb.WellFormed, failed, unevaluated)
		}
		if sb.WellFormed && len(sb.Blocks) == 0 {
			t.Fatal("well-formed with no blocks")
		}
		// A soft binding never claims an algorithm it did not resolve.
		if sb.WellFormed && sb.Algorithm == "" {
			t.Fatal("well-formed with no algorithm")
		}
		if sb.AlgorithmRegistered && sb.AlgorithmType == "" {
			t.Fatal("registered with no type")
		}
	})
}
