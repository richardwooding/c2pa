package c2pa

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestVerifyMultiAssetHash(t *testing.T) {
	enc := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	partData := [][]byte{bytes.Repeat([]byte{1}, 40), bytes.Repeat([]byte{2}, 30), bytes.Repeat([]byte{3}, 20)}
	build := func(optional []bool) (*parsedManifest, *rawAssertion) {
		m := &parsedManifest{claim: map[string]any{"alg": "sha256"}}
		var parts []any
		off := 0
		for i, d := range partData {
			sum := sha256.Sum256(d)
			label := "c2pa.hash.data.part"
			if i > 0 {
				label += "__" + string(rune('0'+i))
			}
			pa := rawAssertion{label: label, tbox: "cbor", data: enc(map[string]any{"alg": "sha256", "hash": sum[:]})}
			pa.boxContent = pa.data
			m.assertions = append(m.assertions, pa)
			hs := sha256.Sum256(pa.boxContent)
			l := len(d)
			parts = append(parts, map[string]any{
				"location":      map[string]any{"byteOffset": off, "length": l},
				"hashAssertion": map[string]any{"url": "self#jumbf=c2pa.assertions/" + label, "hash": hs[:]},
				"optional":      optional[i],
			})
			off += l
		}
		a := &rawAssertion{label: "c2pa.hash.multi-asset", tbox: "cbor", data: enc(map[string]any{"parts": parts})}
		return m, a
	}
	cat := func(n int) []byte { return bytes.Join(partData[:n], nil) }
	opt := []bool{false, true, true}
	tests := []struct {
		name     string
		data     []byte
		optional []bool
		want     StatusCode
	}{
		{"all parts", cat(3), opt, StatusMultiAssetHashMatch},
		{"optional parts dropped", cat(1), opt, StatusMultiAssetHashMatch},
		{"required part dropped", cat(1), []bool{false, false, true}, StatusMultiAssetHashMissingPart},
		{"optional part tampered", cat(2), opt, StatusMultiAssetHashMismatch},
		{"extra data", append(cat(3), 0), opt, StatusMultiAssetHashMismatch},
		{"part cut short", cat(3)[:65], opt, StatusMultiAssetHashMismatch},
		{"gap between parts", cat(3), opt, StatusMultiAssetHashMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, a := build(tc.optional)
			if tc.name == "gap between parts" {
				var d map[string]any
				_ = decMode.Unmarshal(a.data, &d)
				ps := d["parts"].([]any)
				ps[2].(map[string]any)["location"].(map[string]any)["byteOffset"] = uint64(71)
				a.data = enc(d)
			}
			data := tc.data
			if tc.name == "optional part tampered" {
				data = append([]byte(nil), cat(2)...)
				data[50] ^= 0xff
			}
			v := &validator{ctx: t.Context(), data: data}
			v.cfg.maxScan = MaxScan
			v.verifyMultiAssetHash(m, a, "urn:c2pa:t")
			if !v.res.Has(tc.want) {
				t.Errorf("want %s; got %v", tc.want, codes(v.res))
			}
			if tc.want != StatusMultiAssetHashMatch && v.res.Has(StatusMultiAssetHashMatch) {
				t.Errorf("must not report a match: %v", codes(v.res))
			}
		})
	}
}

// TestVerifyMultiAssetHashUnsupportedShapes: §18.9.2 permits a bmffBox locator
// and a boxes- or BMFF-hash part assertion. Neither is evaluated here, and the
// honest report is an informational general.unsupported with NO verdict — the
// caller then keeps the whole-asset mismatch that led it to the parts, so a
// shape this verifier does not check can never erase a hash failure.
func TestVerifyMultiAssetHashUnsupportedShapes(t *testing.T) {
	enc := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	data := bytes.Repeat([]byte{7}, 50)
	sum := sha256.Sum256(data)
	for _, tc := range []struct {
		name  string
		label string
		loc   map[string]any
	}{
		{"boxes-hash part", "c2pa.hash.boxes.part", map[string]any{"byteOffset": 0, "length": 50}},
		{"bmff-hash part", "c2pa.hash.bmff.v3.part", map[string]any{"byteOffset": 0, "length": 50}},
		{"bmffBox locator", "c2pa.hash.data.part", map[string]any{"bmffBox": "/mpvd"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pa := rawAssertion{label: tc.label, tbox: "cbor", data: enc(map[string]any{"alg": "sha256", "hash": sum[:]})}
			pa.boxContent = pa.data
			m := &parsedManifest{claim: map[string]any{"alg": "sha256"}, assertions: []rawAssertion{pa}}
			hs := sha256.Sum256(pa.boxContent)
			a := &rawAssertion{label: "c2pa.hash.multi-asset", tbox: "cbor", data: enc(map[string]any{"parts": []any{map[string]any{
				"location":      tc.loc,
				"hashAssertion": map[string]any{"url": "self#jumbf=c2pa.assertions/" + tc.label, "hash": hs[:]},
			}}})}
			v := &validator{ctx: t.Context(), data: data}
			v.cfg.maxScan = MaxScan
			if v.verifyMultiAssetHash(m, a, "urn:c2pa:t") {
				t.Errorf("an unevaluated shape must not report itself as evaluated")
			}
			if !v.res.Has(StatusUnsupported) || v.res.Has(StatusMultiAssetHashMatch) {
				t.Errorf("want only general.unsupported; got %v", codes(v.res))
			}
			for _, e := range v.res.Statuses {
				if e.Severity == SeverityFailure {
					t.Errorf("an unevaluated shape must not fail on its own: %v", codes(v.res))
				}
			}
		})
	}
}

// TestHardBindingTamperedIsManifestScoped: a hashed-URI mismatch on ANOTHER
// manifest's hard binding says nothing about this one.
func TestHardBindingTamperedIsManifestScoped(t *testing.T) {
	v := &validator{}
	v.add(StatusAssertionHashedURIMismatch, "urn:c2pa:other/c2pa.assertions/c2pa.hash.data", "", nil)
	if v.hardBindingTampered("urn:c2pa:this") {
		t.Error("another manifest's tampered binding was counted against this one")
	}
	v.add(StatusAssertionHashedURIMismatch, "urn:c2pa:this/c2pa.assertions/c2pa.hash.data", "", nil)
	if !v.hardBindingTampered("urn:c2pa:this") {
		t.Error("this manifest's tampered binding was not seen")
	}
}
