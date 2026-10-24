package c2pa

import "testing"

func TestCheckClaimStructure(t *testing.T) {
	cbor := func(v any) []byte {
		b, err := encMode.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v2 := func(extra map[string]any) map[string]any {
		c := map[string]any{
			"instanceID": "xmp:iid:1", "signature": "self#jumbf=c2pa.signature",
			"claim_generator_info": map[string]any{"name": "t"},
			"created_assertions": []any{map[string]any{
				"url": "self#jumbf=c2pa.assertions/c2pa.hash.data", "hash": make([]byte, 32),
			}},
		}
		for k, val := range extra {
			c[k] = val
		}
		return c
	}
	hash := rawAssertion{label: "c2pa.hash.data", tbox: "cbor", data: cbor(map[string]any{})}
	tests := []struct {
		name string
		m    parsedManifest
		want StatusCode
		ok   bool // hard binding ok
	}{
		{"sound", parsedManifest{claimBytes: []byte{1}, claim: v2(nil), assertions: []rawAssertion{hash}}, "", true},
		{"claim not CBOR", parsedManifest{claimBytes: []byte{0xff}}, StatusClaimCBORInvalid, false},
		{"missing created_assertions", parsedManifest{claimBytes: []byte{1}, claim: v2(map[string]any{"created_assertions": nil})}, StatusClaimMalformed, true},
		{"hard binding not referenced", parsedManifest{claimBytes: []byte{1}, claim: v2(map[string]any{"created_assertions": []any{map[string]any{
			"url": "self#jumbf=c2pa.assertions/c2pa.actions.v2", "hash": make([]byte, 32)}}}), assertions: []rawAssertion{hash}}, StatusClaimHardBindingsMissing, false},
		{"assertion not CBOR", parsedManifest{claimBytes: []byte{1}, claim: v2(nil), assertions: []rawAssertion{hash, {label: "c2pa.actions.v2", tbox: "cbor", data: []byte{0xff}}}}, StatusAssertionCBORInvalid, true},
		{"ingredient without validationResults", parsedManifest{claimBytes: []byte{1}, claim: v2(nil), assertions: []rawAssertion{hash, {label: "c2pa.ingredient.v3", tbox: "cbor",
			data: cbor(map[string]any{"activeManifest": map[string]any{"url": "x"}})}}}, StatusAssertionIngredientMalform, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &validator{}
			ok := v.checkClaimStructure(&tc.m, "urn:c2pa:t")
			if ok != tc.ok {
				t.Errorf("hardBindingsOK = %v, want %v", ok, tc.ok)
			}
			got := StatusCode("")
			if len(v.res.Statuses) > 0 {
				got = v.res.Statuses[0].Code
			}
			if got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}
