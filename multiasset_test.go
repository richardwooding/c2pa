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
