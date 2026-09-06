package c2pa

import (
	"bytes"
	"context"
	"testing"
)

// FuzzSign runs the whole writer over arbitrary bytes for every supported
// container. Contract: never panic; when Sign succeeds the output validates
// with the signer's own root; when it fails nothing is written.
func FuzzSign(f *testing.F) {
	s, sc := newTestSigner(f)
	f.Add(unsignedJPEG(f), uint8(0))
	f.Add(unsignedPNG(f), uint8(1))
	f.Add(fixtureBytes(f, "c2pa_signed.jpg"), uint8(0))
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9}, uint8(0))
	f.Add([]byte{}, uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, which uint8) {
		if len(data) > 1<<20 {
			return
		}
		c := signableContainers[int(which)%len(signableContainers)]
		var out bytes.Buffer
		err := s.Sign(context.Background(), c, bytes.NewReader(data), &out, openedManifest("fuzz"))
		if err != nil {
			if out.Len() != 0 {
				t.Fatalf("wrote %d bytes on error %v", out.Len(), err)
			}
			return
		}
		res := Validate(context.Background(), c, bytes.NewReader(out.Bytes()), WithSigningTrust(sc.roots), WithOnlineRevocation(false), WithMaxIngredientDepth(0))
		if !res.Valid {
			t.Fatalf("signed output does not validate: %v", codes(res))
		}
	})
}

// FuzzEmbedStore targets the embedders alone: arbitrary asset bytes and an
// arbitrary store payload must never panic, and a success must read back.
func FuzzEmbedStore(f *testing.F) {
	f.Add(unsignedJPEG(f), []byte{0xA0}, uint8(0))
	f.Add(unsignedPNG(f), []byte{0xA0}, uint8(1))
	f.Add(fixtureBytes(f, "c2pa_signed.jpg"), bytes.Repeat([]byte{7}, 70000), uint8(0))
	f.Fuzz(func(t *testing.T, asset, payload []byte, which uint8) {
		if len(asset) > 1<<20 || len(payload) > 1<<17 {
			return
		}
		c := signableContainers[int(which)%len(signableContainers)]
		store := storeBox(superBox(uuidC2MA, "urn:c2pa:fuzz", assertionBox("com.fuzz", payload)))
		out, excl, err := embedStore(context.Background(), c, asset, store)
		if err != nil {
			return
		}
		for _, r := range excl {
			if r.start < 0 || r.length < 0 || r.start+r.length > len(out) {
				t.Fatalf("exclusion %v outside %d bytes", r, len(out))
			}
		}
		if !bytes.Equal(extractJUMBF(context.Background(), c, out), store) {
			t.Fatalf("store did not read back")
		}
	})
}
