package c2pa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

// TestMerkleBoxBytes pins the wire layout the verifier reads: size, 'uuid',
// the C2PA usertype, version and flags, "merkle" and its NUL, CBOR, zero
// padding — and no merkle-offset field.
func TestMerkleBoxBytes(t *testing.T) {
	proof := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
	spec := merkleBoxSpec{uniqueID: 1, localID: 1, location: 7, hashes: proof}
	box, err := merkleBoxBytes(spec, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != 200 || string(box[4:8]) != "uuid" || !bytes.Equal(box[8:24], c2paBoxUUID[:]) ||
		!bytes.Equal(box[24:28], []byte{0, 0, 0, 0}) || string(box[28:35]) != "merkle\x00" {
		t.Fatalf("layout: %x", box[:40])
	}
	top := parseBMFFBoxes(context.Background(), box)
	if len(top) != 1 {
		t.Fatalf("parsed %d boxes", len(top))
	}
	payload := c2paMerklePayload(box, top[0])
	if payload == nil {
		t.Fatal("not recognised as a merkle box")
	}
	mb, ok := decodeMerkleBox(payload)
	if !ok || mb.uniqueID != 1 || mb.localID != 1 || mb.location != 7 || len(mb.hashes) != 2 || !bytes.Equal(mb.hashes[1], proof[1]) {
		t.Fatalf("decoded %+v (%v)", mb, ok)
	}
	if tail := box[len(box)-8:]; !bytes.Equal(tail, make([]byte, 8)) {
		t.Fatalf("padding is not zero: %x", tail)
	}
	// No proof → no hashes key at all, which decodes as absent.
	bare, err := merkleBoxBytes(merkleBoxSpec{uniqueID: 1, localID: 1, location: 3}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bare, []byte("hashes")) {
		t.Fatal("an empty proof must not write a hashes key")
	}
	if mb, ok := decodeMerkleBox(c2paMerklePayload(bare, parseBMFFBoxes(context.Background(), bare)[0])); !ok || mb.hashes != nil {
		t.Fatalf("bare box decoded %+v (%v)", mb, ok)
	}
	if _, err := merkleBoxBytes(spec, 40); err == nil {
		t.Fatal("a box that does not fit its padding must be an error, not a truncation")
	}
}

// TestMerkleBoxSize: the arithmetic equals the largest real encoding over every
// location, for every tree size that changes a CBOR integer width or an
// odd-row shape.
func TestMerkleBoxSize(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 11, 23, 24, 25, 31, 32, 33, 64, 100, 255, 256, 257, 300} {
		rowIndex := merkleRowIndex(n)
		got, err := merkleBoxSize("sha256", 1, 1, n, rowIndex)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		for loc := 0; loc < n; loc++ {
			proof := make([][]byte, merkleProofLen(n, loc, rowIndex))
			for i := range proof {
				proof[i] = make([]byte, sha256.Size)
			}
			box, err := merkleBoxBytes(merkleBoxSpec{uniqueID: 1, localID: 1, location: loc, hashes: proof}, 0)
			if err != nil {
				t.Fatal(err)
			}
			want = max(want, len(box))
		}
		if got != want {
			t.Errorf("n=%d: merkleBoxSize %d, brute force %d", n, got, want)
		}
	}
}

// TestMerkleRowPolicy pins c2pa-rs's row choice and the proof lengths it
// implies: the root for fewer than 32 leaves, and for 11 leaves location 0
// needs 4 siblings while location 10 — an unpaired node twice on its way up —
// needs 2.
func TestMerkleRowPolicy(t *testing.T) {
	for n, wantRow := range map[int]int{1: 1, 2: 1, 5: 1, 31: 1, 32: 1, 33: 2, 100: 4} {
		if got := merkleLayout(n)[merkleRowIndex(n)]; got != wantRow {
			t.Errorf("n=%d: stored row has %d nodes, want %d", n, got, wantRow)
		}
	}
	if merkleRowIndex(1) != 0 || merkleProofLen(1, 0, 0) != 0 {
		t.Error("a one-leaf tree stores its leaf and needs no proof")
	}
	if got := merkleProofLen(11, 0, merkleRowIndex(11)); got != 4 {
		t.Errorf("11 leaves, location 0: proof %d, want 4", got)
	}
	if got := merkleProofLen(11, 10, merkleRowIndex(11)); got != 2 {
		t.Errorf("11 leaves, location 10: proof %d, want 2", got)
	}
	// merkleProof agrees with merkleProofLen and with merkleProve.
	leaves := make([][]byte, 11)
	for i := range leaves {
		h := sha256.Sum256([]byte{byte(i)})
		leaves[i] = h[:]
	}
	layers := merkleLayers("sha256", leaves)
	rowIndex := merkleRowIndex(11)
	m := merkleMap{count: 11, hashes: layers[rowIndex]}
	for loc := range leaves {
		proof := merkleProof(layers, loc, rowIndex)
		if len(proof) != merkleProofLen(11, loc, rowIndex) {
			t.Errorf("location %d: proof %d, len says %d", loc, len(proof), merkleProofLen(11, loc, rowIndex))
		}
		if ok, malformed := merkleProve("sha256", m, leaves[loc], loc, proof); !ok || malformed {
			t.Errorf("location %d: proof does not verify (ok=%v malformed=%v)", loc, ok, malformed)
		}
	}
}

// TestPrepareFragment: the editor's refusals and its byte-level promises.
func TestPrepareFragment(t *testing.T) {
	ctx := context.Background()
	_, frags := unsignedFragmentedSet(2, fragOpts{sidxVersion: 0, emsg: true})
	box, err := merkleBoxBytes(merkleBoxSpec{uniqueID: 1, localID: 1}, 120)
	if err != nil {
		t.Fatal(err)
	}
	out, err := prepareFragment(ctx, frags[0], box)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(frags[0])+len(box) {
		t.Fatalf("length %d, want %d", len(out), len(frags[0])+len(box))
	}
	top := parseBMFFBoxes(ctx, out)
	var types []string
	for _, b := range top {
		types = append(types, b.typ)
	}
	if want := []string{"styp", "sidx", "emsg", "uuid", "moof", "mdat"}; !equalStrings(types, want) {
		t.Fatalf("box order %v, want %v", types, want)
	}
	// Idempotent replacement: prepare the prepared fragment again → one box.
	again, err := prepareFragment(ctx, out, box)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, out) {
		t.Fatal("re-preparing a prepared fragment should reproduce it")
	}

	init, _ := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	twoMoof := append(append([]byte(nil), frags[0]...), topBoxBytes(frags[1], "moof")...)
	cases := []struct {
		name string
		frag []byte
		want error
	}{
		{"init segment", init, errCarrierMalformed},
		{"no moof", synthBox("styp", []byte("msdh")), errCarrierMalformed},
		{"two moofs", twoMoof, errCarrierUnsupported},
		{"trailing bytes", append(append([]byte(nil), frags[0]...), 1, 2, 3), errCarrierMalformed},
		{"garbage", []byte("not a fragment at all"), errCarrierMalformed},
		{"empty", nil, errCarrierMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := prepareFragment(ctx, tc.frag, box); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// topBoxBytes returns the bytes of the first top-level box of type typ.
func topBoxBytes(data []byte, typ string) []byte {
	b := topBox(data, typ)
	if b == nil {
		return nil
	}
	return data[b.start:b.end]
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
