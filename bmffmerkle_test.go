package c2pa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// merkleAsset builds a minimal non-fragmented MP4: an 'ftyp' box then one
// 'mdat' whose payload is `payload` bytes past the 16 a Merkle leaf never
// covers.
func merkleAsset(t testing.TB, payload []byte) (asset []byte, mdatStart int) {
	t.Helper()
	ftyp := synthBox("ftyp", []byte("isom"))
	body := append(bytes.Repeat([]byte{0xAB}, mdatBlockPrefix-8), payload...)
	mdat := synthBox("mdat", body)
	asset = append(append([]byte{}, ftyp...), mdat...)
	return asset, len(ftyp)
}

// leafDigests hashes each block of payload, cut at the given sizes.
func leafDigests(t testing.TB, payload []byte, sizes []int) [][]byte {
	t.Helper()
	var out [][]byte
	off := 0
	for _, n := range sizes {
		if off+n > len(payload) {
			t.Fatalf("block sizes overrun the payload")
		}
		h := sha256.New()
		h.Write(payload[off : off+n])
		out = append(out, h.Sum(nil))
		off += n
	}
	if off != len(payload) {
		t.Fatalf("block sizes cover %d of %d payload bytes", off, len(payload))
	}
	return out
}

// runMerkle validates a merkle assertion against an asset directly, without the
// signing machinery: the hard binding is what is under test.
func runMerkle(t testing.TB, asset []byte, assertion map[string]any) ValidationResult {
	t.Helper()
	raw, err := cbor.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	v := &validator{
		ctx:       context.Background(),
		cfg:       validateConfig{maxScan: ValidateMaxScan},
		container: BMFF,
		data:      asset,
	}
	v.verifyBMFFHash(&rawAssertion{label: "c2pa.hash.bmff.v3", data: raw}, "urn:test")
	return v.res
}

func hasCode(res ValidationResult, code StatusCode) bool {
	for _, s := range res.Statuses {
		if s.Code == code {
			return true
		}
	}
	return false
}

func merkleExplanation(res ValidationResult) string {
	for _, s := range res.Statuses {
		if s.Code == StatusUnsupported {
			return s.Explanation
		}
	}
	return ""
}

// TestBMFFMerkleVariableBlocks verifies the case a single file can settle in
// full: a non-fragmented asset whose 'mdat' is cut into declared blocks, with
// the leaf row stored in the assertion.
func TestBMFFMerkleVariableBlocks(t *testing.T) {
	payload := bytes.Repeat([]byte{0x11}, 150)
	for i := range payload {
		payload[i] = byte(i)
	}
	asset, _ := merkleAsset(t, payload)
	sizes := []int{100, 30, 20}
	leaves := leafDigests(t, payload, sizes)

	res := runMerkle(t, asset, map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 17, "localId": 19, "count": 3,
			"variableBlockSizes": []any{100, 30, 20},
			"hashes":             []any{leaves[0], leaves[1], leaves[2]},
		}},
	})
	if !hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Fatalf("expected a match, got %v (%q)", codes(res), merkleExplanation(res))
	}
	if hasCode(res, StatusUnsupported) {
		t.Errorf("a fully verifiable merkle map should raise no advisory: %q", merkleExplanation(res))
	}
}

// TestBMFFMerkleDetectsTamperedBlock is the point of the binding: editing a
// byte inside one leaf block must break it.
func TestBMFFMerkleDetectsTamperedBlock(t *testing.T) {
	payload := bytes.Repeat([]byte{0x22}, 90)
	asset, mdatStart := merkleAsset(t, payload)
	leaves := leafDigests(t, payload, []int{30, 30, 30})

	assertion := map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 3,
			"fixedBlockSize": 30,
			"hashes":         []any{leaves[0], leaves[1], leaves[2]},
		}},
	}
	if res := runMerkle(t, asset, assertion); !hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Fatalf("baseline should match, got %v (%q)", codes(res), merkleExplanation(res))
	}

	// Flip a byte in the middle block, past the 16-byte prefix no leaf covers.
	tampered := append([]byte(nil), asset...)
	tampered[mdatStart+mdatBlockPrefix+40] ^= 0xFF
	res := runMerkle(t, tampered, assertion)
	if !hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Errorf("expected a mismatch after editing a block, got %v", codes(res))
	}
}

// TestBMFFMerkleRootRow pins that `hashes` may be any row of the tree, not just
// the leaf row — here the root of a three-leaf tree, whose last leaf has no
// sibling and so is carried up unchanged.
func TestBMFFMerkleRootRow(t *testing.T) {
	payload := bytes.Repeat([]byte{0x33}, 90)
	asset, _ := merkleAsset(t, payload)
	leaves := leafDigests(t, payload, []int{30, 30, 30})

	// Layer 1: H(l0||l1), then l2 propagated unchanged. Layer 2: H of those.
	h := sha256.New()
	h.Write(leaves[0])
	h.Write(leaves[1])
	l1a := h.Sum(nil)
	h = sha256.New()
	h.Write(l1a)
	h.Write(leaves[2])
	root := h.Sum(nil)

	res := runMerkle(t, asset, map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 3,
			"fixedBlockSize": 30,
			"hashes":         []any{root},
		}},
	})
	if !hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Fatalf("root-row merkle map did not verify: %v (%q)", codes(res), merkleExplanation(res))
	}
}

// TestBMFFMerkleUnpairedLeafIsCarriedUp pins the tree shape that makes this
// C2PA's rather than the usual one: an odd last node is propagated unchanged,
// NOT duplicated and hashed with itself.
func TestBMFFMerkleUnpairedLeafIsCarriedUp(t *testing.T) {
	leaves := [][]byte{{1}, {2}, {3}}
	layers := merkleLayers("sha256", leaves)
	if len(layers) != 3 {
		t.Fatalf("got %d layers, want 3", len(layers))
	}
	if !bytes.Equal(layers[1][1], leaves[2]) {
		t.Errorf("unpaired leaf was not carried up unchanged")
	}
	dup := sha256.New()
	dup.Write(leaves[2])
	dup.Write(leaves[2])
	if bytes.Equal(layers[1][1], dup.Sum(nil)) {
		t.Errorf("unpaired leaf was duplicated and hashed, which C2PA does not do")
	}
}

// TestBMFFMerkleIntermediateRow pins the middle of the CDDL's "leaf-most row,
// root row, or any intermediate row": here row 1 of a three-leaf tree, whose
// length is what says which row it is.
func TestBMFFMerkleIntermediateRow(t *testing.T) {
	payload := bytes.Repeat([]byte{0x66}, 90)
	asset, _ := merkleAsset(t, payload)
	leaves := leafDigests(t, payload, []int{30, 30, 30})

	h := sha256.New()
	h.Write(leaves[0])
	h.Write(leaves[1])
	row1 := [][]byte{h.Sum(nil), leaves[2]} // the unpaired leaf carries up

	res := runMerkle(t, asset, map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 3,
			"fixedBlockSize": 30,
			"hashes":         []any{row1[0], row1[1]},
		}},
	})
	if !hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Fatalf("intermediate-row merkle map did not verify: %v (%q)", codes(res), merkleExplanation(res))
	}

	// And the same row with one entry wrong is a mismatch, not a malformed.
	res = runMerkle(t, asset, map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 3,
			"fixedBlockSize": 30,
			"hashes":         []any{row1[0], bytes.Repeat([]byte{0x07}, 32)},
		}},
	})
	if !hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Errorf("expected a mismatch on a wrong intermediate row, got %v", codes(res))
	}
}

// TestBMFFMerkleMalformed covers the structural rejections, which are reported
// as malformed rather than as a mismatch because nothing was compared.
func TestBMFFMerkleMalformed(t *testing.T) {
	payload := bytes.Repeat([]byte{0x44}, 90)
	asset, _ := merkleAsset(t, payload)
	leaves := leafDigests(t, payload, []int{30, 30, 30})
	base := func() map[string]any {
		return map[string]any{
			"uniqueId": 1, "localId": 1, "count": 3,
			"fixedBlockSize": 30,
			"hashes":         []any{leaves[0], leaves[1], leaves[2]},
		}
	}
	tests := []struct {
		name  string
		build func(m map[string]any)
	}{
		{"both block-size fields", func(m map[string]any) {
			m["variableBlockSizes"] = []any{30, 30, 30}
		}},
		{"count disagrees with the blocks", func(m map[string]any) {
			m["count"] = 4
		}},
		{"variable sizes short of the payload", func(m map[string]any) {
			delete(m, "fixedBlockSize")
			m["variableBlockSizes"] = []any{30, 30, 20}
		}},
		{"variable sizes past the payload", func(m map[string]any) {
			delete(m, "fixedBlockSize")
			m["variableBlockSizes"] = []any{30, 30, 40}
		}},
		{"fixed block size of one", func(m map[string]any) {
			m["fixedBlockSize"] = 1
		}},
		{"hashes match no row", func(m map[string]any) {
			// A three-leaf tree has rows of 3, 2 and 1; four hashes are none
			// of them, so there is nothing to compare against.
			m["hashes"] = []any{leaves[0], leaves[1], leaves[2], leaves[0]}
		}},
		{"no hashes at all", func(m map[string]any) {
			m["hashes"] = []any{}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.build(m)
			res := runMerkle(t, asset, map[string]any{
				"alg": "sha256", "merkle": []any{m},
			})
			if !hasCode(res, StatusAssertionBMFFHashMalformed) {
				t.Errorf("expected %s, got %v (%q)",
					StatusAssertionBMFFHashMalformed, codes(res), merkleExplanation(res))
			}
		})
	}
}

// TestBMFFMerkleLeafCountIsCapped pins the allocation guard: fixedBlockSize is
// attacker-controlled, and a tiny one over a large 'mdat' is what turns an
// assertion's size into ours.
func TestBMFFMerkleLeafCountIsCapped(t *testing.T) {
	mdat := &bmffBox{typ: "mdat", start: 0, end: mdatBlockPrefix + (maxMerkleLeaves+1)*2}
	_, status := merkleLeafRanges(mdat, merkleMap{
		count: 2, hasFixed: true, fixedBlockSize: 2,
	})
	if status != StatusAssertionBMFFHashMalformed {
		t.Errorf("got %q, want the leaf cap to reject it", status)
	}
}

// TestBMFFMerkleFragmentedInitSegment covers a flat fragmented file: the init
// hash covers everything before the first 'moof' and IS checked here, while the
// chunk hashes need each chunk's own merkle box and are reported as such.
func TestBMFFMerkleFragmentedInitSegment(t *testing.T) {
	ftyp := synthBox("ftyp", []byte("isom"))
	moov := synthBox("moov", bytes.Repeat([]byte{0x55}, 24))
	moof := synthBox("moof", bytes.Repeat([]byte{0x66}, 16))
	mdat := synthBox("mdat", bytes.Repeat([]byte{0x77}, 32))
	asset := append(append(append(append([]byte{}, ftyp...), moov...), moof...), mdat...)
	firstMoof := len(ftyp) + len(moov)

	// The init hash is the same offset-marker walk the flat hash uses, over the
	// boxes before the first 'moof'.
	top := parseBMFFBoxes(context.Background(), asset)
	h := sha256.New()
	hashBMFFTopLevel(context.Background(), asset, top,
		[]byteRange{{start: firstMoof, length: len(asset) - firstMoof}}, h)
	initHash := h.Sum(nil)

	assertion := map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 17, "localId": 19, "count": 1,
			"initHash": initHash,
			"hashes":   []any{bytes.Repeat([]byte{0x01}, 32)},
		}},
	}

	res := runMerkle(t, asset, assertion)
	if hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Fatalf("a correct init hash should not mismatch: %v", codes(res))
	}
	// The chunks are not bound by anything this file can check, so a plain
	// match would overstate what was verified.
	if hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match while the chunk hashes went unverified: %v", codes(res))
	}
	if !hasCode(res, StatusUnsupported) {
		t.Fatalf("expected an advisory naming what was not verified: %v", codes(res))
	}
	if got := merkleExplanation(res); !bytes.Contains([]byte(got), []byte("chunk")) {
		t.Errorf("advisory does not say the chunks went unverified: %q", got)
	}

	// A WRONG init hash is disproved by this file alone, so it must fail.
	bad := map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 17, "localId": 19, "count": 1,
			"initHash": bytes.Repeat([]byte{0x02}, 32),
			"hashes":   []any{bytes.Repeat([]byte{0x01}, 32)},
		}},
	}
	if res := runMerkle(t, asset, bad); !hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Errorf("a wrong init hash should be a mismatch, got %v", codes(res))
	}
}

// TestBMFFMerkleInitSegmentAlone covers a fragmented asset's initialization
// segment read on its own: it carries an init hash but no 'moof', and the
// chunks it binds are other files entirely.
func TestBMFFMerkleInitSegmentAlone(t *testing.T) {
	ftyp := synthBox("ftyp", []byte("isom"))
	moov := synthBox("moov", bytes.Repeat([]byte{0x88}, 24))
	asset := append(append([]byte{}, ftyp...), moov...)

	res := runMerkle(t, asset, map[string]any{
		"alg": "sha256",
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 1,
			"initHash": bytes.Repeat([]byte{0x03}, 32),
			"hashes":   []any{bytes.Repeat([]byte{0x04}, 32)},
		}},
	})
	if hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Errorf("an init segment read alone is unverifiable, not wrong: %v", codes(res))
	}
	if !hasCode(res, StatusUnsupported) {
		t.Errorf("expected an advisory, got %v", codes(res))
	}
	if got := merkleExplanation(res); !bytes.Contains([]byte(got), []byte("other files")) {
		t.Errorf("advisory does not say the chunks are elsewhere: %q", got)
	}
}

// TestBMFFMerkleWithFlatHash pins that an assertion carrying both a flat hash
// and a merkle array has both checked — the flat hash first, and a merkle
// failure still surfaces after it passes.
func TestBMFFMerkleWithFlatHash(t *testing.T) {
	payload := bytes.Repeat([]byte{0x99}, 60)
	asset, _ := merkleAsset(t, payload)
	top := parseBMFFBoxes(context.Background(), asset)
	h := sha256.New()
	hashBMFFTopLevel(context.Background(), asset, top, nil, h)
	flat := h.Sum(nil)
	leaves := leafDigests(t, payload, []int{30, 30})

	res := runMerkle(t, asset, map[string]any{
		"alg": "sha256", "hash": flat,
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 2,
			"fixedBlockSize": 30,
			"hashes":         []any{leaves[0], leaves[1]},
		}},
	})
	if !hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Fatalf("both hashes are correct: %v (%q)", codes(res), merkleExplanation(res))
	}

	// A wrong flat hash fails before the merkle array is reached.
	res = runMerkle(t, asset, map[string]any{
		"alg": "sha256", "hash": bytes.Repeat([]byte{0x05}, 32),
		"merkle": []any{map[string]any{
			"uniqueId": 1, "localId": 1, "count": 2,
			"fixedBlockSize": 30,
			"hashes":         []any{leaves[0], leaves[1]},
		}},
	})
	if !hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Errorf("a wrong flat hash should still fail, got %v", codes(res))
	}
}

// TestBMFFMerkleMdatPairing pins that merkle maps pair with 'mdat' boxes
// positionally, and that a count mismatch is reported rather than guessed
// around.
func TestBMFFMerkleMdatPairing(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAA}, 30)
	asset, _ := merkleAsset(t, payload)
	leaves := leafDigests(t, payload, []int{30})

	one := map[string]any{
		"uniqueId": 1, "localId": 1, "count": 1,
		"hashes": []any{leaves[0]},
	}
	if res := runMerkle(t, asset, map[string]any{"alg": "sha256", "merkle": []any{one}}); !hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Fatalf("a single whole-payload leaf should verify: %v (%q)", codes(res), merkleExplanation(res))
	}

	// Two maps, one mdat: the pairing means nothing, so say so.
	res := runMerkle(t, asset, map[string]any{"alg": "sha256", "merkle": []any{one, one}})
	if hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match on a pairing it could not make: %v", codes(res))
	}
	if !hasCode(res, StatusUnsupported) {
		t.Errorf("expected an advisory, got %v", codes(res))
	}
}
