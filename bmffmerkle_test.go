package c2pa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
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

// --- fragmented builders ------------------------------------------------------

// testMerkleBoxPayload is the fixed payload size every merkle box a test writes
// is padded to, as §A.5.4.1.3 pads real ones. Fixing it keeps box offsets — and
// so every chunk hash — the same whatever a test writes into a box: a mutated
// box changes only what it says, never where the chunk after it lies.
const testMerkleBoxPayload = 256

// testMerkleBox is the production merkle box writer padded to
// testMerkleBoxPayload — the corpus writes real boxes, as it writes real JUMBF.
func testMerkleBox(t testing.TB, spec merkleBoxSpec) []byte {
	t.Helper()
	box, err := merkleBoxBytes(spec, merkleBoxHeader+testMerkleBoxPayload)
	if err != nil {
		t.Fatalf("merkle box: %v", err)
	}
	return box
}

// standardBMFFExclusions are the exclusions a real fragmented assertion
// carries: the C2PA uuid boxes — by usertype, so a foreign uuid box stays
// bound — and 'ftyp'. Returned both as the verifier's decoded form and as the
// CBOR-ready form an assertion map takes.
func standardBMFFExclusions() ([]bmffExclusion, []any) {
	return []bmffExclusion{
		{xpath: "/uuid", length: -1, version: -1, exact: true,
			data: []bmffDataMatch{{offset: 8, value: c2paBoxUUID[:]}}},
		{xpath: "/ftyp", length: -1, version: -1, exact: true},
	}, []any{
		map[string]any{"xpath": "/uuid", "data": []any{map[string]any{"offset": 8, "value": c2paBoxUUID[:]}}},
		map[string]any{"xpath": "/ftyp"},
	}
}

// merkleRow returns the row with n nodes of the sha256 tree over leaves.
func merkleRow(t testing.TB, leaves [][]byte, n int) [][]byte {
	t.Helper()
	for _, layer := range merkleLayers("sha256", leaves) {
		if len(layer) == n {
			return layer
		}
	}
	t.Fatalf("a %d-leaf tree has no row of %d nodes", len(leaves), n)
	return nil
}

// merkleProofFor returns the proof for the leaf at location up to the row of
// storedRowLen nodes, through the production merkleProof, so the tests' proofs
// and the verifier's tree share one definition of the shape. nil when the leaf
// row itself is stored.
func merkleProofFor(t testing.TB, leaves [][]byte, location, storedRowLen int) [][]byte {
	t.Helper()
	layers := merkleLayers("sha256", leaves)
	for row, layer := range layers {
		if len(layer) == storedRowLen {
			return merkleProof(layers, location, row)
		}
	}
	t.Fatalf("a %d-leaf tree has no row of %d nodes", len(leaves), storedRowLen)
	return nil
}

// merkleAssertion builds the c2pa.hash.bmff.v3 assertion map binding one tree.
func merkleAssertion(uniqueID, localID, count int, initHash []byte, row [][]byte, exclusions []any) map[string]any {
	rowAny := make([]any, len(row))
	for i, r := range row {
		rowAny[i] = r
	}
	return map[string]any{
		"alg":        "sha256",
		"exclusions": exclusions,
		"merkle": []any{map[string]any{
			"uniqueId": uniqueID, "localId": localID, "count": count,
			"initHash": initHash, "hashes": rowAny,
		}},
	}
}

// firstMerkleMap returns the assertion's first merkle-map for a test to edit.
func firstMerkleMap(assertion map[string]any) map[string]any {
	return assertion["merkle"].([]any)[0].(map[string]any)
}

// flatFragmented is a fragmented MP4 in one file, built by fragmentedFlatAsset.
type flatFragmented struct {
	asset     []byte
	assertion map[string]any
	leaves    [][]byte // the chunk hashes
	moovStart int
	moofStart []int // offset of each chunk's 'moof'
	mdatStart []int // offset of each chunk's 'mdat'
}

// fragmentedFlatAsset builds a fragmented MP4 in one flat file — 'ftyp',
// 'moov', then n chunks each preceded by its merkle box: [uuid][moof][mdat] —
// and the c2pa.hash.bmff.v3 assertion binding it, with the tree's row of
// storedRowLen nodes stored in the assertion and each box carrying the proof
// up to that row. mutate, if set, edits a box's spec before it is written.
//
// Chunk hashes come from the package's own offset-marker walk over the laid-out
// file. Every merkle box has the same fixed size, so the layout does not depend
// on what the boxes say and no fixpoint is needed.
func fragmentedFlatAsset(t testing.TB, n, storedRowLen, uniqueID, localID int, mutate func(k int, spec *merkleBoxSpec)) flatFragmented {
	t.Helper()
	ctx := context.Background()
	ftyp := synthBox("ftyp", []byte("isom"))
	moov := synthBox("moov", bytes.Repeat([]byte{0x55}, 24))
	assemble := func(boxes [][]byte) []byte {
		file := append(append([]byte{}, ftyp...), moov...)
		for k := 0; k < n; k++ {
			file = append(file, boxes[k]...)
			file = append(file, synthBox("moof", bytes.Repeat([]byte{byte(0x60 + k)}, 16))...)
			file = append(file, synthBox("mdat", bytes.Repeat([]byte{byte(0x70 + k)}, 32))...)
		}
		return file
	}
	excl, exclCBOR := standardBMFFExclusions()

	// Lay the file out with placeholder boxes to learn where every chunk lies.
	placeholder := make([][]byte, n)
	for k := range placeholder {
		placeholder[k] = testMerkleBox(t, merkleBoxSpec{uniqueID: uniqueID, localID: localID, location: k})
	}
	layout := assemble(placeholder)
	top := parseBMFFBoxes(ctx, layout)
	if len(top) != 2+3*n {
		t.Fatalf("laid out %d top-level boxes, want %d", len(top), 2+3*n)
	}
	ranges := bmffExclusionByteRanges(layout, top, excl)
	ff := flatFragmented{leaves: make([][]byte, n), moovStart: len(ftyp), moofStart: make([]int, n), mdatStart: make([]int, n)}
	for k := 0; k < n; k++ {
		moof, mdat := top[2+3*k+1], top[2+3*k+2]
		h := sha256.New()
		hashBMFFTopLevel(ctx, layout, []*bmffBox{moof, mdat}, ranges, h)
		ff.leaves[k] = h.Sum(nil)
		ff.moofStart[k], ff.mdatStart[k] = moof.start, mdat.start
	}
	firstMoof := ff.moofStart[0]
	h := sha256.New()
	hashBMFFTopLevel(ctx, layout, top, mergeRanges(append(append([]byteRange(nil), ranges...),
		byteRange{start: firstMoof, length: len(layout) - firstMoof})), h)
	initHash := h.Sum(nil)

	boxes := make([][]byte, n)
	for k := range boxes {
		spec := merkleBoxSpec{uniqueID: uniqueID, localID: localID, location: k,
			hashes: merkleProofFor(t, ff.leaves, k, storedRowLen)}
		if mutate != nil {
			mutate(k, &spec)
		}
		boxes[k] = testMerkleBox(t, spec)
	}
	ff.asset = assemble(boxes)
	if len(ff.asset) != len(layout) {
		t.Fatalf("final layout is %d bytes, placeholder was %d", len(ff.asset), len(layout))
	}
	ff.assertion = merkleAssertion(uniqueID, localID, n, initHash, merkleRow(t, ff.leaves, storedRowLen), exclCBOR)
	return ff
}

// splitFragmented is a fragmented asset split across files, built by
// fragmentedFiles.
type splitFragmented struct {
	init      []byte
	frags     [][]byte
	assertion map[string]any
	leaves    [][]byte // the fragment hashes
}

// splitOpts adjusts fragmentedFiles.
type splitOpts struct {
	noStyp   bool                             // omit the 'styp' a CMAF fragment starts with
	mutate   func(k int, spec *merkleBoxSpec) // edit a fragment's merkle box before it is written
	moovFill byte                             // the 'moov' filler byte; 0 means the default, so two sets can have different inits
}

// fragmentedFiles builds a fragmented asset the way DASH/CMAF ships it: an
// initialization segment ('ftyp' + 'moov') and n fragment files, each
// [styp][uuid merkle][moof][mdat]. A fragment is hashed from its own offset 0
// with the exclusions re-resolved against its own boxes, and the init hash
// covers the whole initialization segment — which is why joining the files end
// to end does NOT make the flat fragmented file the same chunks would.
func fragmentedFiles(t testing.TB, n, storedRowLen, uniqueID, localID int, o splitOpts) splitFragmented {
	t.Helper()
	ctx := context.Background()
	excl, exclCBOR := standardBMFFExclusions()
	sf := splitFragmented{leaves: make([][]byte, n), frags: make([][]byte, n)}
	fill := byte(0x55)
	if o.moovFill != 0 {
		fill = o.moovFill
	}
	sf.init = append(synthBox("ftyp", []byte("iso6")), synthBox("moov", bytes.Repeat([]byte{fill}, 24))...)
	initTop := parseBMFFBoxes(ctx, sf.init)
	h := sha256.New()
	hashBMFFTopLevel(ctx, sf.init, initTop, bmffExclusionByteRanges(sf.init, initTop, excl), h)
	initHash := h.Sum(nil)

	fragment := func(k int, box []byte) []byte {
		var parts [][]byte
		if !o.noStyp {
			parts = append(parts, synthBox("styp", []byte("msdh")))
		}
		return bytes.Join(append(parts,
			box,
			synthBox("moof", bytes.Repeat([]byte{byte(0x60 + k)}, 16)),
			synthBox("mdat", bytes.Repeat([]byte{byte(0x70 + k)}, 32)),
		), nil)
	}
	hashFragment := func(frag []byte) []byte {
		top := parseBMFFBoxes(ctx, frag)
		h := sha256.New()
		hashBMFFTopLevel(ctx, frag, top, bmffExclusionByteRanges(frag, top, excl), h)
		return h.Sum(nil)
	}
	for k := range sf.leaves {
		sf.leaves[k] = hashFragment(fragment(k, testMerkleBox(t, merkleBoxSpec{uniqueID: uniqueID, localID: localID, location: k})))
	}
	for k := range sf.frags {
		spec := merkleBoxSpec{uniqueID: uniqueID, localID: localID, location: k,
			hashes: merkleProofFor(t, sf.leaves, k, storedRowLen)}
		if o.mutate != nil {
			o.mutate(k, &spec)
		}
		sf.frags[k] = fragment(k, testMerkleBox(t, spec))
		if got := hashFragment(sf.frags[k]); !bytes.Equal(got, sf.leaves[k]) {
			t.Fatalf("fragment %d hash moved when its merkle box was filled in", k)
		}
	}
	sf.assertion = merkleAssertion(uniqueID, localID, n, initHash, merkleRow(t, sf.leaves, storedRowLen), exclCBOR)
	return sf
}

// statusExplanation returns the explanation of the first status with code.
func statusExplanation(res ValidationResult, code StatusCode) string {
	for _, s := range res.Statuses {
		if s.Code == code {
			return s.Explanation
		}
	}
	return ""
}

// expectMismatchSaying asserts a mismatch whose explanation contains want, and
// no match alongside it.
func expectMismatchSaying(t testing.TB, res ValidationResult, want string) {
	t.Helper()
	if hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match: %v", codes(res))
	}
	if !hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Fatalf("expected %s, got %v (%q)", StatusAssertionBMFFHashMismatch, codes(res), merkleExplanation(res))
	}
	if got := statusExplanation(res, StatusAssertionBMFFHashMismatch); !strings.Contains(got, want) {
		t.Errorf("mismatch does not say %q: %q", want, got)
	}
}

// --- flat fragmented file -----------------------------------------------------

// TestBMFFMerkleFragmentedFlatFile covers a fragmented asset in one flat file
// end to end: the init hash over 'ftyp'/'moov', and each chunk's hash checked
// against the proof in the merkle box before it — whichever row of the tree the
// assertion stores, and so whatever length of proof the boxes carry.
func TestBMFFMerkleFragmentedFlatFile(t *testing.T) {
	tests := []struct {
		name         string
		n, storedRow int
	}{
		{"one chunk", 1, 1},
		{"leaf row stored, no proofs", 4, 4},
		{"root stored", 4, 1},
		{"intermediate row stored", 4, 2},
		{"odd count, root stored", 5, 1},
		{"odd count, row of three", 5, 3},
		{"odd count, row of two", 5, 2},
		{"seven chunks, root stored", 7, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ff := fragmentedFlatAsset(t, tc.n, tc.storedRow, 1, 1, nil)
			res := runMerkle(t, ff.asset, ff.assertion)
			if !hasCode(res, StatusAssertionBMFFHashMatch) {
				t.Fatalf("expected a match, got %v (%q %q)", codes(res),
					merkleExplanation(res), statusExplanation(res, StatusAssertionBMFFHashMismatch))
			}
			if hasCode(res, StatusUnsupported) {
				t.Errorf("a fully verifiable fragmented file should raise no advisory: %q", merkleExplanation(res))
			}
		})
	}
}

// TestBMFFMerkleFragmentedFlatTamper is the point of the binding: editing a
// byte of one chunk breaks that chunk's proof and names the chunk, and editing
// the initialization segment breaks the init hash.
func TestBMFFMerkleFragmentedFlatTamper(t *testing.T) {
	ff := fragmentedFlatAsset(t, 4, 1, 1, 1, nil)
	for k := range 4 {
		tampered := append([]byte(nil), ff.asset...)
		tampered[ff.mdatStart[k]+12] ^= 0xFF
		expectMismatchSaying(t, runMerkle(t, tampered, ff.assertion), fmt.Sprintf("chunk %d hash", k))
	}
	tampered := append([]byte(nil), ff.asset...)
	tampered[ff.moovStart+12] ^= 0xFF
	expectMismatchSaying(t, runMerkle(t, tampered, ff.assertion), "initialization segment")
}

// TestBMFFMerkleFragmentedFlatCardinality pins that the chunk count, the merkle
// box count and the map's count must all agree — positional pairing means
// nothing otherwise — and that the disagreement is reported, not guessed around.
func TestBMFFMerkleFragmentedFlatCardinality(t *testing.T) {
	t.Run("map count disagrees with the chunks", func(t *testing.T) {
		ff := fragmentedFlatAsset(t, 3, 1, 1, 1, nil)
		firstMerkleMap(ff.assertion)["count"] = 4
		expectMismatchSaying(t, runMerkle(t, ff.asset, ff.assertion), "3 fragment chunks")
	})
	t.Run("an extra merkle box", func(t *testing.T) {
		ff := fragmentedFlatAsset(t, 3, 1, 1, 1, nil)
		// Appended after the last 'mdat' it lies inside the last chunk, where
		// the /uuid exclusion keeps it out of the hash — only the count changes.
		asset := append(append([]byte(nil), ff.asset...),
			testMerkleBox(t, merkleBoxSpec{uniqueID: 1, localID: 1, location: 3})...)
		expectMismatchSaying(t, runMerkle(t, asset, ff.assertion), "4 merkle boxes")
	})
}

// TestBMFFMerkleFragmentedFlatBoxIdentity pins what a merkle box must say about
// itself — the tree it belongs to and its place in it — and what a proof must
// look like. §15.12.2 has locations run 0, 1, 2… in file order, and checking
// that is what stops two chunks swapping places along with their proofs.
func TestBMFFMerkleFragmentedFlatBoxIdentity(t *testing.T) {
	t.Run("location out of sequence", func(t *testing.T) {
		ff := fragmentedFlatAsset(t, 4, 1, 1, 1, func(k int, spec *merkleBoxSpec) {
			if k == 1 {
				spec.location = 2
			}
		})
		expectMismatchSaying(t, runMerkle(t, ff.asset, ff.assertion), "chunk 1 carries merkle location 2")
	})
	t.Run("box for another tree", func(t *testing.T) {
		ff := fragmentedFlatAsset(t, 4, 1, 1, 1, func(k int, spec *merkleBoxSpec) {
			if k == 2 {
				spec.uniqueID = 9
			}
		})
		expectMismatchSaying(t, runMerkle(t, ff.asset, ff.assertion), "uniqueId 9")
	})
	t.Run("wrong proof element", func(t *testing.T) {
		ff := fragmentedFlatAsset(t, 4, 1, 1, 1, func(k int, spec *merkleBoxSpec) {
			if k == 0 {
				spec.hashes[1] = bytes.Repeat([]byte{0x07}, 32)
			}
		})
		expectMismatchSaying(t, runMerkle(t, ff.asset, ff.assertion), "chunk 0 hash does not match")
	})
	malformed := []struct {
		name   string
		mutate func(k int, spec *merkleBoxSpec)
	}{
		{"proof too short", func(k int, spec *merkleBoxSpec) {
			if k == 0 {
				spec.hashes = spec.hashes[:1]
			}
		}},
		{"proof too long", func(k int, spec *merkleBoxSpec) {
			if k == 0 {
				spec.hashes = append(spec.hashes, bytes.Repeat([]byte{0x08}, 32))
			}
		}},
		{"proof absent though a higher row is stored", func(k int, spec *merkleBoxSpec) {
			if k == 0 {
				spec.hashes = nil
			}
		}},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			ff := fragmentedFlatAsset(t, 4, 1, 1, 1, tc.mutate)
			res := runMerkle(t, ff.asset, ff.assertion)
			if !hasCode(res, StatusAssertionBMFFHashMalformed) {
				t.Errorf("expected %s, got %v", StatusAssertionBMFFHashMalformed, codes(res))
			}
			if hasCode(res, StatusAssertionBMFFHashMatch) {
				t.Errorf("reported a match on a proof that cannot fit the tree")
			}
		})
	}
	t.Run("merkle box that does not decode", func(t *testing.T) {
		ff := fragmentedFlatAsset(t, 2, 1, 1, 1, nil)
		asset := append([]byte(nil), ff.asset...)
		// The CBOR map header sits right after the NUL-terminated purpose.
		p := ff.moofStart[0] - testMerkleBoxPayload
		asset[p] = 0xFF // not a CBOR data item
		res := runMerkle(t, asset, ff.assertion)
		if !hasCode(res, StatusAssertionBMFFHashMalformed) {
			t.Errorf("expected %s, got %v", StatusAssertionBMFFHashMalformed, codes(res))
		}
	})
}

// TestBMFFMerkleBareFragment pins the line c2pa-rs draws too: a file that
// BEGINS with a 'moof' is a fragment, not fragmented content — it has no
// initialization segment for an initHash to cover and no chunks to pair.
func TestBMFFMerkleBareFragment(t *testing.T) {
	ff := fragmentedFlatAsset(t, 2, 1, 1, 1, nil)
	bare := ff.asset[ff.moofStart[0]:]
	res := runMerkle(t, bare, ff.assertion)
	if hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Errorf("a bare fragment verified as a fragmented asset: %v", codes(res))
	}
	if !hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Errorf("expected a mismatch, got %v", codes(res))
	}
}

// TestBMFFMerkleConcatenatedFragmentsAreNotAFlatFile pins §A.5.4.1.2: a
// fragment is hashed from its own offset 0, so the files of a split asset joined
// end to end are not the flat file the same chunks would make — every offset
// marker has moved. The fragments here carry no 'styp', so the joined file's
// initialization segment is byte-for-byte the real one and the ONLY thing that
// differs from a flat file is where each chunk's offsets are anchored; a
// verifier that anchored them at the chunk would match, and must not.
func TestBMFFMerkleConcatenatedFragmentsAreNotAFlatFile(t *testing.T) {
	sf := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{noStyp: true})
	joined := append([]byte(nil), sf.init...)
	for _, f := range sf.frags {
		joined = append(joined, f...)
	}
	expectMismatchSaying(t, runMerkle(t, joined, sf.assertion), "chunk 0 hash does not match")
}

// TestBMFFMerkleInitSegmentAlone covers a fragmented asset's initialization
// segment read on its own: it carries an init hash but no 'moof', so this file
// proves or disproves the init hash and the fragments it binds are other files
// entirely — named as such, never rolled into a match.
func TestBMFFMerkleInitSegmentAlone(t *testing.T) {
	sf := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	res := runMerkle(t, sf.init, sf.assertion)
	if hasCode(res, StatusAssertionBMFFHashMismatch) {
		t.Fatalf("a correct init hash should not mismatch: %v", codes(res))
	}
	if hasCode(res, StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match while the fragments went unverified: %v", codes(res))
	}
	if !hasCode(res, StatusUnsupported) {
		t.Fatalf("expected an advisory naming what was not verified: %v", codes(res))
	}
	got := merkleExplanation(res)
	for _, want := range []string{"other files", "3 fragments", "initialization segment hash matches"} {
		if !strings.Contains(got, want) {
			t.Errorf("advisory does not say %q: %q", want, got)
		}
	}

	// A WRONG init hash is disproved by this file alone, so it must fail.
	firstMerkleMap(sf.assertion)["initHash"] = bytes.Repeat([]byte{0x02}, 32)
	expectMismatchSaying(t, runMerkle(t, sf.init, sf.assertion), "initialization segment")
}

// --- the pieces ---------------------------------------------------------------

// TestMerkleLayout pins that merkleLayout describes exactly the tree
// merkleLayers builds, row for row, so a proof folded by one shape is checked
// against a tree of the same shape.
func TestMerkleLayout(t *testing.T) {
	for n := 1; n <= 40; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte{byte(i)}
		}
		layers := merkleLayers("sha256", leaves)
		widths := merkleLayout(n)
		if len(widths) != len(layers) {
			t.Fatalf("n=%d: layout has %d rows, tree has %d", n, len(widths), len(layers))
		}
		for i := range layers {
			if len(layers[i]) != widths[i] {
				t.Errorf("n=%d row %d: layout says %d nodes, tree has %d", n, i, widths[i], len(layers[i]))
			}
		}
	}
	if merkleLayout(0) != nil {
		t.Errorf("a tree over no leaves has no rows")
	}
}

// TestMerkleProve folds a proof for every leaf of every tree up to 17 leaves,
// up to every row the assertion could store, and checks it against the tree
// merkleLayers rebuilds; then breaks each proof every way a box can.
func TestMerkleProve(t *testing.T) {
	for count := 1; count <= 17; count++ {
		leaves := make([][]byte, count)
		for i := range leaves {
			sum := sha256.Sum256([]byte{byte(i)})
			leaves[i] = sum[:]
		}
		for _, storedRow := range merkleLayout(count) {
			m := merkleMap{count: count, hashes: merkleRow(t, leaves, storedRow)}
			for loc := range count {
				proof := merkleProofFor(t, leaves, loc, storedRow)
				name := fmt.Sprintf("count %d, row of %d, leaf %d", count, storedRow, loc)
				if ok, malformed := merkleProve("sha256", m, leaves[loc], loc, proof); !ok || malformed {
					t.Errorf("%s: ok=%v malformed=%v, want a clean match", name, ok, malformed)
				}
				wrong := append([]byte(nil), leaves[loc]...)
				wrong[0] ^= 1
				if ok, malformed := merkleProve("sha256", m, wrong, loc, proof); ok || malformed {
					t.Errorf("%s: wrong leaf gave ok=%v malformed=%v, want a plain mismatch", name, ok, malformed)
				}
				long := append(append([][]byte(nil), proof...), leaves[0])
				if ok, malformed := merkleProve("sha256", m, leaves[loc], loc, long); ok || !malformed {
					t.Errorf("%s: proof past the stored row gave ok=%v malformed=%v", name, ok, malformed)
				}
				if len(proof) == 0 {
					continue
				}
				short := proof[:len(proof)-1]
				if ok, malformed := merkleProve("sha256", m, leaves[loc], loc, short); ok || !malformed {
					t.Errorf("%s: proof too short gave ok=%v malformed=%v", name, ok, malformed)
				}
				bad := append([][]byte(nil), proof...)
				bad[0] = bytes.Repeat([]byte{0x07}, 32)
				if ok, malformed := merkleProve("sha256", m, leaves[loc], loc, bad); ok || malformed {
					t.Errorf("%s: wrong proof element gave ok=%v malformed=%v, want a plain mismatch", name, ok, malformed)
				}
			}
			if ok, malformed := merkleProve("sha256", m, leaves[0], count, nil); ok || malformed {
				t.Errorf("count %d: a location past the tree gave ok=%v malformed=%v", count, ok, malformed)
			}
		}
		// count+1 is never a row of a count-leaf tree.
		bogus := merkleMap{count: count, hashes: make([][]byte, count+1)}
		if ok, malformed := merkleProve("sha256", bogus, leaves[0], 0, nil); ok || !malformed {
			t.Errorf("count %d: a stored row no tree has gave ok=%v malformed=%v", count, ok, malformed)
		}
	}
	// The algorithm is the caller's to validate; refusing it here only keeps
	// the never-panic contract.
	if ok, malformed := merkleProve("md5", merkleMap{count: 1, hashes: [][]byte{{1}}}, []byte{1}, 0, nil); ok || !malformed {
		t.Errorf("unsupported algorithm gave ok=%v malformed=%v", ok, malformed)
	}
}

// TestBMFFChunks pins where a chunk starts and ends: at a 'moof', up to the box
// before the next one, with trailing boxes belonging to the last chunk — and
// that a file with no 'moof', or one that opens with a 'moof', has no chunks.
func TestBMFFChunks(t *testing.T) {
	box := func(typ string) *bmffBox { return &bmffBox{typ: typ} }
	top := []*bmffBox{box("ftyp"), box("moov"), box("uuid"), box("moof"), box("mdat"),
		box("uuid"), box("moof"), box("mdat"), box("free")}
	chunks := bmffChunks(top)
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	if len(chunks[0]) != 3 || chunks[0][0] != top[3] || chunks[0][2] != top[5] {
		t.Errorf("chunk 0 should be moof, mdat and the next merkle box; got %d boxes", len(chunks[0]))
	}
	if len(chunks[1]) != 3 || chunks[1][0] != top[6] || chunks[1][2] != top[8] {
		t.Errorf("chunk 1 should run to the end of the file; got %d boxes", len(chunks[1]))
	}
	if got := bmffChunks([]*bmffBox{box("moof"), box("mdat")}); got != nil {
		t.Errorf("a file that opens with 'moof' is a bare fragment, not fragmented content: %d chunks", len(got))
	}
	if got := bmffChunks([]*bmffBox{box("ftyp"), box("moov"), box("mdat")}); got != nil {
		t.Errorf("a file with no 'moof' has no chunks: %d", len(got))
	}
}

// TestDecodeMerkleBox pins the box decoder: the zero padding a fixed-size box
// carries after its CBOR is ignored, the proof is optional, and everything
// else is required, non-negative and within the caps.
func TestDecodeMerkleBox(t *testing.T) {
	enc := func(v any) []byte {
		raw, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	proof := bytes.Repeat([]byte{9}, 32)
	good := map[string]any{"uniqueId": 1, "localId": 2, "location": 3, "hashes": []any{proof}}
	for name, payload := range map[string][]byte{
		"exact":  enc(good),
		"padded": append(enc(good), make([]byte, 100)...),
	} {
		mb, ok := decodeMerkleBox(payload)
		if !ok || mb.uniqueID != 1 || mb.localID != 2 || mb.location != 3 || len(mb.hashes) != 1 || !bytes.Equal(mb.hashes[0], proof) {
			t.Errorf("%s: got %+v ok=%v", name, mb, ok)
		}
	}
	if mb, ok := decodeMerkleBox(enc(map[string]any{"uniqueId": 1, "localId": 2, "location": 0})); !ok || mb.hashes != nil {
		t.Errorf("a box without a proof is valid: %+v ok=%v", mb, ok)
	}
	tooMany := make([]any, maxMerkleProof+1)
	for i := range tooMany {
		tooMany[i] = proof
	}
	for name, payload := range map[string][]byte{
		"empty payload":      {},
		"zero padding only":  make([]byte, 64),
		"not a map":          enc([]any{1, 2, 3}),
		"no location":        enc(map[string]any{"uniqueId": 1, "localId": 2}),
		"negative location":  enc(map[string]any{"uniqueId": 1, "localId": 2, "location": -1}),
		"empty proof list":   enc(map[string]any{"uniqueId": 1, "localId": 2, "location": 0, "hashes": []any{}}),
		"empty proof hash":   enc(map[string]any{"uniqueId": 1, "localId": 2, "location": 0, "hashes": []any{[]byte{}}}),
		"proof over the cap": enc(map[string]any{"uniqueId": 1, "localId": 2, "location": 0, "hashes": tooMany}),
	} {
		if mb, ok := decodeMerkleBox(payload); ok {
			t.Errorf("%s: decoded to %+v, want a rejection", name, mb)
		}
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
