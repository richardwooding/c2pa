package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// flatOpts shapes the file unsignedFlatFragmented builds.
type flatOpts struct {
	sidxVersion int  // -1: no top-level 'sidx'; 0 or 1 otherwise
	tfhdBase    bool // every 'tfhd' carries base-data-offset-present
	stco        bool // a 'moov' whose chunk-offset table addresses every 'mdat'
	mfra        bool // an 'mfra' indexing every 'moof', with its 'mfro'
	styp        bool // a 'styp' at the head of every chunk
	dropMdat    int  // 1-based chunk to build without an 'mdat' (0: none)
}

// unsignedFlatFragmented lays out the flat single-file fragmented arrangement:
// 'ftyp', 'moov', an optional top-level 'sidx' measuring every subsegment,
// then n chunks of ['styp'] 'moof' 'mdat', and an optional 'mfra'. Every
// absolute offset it writes — the 'stco' entries, the 'sidx' first_offset and
// referenced_sizes, each 'tfhd' base_data_offset and each 'tfra' moof_offset —
// is filled in after the layout is known, in a second pass over the assembled
// bytes, so what the writer has to repair is genuinely there to check.
func unsignedFlatFragmented(t testing.TB, n int, o flatOpts) []byte {
	t.Helper()
	mvhd := synthBox("mvhd", bmffFullBox(make([]byte, 96)))
	trak := synthBox("trak", synthBox("tkhd", bmffFullBox(make([]byte, 80))))
	if o.stco {
		stco := synthBox("stco", bmffFullBox(binary.BigEndian.AppendUint32(nil, uint32(n)), make([]byte, 4*n)))
		trak = synthBox("trak", synthBox("tkhd", bmffFullBox(make([]byte, 80))),
			synthBox("mdia", synthBox("minf", synthBox("stbl", stco))))
	}
	mvex := synthBox("mvex", synthBox("trex", bmffFullBox(binary.BigEndian.AppendUint32(nil, 1), make([]byte, 16))))
	file := append(synthBox("ftyp", []byte("iso6"), []byte{0, 0, 0, 0}, []byte("iso6"), []byte("dash")),
		synthBox("moov", mvhd, trak, mvex)...)

	if o.sidxVersion >= 0 {
		body := []byte{byte(o.sidxVersion), 0, 0, 0}
		body = binary.BigEndian.AppendUint32(body, 1)    // reference_ID
		body = binary.BigEndian.AppendUint32(body, 1000) // timescale
		if o.sidxVersion == 0 {
			body = append(body, make([]byte, 8)...) // earliest_presentation_time, first_offset
		} else {
			body = append(body, make([]byte, 16)...)
		}
		body = append(body, 0, 0)                             // reserved
		body = binary.BigEndian.AppendUint16(body, uint16(n)) // reference_count
		body = append(body, make([]byte, 12*n)...)            // the references
		file = append(file, synthBox("sidx", body)...)
	}
	for k := 0; k < n; k++ {
		if o.styp {
			file = append(file, synthBox("styp", []byte("msdh"), []byte{0, 0, 0, 0}, []byte("msdh"), []byte("msix"))...)
		}
		mfhd := synthBox("mfhd", bmffFullBox(binary.BigEndian.AppendUint32(nil, uint32(k+1))))
		tfhdBody := append([]byte{0, 0x02, 0x00, 0x00}, binary.BigEndian.AppendUint32(nil, 1)...) // default-base-is-moof
		if o.tfhdBase {
			tfhdBody = append([]byte{0, 0x00, 0x00, 0x01}, binary.BigEndian.AppendUint32(nil, 1)...)
			tfhdBody = append(tfhdBody, make([]byte, 8)...)
		}
		tfdt := synthBox("tfdt", append([]byte{1, 0, 0, 0}, binary.BigEndian.AppendUint64(nil, uint64(k*2000))...))
		trun := synthBox("trun", []byte{0, 0, 0x02, 0x01}, binary.BigEndian.AppendUint32(nil, 1), make([]byte, 8))
		file = append(file, synthBox("moof", mfhd, synthBox("traf", synthBox("tfhd", tfhdBody), tfdt, trun))...)
		if k+1 != o.dropMdat {
			file = append(file, synthBox("mdat", bytes.Repeat([]byte{byte(0x70 + k%64)}, 40+k%17))...)
		}
	}
	if o.mfra {
		body := []byte{0, 0, 0, 0}
		body = binary.BigEndian.AppendUint32(body, 1)         // track_ID
		body = binary.BigEndian.AppendUint32(body, 0)         // one-byte traf/trun/sample numbers
		body = binary.BigEndian.AppendUint32(body, uint32(n)) // number_of_entry
		for k := 0; k < n; k++ {
			body = binary.BigEndian.AppendUint32(body, uint32(k*2000)) // time
			body = append(body, make([]byte, 4)...)                    // moof_offset
			body = append(body, 1, 1, 1)                               // traf, trun, sample numbers
		}
		tfra := synthBox("tfra", body)
		mfro := synthBox("mfro", bmffFullBox(binary.BigEndian.AppendUint32(nil, uint32(8+len(tfra)+16))))
		file = append(file, synthBox("mfra", tfra, mfro)...)
	}
	return fillFlatOffsets(t, file, n, o)
}

// fillFlatOffsets writes the absolute offsets the assembled layout implies.
func fillFlatOffsets(t testing.TB, file []byte, n int, o flatOpts) []byte {
	t.Helper()
	ctx := context.Background()
	top := parseBMFFBoxes(ctx, file)
	var moofs, mdats []*bmffBox
	for _, b := range top {
		switch b.typ {
		case "moof":
			moofs = append(moofs, b)
		case "mdat":
			mdats = append(mdats, b)
		}
	}
	if len(moofs) != n {
		t.Fatalf("laid out %d 'moof' boxes, want %d", len(moofs), n)
	}
	if o.stco {
		stco := bmffFind(top, "stco")
		if stco == nil {
			t.Fatal("no 'stco' in the layout")
		}
		for i, mdat := range mdats {
			binary.BigEndian.PutUint32(file[stco.start+stco.headerLen+8+4*i:], uint32(mdat.start+8))
		}
	}
	if sidx := bmffFind(top, "sidx"); sidx != nil {
		payload := sidx.start + sidx.headerLen
		field, w := payload+16, 4
		if o.sidxVersion == 1 {
			field, w = payload+20, 8
		}
		putN(file, field, w, uint64(moofs[0].start-sidx.end))
		at := field + w + 4
		for k := 0; k < n; k++ {
			end := len(file)
			if k+1 < n {
				end = moofs[k+1].start
			} else if last := top[len(top)-1]; last.typ == "mfra" {
				end = last.start
			}
			binary.BigEndian.PutUint32(file[at+12*k:], uint32(end-moofs[k].start))
		}
	}
	if o.tfhdBase {
		for _, moof := range moofs {
			tfhd := bmffFind(moof.children, "tfhd")
			if tfhd == nil {
				t.Fatal("no 'tfhd' in a 'moof'")
			}
			binary.BigEndian.PutUint64(file[tfhd.start+tfhd.headerLen+8:], uint64(moof.start))
		}
	}
	if o.mfra {
		tfra := bmffFind(top, "tfra")
		if tfra == nil {
			t.Fatal("no 'tfra' in the layout")
		}
		for k, moof := range moofs {
			binary.BigEndian.PutUint32(file[tfra.start+tfra.headerLen+16+11*k+4:], uint32(moof.start))
		}
	}
	return file
}

// bmffFind is the first box of type typ in boxes or, recursively, under them.
func bmffFind(boxes []*bmffBox, typ string) *bmffBox {
	for _, b := range boxes {
		if b.typ == typ {
			return b
		}
		if f := bmffFind(b.children, typ); f != nil {
			return f
		}
	}
	return nil
}

// flatChunkStarts are the file offsets of every top-level 'moof'.
func flatChunkStarts(data []byte) []int {
	var out []int
	for _, b := range parseBMFFBoxes(context.Background(), data) {
		if b.typ == "moof" {
			out = append(out, b.start)
		}
	}
	return out
}

// bindingAssertion decodes the c2pa.hash.bmff.v3 assertion of an asset's
// active manifest.
func bindingAssertion(t testing.TB, container Container, data []byte) map[string]any {
	t.Helper()
	ctx := context.Background()
	store := parseStore(ctx, extractJUMBF(ctx, container, data))
	m := store.active()
	if m == nil {
		t.Fatal("no active manifest")
	}
	for _, a := range m.assertions {
		if !bytes.Contains([]byte(a.label), []byte("c2pa.hash.bmff")) {
			continue
		}
		var out map[string]any
		if err := decMode.Unmarshal(a.data, &out); err != nil {
			t.Fatalf("decoding %s: %v", a.label, err)
		}
		return out
	}
	t.Fatal("no BMFF hard binding in the active manifest")
	return nil
}

// TestSignFlatFragmented signs the flat arrangement and validates the result
// through the ordinary Validate entry point, which is what reads flat files.
func TestSignFlatFragmented(t *testing.T) {
	armBindHook(t)
	ctx := context.Background()
	s, sc := newTestSigner(t)
	for _, tc := range []struct {
		name string
		n    int
		o    flatOpts
	}{
		{"plain", 3, flatOpts{sidxVersion: -1}},
		{"one chunk", 1, flatOpts{sidxVersion: -1}},
		{"styp and sidx v0", 4, flatOpts{sidxVersion: 0, styp: true}},
		{"sidx v1, tfhd base, stco, mfra", 5, flatOpts{sidxVersion: 1, tfhdBase: true, stco: true, mfra: true}},
		{"deep tree", 9, flatOpts{sidxVersion: -1, tfhdBase: true}},
		{"proofs stored", 40, flatOpts{sidxVersion: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := unsignedFlatFragmented(t, tc.n, tc.o)
			out := signBytes(t, s, BMFF, in, createdManifest("flat"))
			res := Validate(ctx, BMFF, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Valid || !res.Has(StatusAssertionBMFFHashMatch) {
				t.Fatalf("Validate: valid=%v %v", res.Valid, codes(res))
			}
			if res.Binding != BindingVerified {
				t.Errorf("Binding = %s, want verified", res.Binding)
			}
			// One merkle box per chunk, each stating its own location, and no
			// flat hash in the assertion: this is the fragmented form.
			top := parseBMFFBoxes(ctx, out)
			boxes, ok := bmffMerkleBoxes(ctx, out, top)
			if !ok || len(boxes) != tc.n {
				t.Fatalf("output carries %d merkle boxes (ok=%v), want %d", len(boxes), ok, tc.n)
			}
			for k, mb := range boxes {
				if mb.location != k || mb.uniqueID != 1 || mb.localID != 1 {
					t.Errorf("merkle box %d says unique=%d local=%d location=%d", k, mb.uniqueID, mb.localID, mb.location)
				}
				if next := flatChunkStarts(out)[k]; mb.box.end != next {
					t.Errorf("merkle box %d ends at %d, its 'moof' starts at %d", k, mb.box.end, next)
				}
			}
			a := bindingAssertion(t, BMFF, out)
			if _, has := a["hash"]; has {
				t.Error("the assertion carries a flat hash as well as a merkle array")
			}
			maps, ok := decodeBMFFMerkle(a["merkle"])
			if !ok || len(maps) != 1 || maps[0].count != tc.n {
				t.Fatalf("merkle array: ok=%v %+v", ok, maps)
			}
			if want := merkleLayout(tc.n)[merkleRowIndex(tc.n)]; len(maps[0].hashes) != want {
				t.Errorf("stored row holds %d hashes, want %d", len(maps[0].hashes), want)
			}
		})
	}
}

// TestSignFlatOffsets: every absolute offset the insertions moved still
// addresses what it did. Nothing hashes these, so only this test would notice.
func TestSignFlatOffsets(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestSigner(t)
	const n = 4
	for _, version := range []int{0, 1} {
		o := flatOpts{sidxVersion: version, tfhdBase: true, stco: true, mfra: true, styp: true}
		in := unsignedFlatFragmented(t, n, o)
		out := signBytes(t, s, BMFF, in, createdManifest("flat"))
		inTop, outTop := parseBMFFBoxes(ctx, in), parseBMFFBoxes(ctx, out)
		moofsIn, moofsOut := flatChunkStarts(in), flatChunkStarts(out)
		boxes, _ := bmffMerkleBoxes(ctx, out, outTop)
		padTo := boxes[0].box.end - boxes[0].box.start

		// 'stco' entries still point at the same eight bytes of media.
		stcoIn, stcoOut := bmffFind(inTop, "stco"), bmffFind(outTop, "stco")
		for i := 0; i < n; i++ {
			was := int(binary.BigEndian.Uint32(in[stcoIn.start+stcoIn.headerLen+8+4*i:]))
			now := int(binary.BigEndian.Uint32(out[stcoOut.start+stcoOut.headerLen+8+4*i:]))
			if !bytes.Equal(in[was:was+8], out[now:now+8]) {
				t.Errorf("v%d: 'stco' entry %d moved from %d to %d and no longer addresses the same bytes", version, i, was, now)
			}
		}
		// 'sidx' first_offset points at the first 'moof'; every subsegment
		// grew by exactly the one merkle box that landed inside it.
		sidxIn, sidxOut := bmffFind(inTop, "sidx"), bmffFind(outTop, "sidx")
		firstIn, _ := sidxFirstOffset(in, sidxIn)
		firstOut, _ := sidxFirstOffset(out, sidxOut)
		if got, want := sidxOut.end+int(firstOut), moofsOut[0]; got != want {
			t.Errorf("v%d: 'sidx' first_offset resolves to %d, first 'moof' is at %d (was %d → %d)", version, got, want, sidxIn.end+int(firstIn), moofsIn[0])
		}
		at := sidxOut.start + sidxOut.headerLen + 24
		atIn := sidxIn.start + sidxIn.headerLen + 24
		if version == 1 {
			at, atIn = at+8, atIn+8
		}
		for k := 0; k < n; k++ {
			was := int(binary.BigEndian.Uint32(in[atIn+12*k:]) & 0x7FFFFFFF)
			now := int(binary.BigEndian.Uint32(out[at+12*k:]) & 0x7FFFFFFF)
			want := was + padTo
			if k == n-1 {
				want = was // the last subsegment's own box precedes it
			}
			if now != want {
				t.Errorf("v%d: 'sidx' referenced_size %d went %d → %d, want %d", version, k, was, now, want)
			}
		}
		// 'tfhd' base_data_offset and 'tfra' moof_offset point at their 'moof'.
		for k, moof := range outTop {
			if moof.typ != "moof" {
				continue
			}
			tfhd := bmffFind(moof.children, "tfhd")
			if base := binary.BigEndian.Uint64(out[tfhd.start+tfhd.headerLen+8:]); int(base) != moof.start {
				t.Errorf("v%d: 'tfhd' base_data_offset %d, 'moof' at %d", version, base, moof.start)
			}
			_ = k
		}
		tfra := bmffFind(outTop, "tfra")
		for k := 0; k < n; k++ {
			off := int(binary.BigEndian.Uint32(out[tfra.start+tfra.headerLen+16+11*k+4:]))
			if off != moofsOut[k] {
				t.Errorf("v%d: 'tfra' entry %d points at %d, 'moof' %d is at %d", version, k, off, k, moofsOut[k])
			}
		}
	}
}

// TestSignFlatTamper: what the binding is for. A chunk's media, the
// initialization region and a merkle box are each disproved.
func TestSignFlatTamper(t *testing.T) {
	ctx := context.Background()
	s, sc := newTestSigner(t)
	opts := []ValidateOption{WithSigningTrust(sc.roots), WithOnlineRevocation(false)}
	signed := signBytes(t, s, BMFF, unsignedFlatFragmented(t, 4, flatOpts{sidxVersion: -1}), createdManifest("flat"))

	for _, tc := range []struct {
		name string
		at   func(top []*bmffBox) int
	}{
		{"chunk 2's media", func(top []*bmffBox) int {
			n := 0
			for _, b := range top {
				if b.typ == "mdat" {
					if n == 2 {
						return b.start + b.headerLen + 1
					}
					n++
				}
			}
			return -1
		}},
		{"the 'moov'", func(top []*bmffBox) int {
			for _, b := range top {
				if b.typ == "moov" {
					return b.end - 1
				}
			}
			return -1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), signed...)
			at := tc.at(parseBMFFBoxes(ctx, bad))
			if at < 0 {
				t.Fatal("nothing to tamper with")
			}
			bad[at] ^= 0xFF
			res := Validate(ctx, BMFF, bytes.NewReader(bad), opts...)
			if res.Valid || !res.Has(StatusAssertionBMFFHashMismatch) {
				t.Fatalf("tampering went unnoticed: valid=%v %v", res.Valid, codes(res))
			}
			if res.Binding != BindingFailed {
				t.Errorf("Binding = %s, want failed", res.Binding)
			}
		})
	}
}

// TestSignFlatResign chains a second manifest onto a flat file, which means
// the writer replaces the merkle boxes it wrote before.
func TestSignFlatResign(t *testing.T) {
	ctx := context.Background()
	s, sc := newTestSigner(t)
	first := signBytes(t, s, BMFF, unsignedFlatFragmented(t, 3, flatOpts{sidxVersion: 0, tfhdBase: true}), createdManifest("flat"))
	second := signBytes(t, s, BMFF, first, openedManifest("flat again"))

	res := Validate(ctx, BMFF, bytes.NewReader(second), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Valid || !res.Has(StatusAssertionBMFFHashMatch) || !res.Has(StatusIngredientManifestValidated) {
		t.Fatalf("re-signed: valid=%v %v", res.Valid, codes(res))
	}
	store := parseStore(ctx, extractJUMBF(ctx, BMFF, second))
	if len(store.manifests) != 2 {
		t.Fatalf("re-signed store holds %d manifests, want 2", len(store.manifests))
	}
	// Exactly one merkle box per chunk: the first signature's boxes are gone,
	// not stacked up beside the new ones.
	boxes, ok := bmffMerkleBoxes(ctx, second, parseBMFFBoxes(ctx, second))
	if !ok || len(boxes) != 3 {
		t.Fatalf("re-signed file carries %d merkle boxes (ok=%v), want 3", len(boxes), ok)
	}
}

// TestSignFlatRefusals: what the flat path will not sign, and what it must
// leave to the other two writers.
func TestSignFlatRefusals(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestSigner(t)
	sign := func(asset []byte) error {
		return s.Sign(ctx, BMFF, bytes.NewReader(asset), &bytes.Buffer{}, createdManifest("flat"))
	}
	// A bare fragment — 'moof' first, no 'moov' — is SignFragmented's input.
	_, frags := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1, noStyp: true})
	if err := sign(frags[0]); !errors.Is(err, ErrFragmentedBMFF) {
		t.Errorf("bare fragment: %v, want ErrFragmentedBMFF", err)
	}
	// So is a DASH initialization segment on its own: no 'moof' at all, so the
	// flat path does not claim it and the flat hash cannot bind fragments.
	init, _ := unsignedFragmentedSet(2, fragOpts{sidxVersion: -1})
	if err := sign(init); err != nil {
		t.Errorf("initialization segment through the ordinary BMFF path: %v", err)
	}
	// A chunk with no media data is not a fragment this writer will bind.
	if err := sign(unsignedFlatFragmented(t, 3, flatOpts{sidxVersion: -1, dropMdat: 2})); !errors.Is(err, ErrUnsupportedContainer) {
		t.Errorf("chunk without 'mdat': %v, want ErrUnsupportedContainer", err)
	}
	// Trailing bytes outside any box stay malformed.
	if err := sign(append(unsignedFlatFragmented(t, 2, flatOpts{sidxVersion: -1}), 1, 2, 3)); !errors.Is(err, ErrMalformedAsset) {
		t.Errorf("trailing bytes: %v, want ErrMalformedAsset", err)
	}
}

// lonelyFragment is a CMAF media fragment with no initialization segment: what
// SignFragmented takes as one of its inputs, and what Sign must refuse.
func lonelyFragment(t testing.TB) []byte {
	t.Helper()
	_, frags := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	return frags[0]
}
