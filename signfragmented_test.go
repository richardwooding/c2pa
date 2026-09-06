package c2pa

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// validateSet runs ValidateFragmented over signed bytes with the test chain.
func validateSet(t testing.TB, sc signingChain, init []byte, frags [][]byte, extra ...ValidateOption) ValidationResult {
	t.Helper()
	opts := append([]ValidateOption{WithSigningTrust(sc.roots), WithOnlineRevocation(false)}, extra...)
	return ValidateFragmented(context.Background(), bytes.NewReader(init), readersOf(frags...), opts...)
}

// merkleAssertionOf decodes the active manifest's c2pa.hash.bmff.v3.
func merkleAssertionOf(t testing.TB, init []byte) map[string]any {
	t.Helper()
	ctx := context.Background()
	store := extractJUMBF(ctx, BMFF, init)
	var raw []byte
	WalkBoxes(ctx, store, func(label, tbox string, content []byte) {
		if label == "c2pa.hash.bmff.v3" && tbox == "cbor" {
			raw = content // the active manifest is last, so the last one wins
		}
	})
	if raw == nil {
		t.Fatal("no c2pa.hash.bmff.v3 in the signed initialization segment")
	}
	var m map[string]any
	if err := decMode.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSignFragmentedRoundTrip(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags := unsignedFragmentedSet(4, fragOpts{sidxVersion: 0})
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("bunny.mp4"))

	res := validateSet(t, sc, sInit, sFrags)
	expectFragmentedMatch(t, res, 4)
	if !res.Has(StatusClaimSignatureValidated) || res.Info.Title != "bunny.mp4" || res.VerifiedSigner() == "" {
		t.Fatalf("verdict: %v title %q signer %q", codes(res), res.Info.Title, res.VerifiedSigner())
	}
	a := merkleAssertionOf(t, sInit)
	if _, flat := a["hash"]; flat {
		t.Error("a fragmented assertion must not carry a flat hash")
	}
	maps, ok := decodeBMFFMerkle(a["merkle"])
	if !ok || len(maps) != 1 {
		t.Fatalf("merkle array: %v %v", maps, ok)
	}
	m := maps[0]
	if m.uniqueID != 1 || m.localID != 1 || m.count != 4 || m.alg != "sha256" || len(m.initHash) != 32 || len(m.hashes) != 1 {
		t.Fatalf("map = %+v", m)
	}
	// Every fragment: one merkle box, all the same size, directly before moof.
	size := -1
	for i, f := range sFrags {
		top := parseBMFFBoxes(context.Background(), f)
		var uuid, moof *bmffBox
		for _, b := range top {
			if b.typ == "uuid" && b.usertype == c2paBoxUUID {
				uuid = b
			}
			if b.typ == "moof" {
				moof = b
			}
		}
		if uuid == nil || moof == nil || uuid.end != moof.start {
			t.Fatalf("fragment %d: merkle box not directly before moof", i)
		}
		if size >= 0 && uuid.end-uuid.start != size {
			t.Fatalf("fragment %d: box size %d differs from %d", i, uuid.end-uuid.start, size)
		}
		size = uuid.end - uuid.start
		mb, ok := decodeMerkleBox(c2paMerklePayload(f, uuid))
		if !ok || mb.location != i || len(mb.hashes) != merkleProofLen(4, i, merkleRowIndex(4)) {
			t.Fatalf("fragment %d: box %+v (%v)", i, mb, ok)
		}
	}
	// Read on the init sees the claim; Validate alone says to use ValidateFragmented.
	if !Read(context.Background(), BMFF, bytes.NewReader(sInit)).Present {
		t.Error("Read does not see the manifest")
	}
	alone := Validate(context.Background(), BMFF, bytes.NewReader(sInit), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if alone.Has(StatusAssertionBMFFHashMatch) || !strings.Contains(statusExplanation(alone, StatusUnsupported), "ValidateFragmented") {
		t.Errorf("the init alone should point at ValidateFragmented: %v", codes(alone))
	}
}

func TestSignFragmentedTamper(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags := unsignedFragmentedSet(3, fragOpts{sidxVersion: 0})
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("t"))

	bad := append([][]byte(nil), sFrags...)
	bad[2] = append([]byte(nil), sFrags[2]...)
	bad[2][len(bad[2])-1] ^= 0xFF // inside mdat
	res := validateSet(t, sc, sInit, bad)
	fails := fragmentFailures(res)
	if res.Valid || len(fails) != 1 {
		t.Fatalf("tampered fragment 2: valid=%v failures %v", res.Valid, fails)
	}
	if _, ok := fails["2"]; !ok {
		t.Fatalf("failure at %v, want fragment 2", fails)
	}
	badInit := append([]byte(nil), sInit...)
	moov := topBox(badInit, "moov")
	badInit[moov.start+12] ^= 0xFF
	res = validateSet(t, sc, badInit, sFrags)
	if res.Valid || !strings.Contains(firstFailureText(res), "initialization segment hash does not match") {
		t.Fatalf("tampered init: valid=%v %s", res.Valid, firstFailureText(res))
	}
}

func TestSignFragmentedOffsetsPatched(t *testing.T) {
	s, sc := newTestSigner(t)
	for _, o := range []fragOpts{{sidxVersion: 0}, {sidxVersion: 1, emsg: true}, {sidxVersion: 0, tfhdBase: true}, {sidxVersion: -1, tfhdBase: true, noStyp: true}} {
		init, frags := unsignedFragmentedSet(3, o)
		sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("o"))
		expectFragmentedMatch(t, validateSet(t, sc, sInit, sFrags), 3)
		for i, f := range sFrags {
			moof := topBox(f, "moof")
			if o.sidxVersion >= 0 {
				sidx := topBox(f, "sidx")
				first, end := sidxFirstOffset(f, sidx)
				if end+int(first) != moof.start {
					t.Errorf("%+v fragment %d: sidx points at %d, moof at %d", o, i, end+int(first), moof.start)
				}
				if got, want := sidxReferencedSize(f, sidx), sidxReferencedSize(frags[i], topBox(frags[i], "sidx")); got != want {
					t.Errorf("%+v fragment %d: referenced_size changed %d → %d", o, i, want, got)
				}
			}
			if o.tfhdBase {
				base, ok := tfhdBaseOffset(f, moof)
				if !ok || int(base) != moof.start {
					t.Errorf("%+v fragment %d: tfhd base %d (%v), moof at %d", o, i, base, ok, moof.start)
				}
			}
			if o.emsg && topBox(f, "emsg") == nil {
				t.Errorf("%+v fragment %d: emsg lost", o, i)
			}
		}
	}
}

func TestSignFragmentedResign(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags := unsignedFragmentedSet(3, fragOpts{sidxVersion: 0})
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("first"))

	// created on an already-signed set is refused, and nothing is written.
	var outInit bytes.Buffer
	bufs, ws := fragmentWriters(3)
	err := s.SignFragmented(context.Background(), bytes.NewReader(sInit), fragmentSeekers(sFrags), &outInit, ws, createdManifest("again"))
	if !errors.Is(err, ErrManifestInvalid) || outInit.Len() != 0 || bufs[0].Len() != 0 {
		t.Fatalf("created on a signed set: %v (%d, %d bytes written)", err, outInit.Len(), bufs[0].Len())
	}

	rInit, rFrags := signFragmentedSet(t, s, sInit, sFrags, openedManifest("second"))
	res := validateSet(t, sc, rInit, rFrags)
	expectFragmentedMatch(t, res, 3)
	if !res.Has(StatusIngredientManifestValidated) || res.Info.Title != "second" {
		t.Fatalf("re-sign: %v title %q", codes(res), res.Info.Title)
	}
	if n := len(parseStore(context.Background(), extractJUMBF(context.Background(), BMFF, rInit)).manifests); n != 2 {
		t.Fatalf("store holds %d manifests, want 2", n)
	}
	for i, f := range rFrags {
		if c2paBoxCount(f) != 1 {
			t.Errorf("fragment %d carries %d C2PA boxes after re-signing, want 1", i, c2paBoxCount(f))
		}
	}

	// c2pa-rs leaves sidx.first_offset stale (0, pointing at its merkle box);
	// re-signing such a fragment re-anchors it at the new moof.
	stale := make([][]byte, len(sFrags))
	for i, f := range sFrags {
		stale[i] = append([]byte(nil), f...)
		sidx := topBox(stale[i], "sidx")
		putN(stale[i], sidx.start+sidx.headerLen+16, 4, 0)
	}
	_, fixed := signFragmentedSet(t, s, sInit, stale, openedManifest("repaired"))
	for i, f := range fixed {
		first, end := sidxFirstOffset(f, topBox(f, "sidx"))
		if moof := topBox(f, "moof"); end+int(first) != moof.start {
			t.Errorf("fragment %d: stale first_offset not repaired: points at %d, moof at %d", i, end+int(first), moof.start)
		}
	}
}

func TestSignFragmentedTreeShapes(t *testing.T) {
	s, sc := newTestSigner(t)
	for _, n := range []int{1, 2, 3, 24, 25, 33, 100} {
		init, frags := unsignedFragmentedSet(n, fragOpts{sidxVersion: -1})
		sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("n"))
		expectFragmentedMatch(t, validateSet(t, sc, sInit, sFrags), n)
		maps, _ := decodeBMFFMerkle(merkleAssertionOf(t, sInit)["merkle"])
		rowIndex := merkleRowIndex(n)
		if want := merkleLayout(n)[rowIndex]; len(maps[0].hashes) != want {
			t.Errorf("n=%d: stored row has %d hashes, want %d", n, len(maps[0].hashes), want)
		}
		want, err := merkleBoxSize("sha256", 1, 1, n, rowIndex)
		if err != nil {
			t.Fatal(err)
		}
		for i, f := range sFrags {
			var uuid *bmffBox
			for _, b := range parseBMFFBoxes(context.Background(), f) {
				if b.typ == "uuid" && b.usertype == c2paBoxUUID {
					uuid = b
				}
			}
			if uuid.end-uuid.start != want {
				t.Fatalf("n=%d fragment %d: box %d bytes, want %d", n, i, uuid.end-uuid.start, want)
			}
			mb, _ := decodeMerkleBox(c2paMerklePayload(f, uuid))
			if len(mb.hashes) != merkleProofLen(n, i, rowIndex) {
				t.Errorf("n=%d fragment %d: proof %d, want %d", n, i, len(mb.hashes), merkleProofLen(n, i, rowIndex))
			}
		}
	}
}

// failingSeeker fails its second Seek — a source that cannot be revisited.
type failingSeeker struct {
	*bytes.Reader
	seeks int
}

func (f *failingSeeker) Seek(off int64, whence int) (int64, error) {
	f.seeks++
	if f.seeks > 1 {
		return 0, errors.New("gone")
	}
	return f.Reader.Seek(off, whence)
}

// mutatingSeeker serves different bytes on every pass.
type mutatingSeeker struct {
	data  []byte
	pass  int
	inner *bytes.Reader
}

func (m *mutatingSeeker) Seek(off int64, whence int) (int64, error) {
	d := append([]byte(nil), m.data...)
	if m.pass > 0 {
		d[len(d)-1] ^= 0xFF
	}
	m.pass++
	m.inner = bytes.NewReader(d)
	return m.inner.Seek(off, whence)
}
func (m *mutatingSeeker) Read(p []byte) (int, error) { return m.inner.Read(p) }

func TestSignFragmentedErrors(t *testing.T) {
	s, _ := newTestSigner(t)
	ctx := context.Background()
	init, frags := unsignedFragmentedSet(2, fragOpts{sidxVersion: 0})
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("x"))
	ftypOnly := topBoxBytes(init, "ftyp")
	twoMoof := append(append([]byte(nil), frags[0]...), topBoxBytes(frags[1], "moof")...)
	good := createdManifest("ok")

	cases := []struct {
		name  string
		init  []byte
		frags []io.ReadSeeker
		nOut  int
		m     Manifest
		ctx   context.Context
		want  error
	}{
		{"no fragments", init, nil, 0, good, ctx, ErrFragmentSet},
		{"writer count", init, fragmentSeekers(frags), 1, good, ctx, ErrFragmentSet},
		{"nil fragment", init, []io.ReadSeeker{bytes.NewReader(frags[0]), nil}, 2, good, ctx, ErrNoInput},
		{"init is a fragment", frags[0], fragmentSeekers(frags), 2, good, ctx, ErrFragmentedBMFF},
		{"init is a flat fragmented file", fragmentedFlatAsset(t, 2, 1, 1, 1, nil).asset, fragmentSeekers(frags), 2, good, ctx, ErrFragmentedBMFF},
		{"init without moov", ftypOnly, fragmentSeekers(frags), 2, good, ctx, ErrMalformedAsset},
		{"init is garbage", []byte("nope"), fragmentSeekers(frags), 2, good, ctx, ErrMalformedAsset},
		{"fragment is an init", init, fragmentSeekers([][]byte{frags[0], init}), 2, good, ctx, ErrMalformedAsset},
		{"fragment with two moofs", init, fragmentSeekers([][]byte{twoMoof, frags[1]}), 2, good, ctx, ErrUnsupportedContainer},
		{"fragment is garbage", init, fragmentSeekers([][]byte{frags[0], []byte("junk")}), 2, good, ctx, ErrMalformedAsset},
		{"fragment is empty", init, fragmentSeekers([][]byte{frags[0], nil}), 2, good, ctx, ErrMalformedAsset},
		{"seek fails on the second pass", init, []io.ReadSeeker{&failingSeeker{Reader: bytes.NewReader(frags[0])}, bytes.NewReader(frags[1])}, 2, good, ctx, ErrFragmentSet},
		{"fragment changes between passes", init, []io.ReadSeeker{&mutatingSeeker{data: frags[0]}, bytes.NewReader(frags[1])}, 2, good, ctx, ErrFragmentSet},
		{"bad manifest", init, fragmentSeekers(frags), 2, Manifest{Title: "no actions"}, ctx, ErrManifestInvalid},
		{"created on a signed set", sInit, fragmentSeekers(sFrags), 2, good, ctx, ErrManifestInvalid},
		{"cancelled", init, fragmentSeekers(frags), 2, good, cancelledContext(), context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var outInit bytes.Buffer
			bufs, ws := fragmentWriters(tc.nOut)
			err := s.SignFragmented(tc.ctx, bytes.NewReader(tc.init), tc.frags, &outInit, ws, tc.m)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if outInit.Len() != 0 {
				t.Errorf("wrote %d bytes of initialization segment on error", outInit.Len())
			}
			for i, b := range bufs {
				if b.Len() != 0 {
					t.Errorf("wrote %d bytes of fragment %d on error", b.Len(), i)
				}
			}
		})
	}
	if err := s.SignFragmented(ctx, nil, fragmentSeekers(frags), &bytes.Buffer{}, make([]io.Writer, 2), good); !errors.Is(err, ErrNoInput) {
		t.Errorf("nil init: %v", err)
	}
	if err := s.SignFragmented(ctx, bytes.NewReader(init), fragmentSeekers(frags), nil, make([]io.Writer, 2), good); !errors.Is(err, ErrNoInput) {
		t.Errorf("nil init writer: %v", err)
	}
	if err := s.SignFragmented(ctx, bytes.NewReader(init), fragmentSeekers(frags), &bytes.Buffer{}, []io.Writer{&bytes.Buffer{}, nil}, good); !errors.Is(err, ErrNoInput) {
		t.Errorf("nil fragment writer: %v", err)
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestSignFragmentedForeignBoxesKept(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags := unsignedFragmentedSet(2, fragOpts{sidxVersion: 0, emsg: true})
	foreign := synthBox("uuid", bytes.Repeat([]byte{0xAB}, 16), []byte("someone else's box"))
	for i := range frags {
		moof := topBox(frags[i], "moof")
		frags[i] = append(append(append([]byte(nil), frags[i][:moof.start]...), foreign...), frags[i][moof.start:]...)
	}
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("f"))
	expectFragmentedMatch(t, validateSet(t, sc, sInit, sFrags), 2)
	for i, f := range sFrags {
		if !bytes.Contains(f, []byte("someone else's box")) || topBox(f, "emsg") == nil {
			t.Errorf("fragment %d lost a foreign box", i)
		}
	}
}

func TestSignFragmentedTimestamp(t *testing.T) {
	ta := liveTSA(t)
	srv := newTSAServer(t, ta, nil)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	init, frags := unsignedFragmentedSet(2, fragOpts{sidxVersion: 0})
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("ts"))
	res := validateSet(t, sc, sInit, sFrags, WithTimestampTrust(ta.pool()))
	expectFragmentedMatch(t, res, 2)
	if !res.Has(StatusTimeStampValidated) || res.SignedAt.IsZero() {
		t.Fatalf("no validated timestamp: %v", codes(res))
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer broken.Close()
	s2, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority(broken.URL))
	if err != nil {
		t.Fatal(err)
	}
	var outInit bytes.Buffer
	bufs, ws := fragmentWriters(2)
	if err := s2.SignFragmented(context.Background(), bytes.NewReader(init), fragmentSeekers(frags), &outInit, ws, createdManifest("ts")); !errors.Is(err, ErrTimestamp) || outInit.Len() != 0 || bufs[1].Len() != 0 {
		t.Fatalf("TSA failure: %v, %d/%d bytes written", err, outInit.Len(), bufs[1].Len())
	}
}

// tracingSeeker records how often a fragment is opened and how many are live at once.
type tracingSeeker struct {
	*bytes.Reader
	opens int
	live  *int
	peak  *int
	open  bool
}

func (s *tracingSeeker) Seek(off int64, whence int) (int64, error) {
	s.opens++
	if !s.open {
		s.open = true
		*s.live++
		*s.peak = max(*s.peak, *s.live)
	}
	return s.Reader.Seek(off, whence)
}

func (s *tracingSeeker) Read(p []byte) (int, error) {
	n, err := s.Reader.Read(p)
	if err == io.EOF && s.open {
		s.open = false
		*s.live--
	}
	return n, err
}

func TestSignFragmentedOneAtATime(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags := unsignedFragmentedSet(4, fragOpts{sidxVersion: 0})
	live, peak := 0, 0
	seekers := make([]io.ReadSeeker, len(frags))
	traced := make([]*tracingSeeker, len(frags))
	for i, f := range frags {
		traced[i] = &tracingSeeker{Reader: bytes.NewReader(f), live: &live, peak: &peak}
		seekers[i] = traced[i]
	}
	var outInit bytes.Buffer
	bufs, ws := fragmentWriters(4)
	if err := s.SignFragmented(context.Background(), bytes.NewReader(init), seekers, &outInit, ws, createdManifest("one")); err != nil {
		t.Fatal(err)
	}
	for i, tr := range traced {
		if tr.opens != 3 {
			t.Errorf("fragment %d opened %d times, want 3 (hash, self-check, write)", i, tr.opens)
		}
	}
	if peak != 1 {
		t.Errorf("%d fragments were live at once, want 1", peak)
	}
	out := make([][]byte, 4)
	for i, b := range bufs {
		out[i] = b.Bytes()
	}
	expectFragmentedMatch(t, validateSet(t, sc, outInit.Bytes(), out), 4)
}

// TestSignFragmentedBunny signs the real DASH rendition: our verifier accepts
// it in full, every sidx now points at its moved moof, Sign on the lone init is
// still a legal flat-hash signing, and Sign on a fragment still refuses.
func TestSignFragmentedBunny(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags, _ := bunnySet(t)
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("Big Buck Bunny"))
	expectFragmentedMatch(t, validateSet(t, sc, sInit, sFrags), 11)
	for i, f := range sFrags {
		sidx := topBox(f, "sidx")
		first, end := sidxFirstOffset(f, sidx)
		if moof := topBox(f, "moof"); end+int(first) != moof.start {
			t.Errorf("fragment %d: sidx points at %d, moof at %d", i, end+int(first), moof.start)
		}
		if got, want := sidxReferencedSize(f, sidx), sidxReferencedSize(frags[i], topBox(frags[i], "sidx")); got != want {
			t.Errorf("fragment %d: referenced_size %d, want %d", i, got, want)
		}
	}
	var out bytes.Buffer
	if err := s.Sign(context.Background(), BMFF, bytes.NewReader(init), &out, createdManifest("lone init")); err != nil {
		t.Errorf("Sign on a lone initialization segment is legal (flat hash): %v", err)
	}
	out.Reset()
	if err := s.Sign(context.Background(), BMFF, bytes.NewReader(frags[0]), &out, createdManifest("frag")); !errors.Is(err, ErrFragmentedBMFF) || out.Len() != 0 {
		t.Errorf("Sign on a fragment: %v (%d bytes)", err, out.Len())
	}
	if err := s.Sign(context.Background(), BMFF, bytes.NewReader(fragmentedFlatAsset(t, 2, 1, 1, 1, nil).asset), &out, createdManifest("flat")); !errors.Is(err, ErrFragmentedBMFF) {
		t.Errorf("Sign on a flat fragmented file: %v", err)
	}
}
