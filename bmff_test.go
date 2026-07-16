package c2pa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"os"
	"testing"

	cose "github.com/veraison/go-cose"
)

// --- synthetic BMFF builders -------------------------------------------------

// synthBox builds a box with a 32-bit size header.
func synthBox(typ string, payload ...[]byte) []byte {
	var body []byte
	for _, p := range payload {
		body = append(body, p...)
	}
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(8+len(body)))
	copy(out[4:8], typ)
	return append(out, body...)
}

// synthJUMB builds a minimal plausible JUMBF superbox with the given payload.
func synthJUMB(payload []byte) []byte {
	return synthBox("jumb", payload)
}

// synthC2PABox builds a C2PA uuid box: FullBox version/flags, NUL-terminated
// purpose, 8-byte merkle offset (for non-merkle purposes), the JUMBF store,
// and optional zero padding.
func synthC2PABox(purpose string, jumbf []byte, padding int) []byte {
	var body []byte
	body = append(body, c2paBoxUUID[:]...)
	body = append(body, 0, 0, 0, 0) // FullBox version + flags
	body = append(body, purpose...)
	body = append(body, 0)
	if purpose != "merkle" {
		body = append(body, make([]byte, 8)...) // merkle offset = 0
	}
	body = append(body, jumbf...)
	body = append(body, make([]byte, padding)...)
	return synthBox("uuid", body)
}

// --- parser ------------------------------------------------------------------

func TestParseBMFFBoxes(t *testing.T) {
	stco := synthBox("stco", []byte{9, 9})
	stbl := synthBox("stbl", stco)
	minf := synthBox("minf", stbl)
	mdia := synthBox("mdia", minf)
	trak := synthBox("trak", mdia)
	moov := synthBox("moov", trak)
	metaChild := synthBox("iloc", []byte{1, 2, 3})
	meta := synthBox("meta", []byte{0, 0, 0, 0}, metaChild) // FullBox container
	ftyp := synthBox("ftyp", []byte("isom"), []byte{0, 0, 0, 1})
	mdat := synthBox("mdat", bytes.Repeat([]byte{0xAB}, 32))
	file := bytes.Join([][]byte{ftyp, moov, meta, mdat}, nil)

	top := parseBMFFBoxes(context.Background(), file)
	if len(top) != 4 {
		t.Fatalf("top-level boxes = %d, want 4", len(top))
	}
	if top[0].typ != "ftyp" || top[0].start != 0 || top[0].end != len(ftyp) {
		t.Fatalf("ftyp box wrong: %+v", top[0])
	}
	// Deep descent through pure containers.
	got := matchBMFFXPath(top, "/moov/trak/mdia/minf/stbl/stco")
	if len(got) != 1 || got[0].typ != "stco" {
		t.Fatalf("stco not found via xpath: %v", got)
	}
	// FullBox container: children offset +4.
	if got := matchBMFFXPath(top, "/meta/iloc"); len(got) != 1 {
		t.Fatalf("meta/iloc not found (FullBox descent broken)")
	}
	// mdat is a leaf.
	if top[3].typ != "mdat" || top[3].children != nil {
		t.Fatalf("mdat should be a childless leaf: %+v", top[3])
	}
}

func TestParseBMFFBoxes_LargesizeAndToEOF(t *testing.T) {
	// largesize box: size==1, 64-bit size follows.
	payload := []byte("hello")
	large := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint32(large[:4], 1)
	copy(large[4:8], "skip")
	binary.BigEndian.PutUint64(large[8:16], uint64(16+len(payload)))
	copy(large[16:], payload)
	// size==0 box extends to EOF.
	toEOF := make([]byte, 8+3)
	binary.BigEndian.PutUint32(toEOF[:4], 0)
	copy(toEOF[4:8], "mdat")

	file := append(append([]byte{}, large...), toEOF...)
	top := parseBMFFBoxes(context.Background(), file)
	if len(top) != 2 {
		t.Fatalf("boxes = %d, want 2", len(top))
	}
	if top[0].headerLen != 16 || top[0].end != len(large) {
		t.Fatalf("largesize box wrong: %+v", top[0])
	}
	if top[1].end != len(file) {
		t.Fatalf("size==0 box should extend to EOF: %+v", top[1])
	}
}

func TestParseBMFFBoxes_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":          {},
		"short":          {0, 0},
		"size too small": {0, 0, 0, 4, 'f', 't', 'y', 'p'},
		"size too big":   {0xFF, 0xFF, 0xFF, 0xFF, 'f', 't', 'y', 'p'},
		"largesize trunc": {0, 0, 0, 1, 'f', 't', 'y', 'p', 0xFF},
	}
	for name, data := range cases {
		if boxes := parseBMFFBoxes(context.Background(), data); len(boxes) != 0 {
			t.Errorf("%s: parsed %d boxes from malformed input", name, len(boxes))
		}
	}
}

// --- manifest extraction -----------------------------------------------------

func TestBMFFJUMBF(t *testing.T) {
	jumbf := synthJUMB([]byte("payload"))
	ftyp := synthBox("ftyp", []byte("isom"))

	t.Run("manifest purpose preferred", func(t *testing.T) {
		file := bytes.Join([][]byte{
			ftyp,
			synthC2PABox("update", synthJUMB([]byte("update!")), 0),
			synthC2PABox("manifest", jumbf, 0),
		}, nil)
		got := bmffJUMBF(context.Background(), file)
		if !bytes.Equal(got, jumbf) {
			t.Fatalf("did not prefer manifest purpose: got %q", got)
		}
	})
	t.Run("zero padding trimmed", func(t *testing.T) {
		file := bytes.Join([][]byte{ftyp, synthC2PABox("manifest", jumbf, 64)}, nil)
		got := bmffJUMBF(context.Background(), file)
		if !bytes.Equal(got, jumbf) {
			t.Fatalf("padding not trimmed: got %d bytes, want %d", len(got), len(jumbf))
		}
	})
	t.Run("no merkle-offset field fallback", func(t *testing.T) {
		// Hand-build a C2PA box WITHOUT the 8-byte merkle offset.
		var body []byte
		body = append(body, c2paBoxUUID[:]...)
		body = append(body, 0, 0, 0, 0)
		body = append(body, "manifest"...)
		body = append(body, 0)
		body = append(body, jumbf...)
		file := bytes.Join([][]byte{ftyp, synthBox("uuid", body)}, nil)
		got := bmffJUMBF(context.Background(), file)
		if !bytes.Equal(got, jumbf) {
			t.Fatalf("fallback without merkle offset failed: got %q", got)
		}
	})
	t.Run("foreign uuid ignored", func(t *testing.T) {
		var body []byte
		body = append(body, bytes.Repeat([]byte{0x42}, 16)...) // wrong usertype
		body = append(body, jumbf...)
		file := bytes.Join([][]byte{ftyp, synthBox("uuid", body)}, nil)
		if got := bmffJUMBF(context.Background(), file); got != nil {
			t.Fatalf("foreign uuid box should not yield a manifest")
		}
	})
	t.Run("update detection", func(t *testing.T) {
		file := bytes.Join([][]byte{ftyp, synthC2PABox("update", jumbf, 0)}, nil)
		if !bmffHasUpdateManifest(context.Background(), file) {
			t.Fatal("update manifest not detected")
		}
		if bmffHasUpdateManifest(context.Background(), ftyp) {
			t.Fatal("false positive update detection")
		}
	})
}

// --- xpath matching + predicates ----------------------------------------------

func TestMatchBMFFXPath(t *testing.T) {
	trak1 := synthBox("trak", synthBox("mdia", []byte{1}))
	trak2 := synthBox("trak", synthBox("mdia", []byte{2}))
	moov := synthBox("moov", trak1, trak2)
	top := parseBMFFBoxes(context.Background(), moov)

	if got := matchBMFFXPath(top, "/moov/trak"); len(got) != 2 {
		t.Fatalf("unindexed segment should match all siblings, got %d", len(got))
	}
	if got := matchBMFFXPath(top, "/moov/trak[2]/mdia"); len(got) != 1 {
		t.Fatalf("indexed segment should match one, got %d", len(got))
	}
	if got := matchBMFFXPath(top, "/moov/trak[3]"); len(got) != 0 {
		t.Fatalf("out-of-range index matched %d boxes", len(got))
	}
	if got := matchBMFFXPath(top, "moov/trak"); got != nil {
		t.Fatal("xpath without leading slash should match nothing")
	}
	if got := matchBMFFXPath(top, "/moov/nope"); len(got) != 0 {
		t.Fatal("nonexistent type matched")
	}
}

func TestBMFFExclusionPredicates(t *testing.T) {
	// A FullBox-ish leaf: version 1, flags 00 00 07, then payload.
	payload := []byte{1, 0x00, 0x00, 0x07, 0xAA, 0xBB}
	b := synthBox("tfhd", payload)
	top := parseBMFFBoxes(context.Background(), b)
	box := top[0]

	base := bmffExclusion{xpath: "/tfhd", length: -1, version: -1, exact: true}

	t.Run("length", func(t *testing.T) {
		e := base
		e.length = len(b)
		if !bmffExclusionApplies(b, box, e) {
			t.Fatal("exact length should apply")
		}
		e.length = len(b) - 1
		if bmffExclusionApplies(b, box, e) {
			t.Fatal("wrong length should not apply")
		}
	})
	t.Run("data", func(t *testing.T) {
		e := base
		e.data = []bmffDataMatch{{offset: 8, value: []byte{1, 0x00}}}
		if !bmffExclusionApplies(b, box, e) {
			t.Fatal("matching data predicate should apply")
		}
		e.data = []bmffDataMatch{{offset: 8, value: []byte{9}}}
		if bmffExclusionApplies(b, box, e) {
			t.Fatal("mismatching data predicate should not apply")
		}
		e.data = []bmffDataMatch{{offset: 1 << 20, value: []byte{1}}}
		if bmffExclusionApplies(b, box, e) {
			t.Fatal("out-of-bounds data predicate should not apply")
		}
	})
	t.Run("version", func(t *testing.T) {
		e := base
		e.version = 1
		if !bmffExclusionApplies(b, box, e) {
			t.Fatal("matching version should apply")
		}
		e.version = 0
		if bmffExclusionApplies(b, box, e) {
			t.Fatal("mismatching version should not apply")
		}
	})
	t.Run("flags exact", func(t *testing.T) {
		e := base
		e.flags = []byte{0x00, 0x00, 0x07}
		if !bmffExclusionApplies(b, box, e) {
			t.Fatal("equal flags with exact=true should apply")
		}
		e.flags = []byte{0x00, 0x00, 0x01}
		if bmffExclusionApplies(b, box, e) {
			t.Fatal("unequal flags with exact=true should not apply")
		}
	})
	t.Run("flags bits-set", func(t *testing.T) {
		// exact=false: the box must have at least the assertion's bits set —
		// (file & want) == want per the spec. (c2pa-rs implements the inverse
		// subset test; the spec semantics are deliberate here.)
		e := base
		e.exact = false
		e.flags = []byte{0x00, 0x00, 0x01} // subset of 0x07
		if !bmffExclusionApplies(b, box, e) {
			t.Fatal("subset flags with exact=false should apply")
		}
		e.flags = []byte{0x00, 0x00, 0x08} // bit not in 0x07
		if bmffExclusionApplies(b, box, e) {
			t.Fatal("non-subset flags with exact=false should not apply")
		}
	})
}

// --- hashing ------------------------------------------------------------------

func TestHashBMFFTopLevel(t *testing.T) {
	ftyp := synthBox("ftyp", []byte("isom"))
	mdat := synthBox("mdat", bytes.Repeat([]byte{0xCD}, 40))
	uuid := synthC2PABox("manifest", synthJUMB([]byte("x")), 0)
	file := bytes.Join([][]byte{ftyp, mdat, uuid}, nil)
	top := parseBMFFBoxes(context.Background(), file)

	excl := []bmffExclusion{
		{xpath: "/ftyp", length: -1, version: -1, exact: true},
		{xpath: "/uuid", length: -1, version: -1, exact: true,
			data: []bmffDataMatch{{offset: 8, value: c2paBoxUUID[:]}}},
	}
	ranges, ok := bmffExclusionByteRanges(file, top, excl)
	if !ok {
		t.Fatal("exclusion resolution failed")
	}

	h := sha256.New()
	hashBMFFTopLevel(context.Background(), file, top, ranges, h)
	got := h.Sum(nil)

	// Independently: only mdat contributes — 8-byte BE offset then its bytes.
	want := sha256.New()
	var off [8]byte
	binary.BigEndian.PutUint64(off[:], uint64(len(ftyp)))
	want.Write(off[:])
	want.Write(mdat)

	if !bytes.Equal(got, want.Sum(nil)) {
		t.Fatal("hash does not match hand-computed digest")
	}
}

func TestHashBMFFTopLevel_Subset(t *testing.T) {
	mdat := synthBox("mdat", bytes.Repeat([]byte{0xEE}, 40))
	file := mdat
	top := parseBMFFBoxes(context.Background(), file)

	// Exclude everything after the first 16 bytes of mdat (the spec's
	// mdat-with-merkle pattern: subset {offset:16, length:0} = to box end).
	excl := []bmffExclusion{
		{xpath: "/mdat", length: -1, version: -1, exact: true,
			subset: []bmffSubsetRange{{offset: 16, length: 0}}},
	}
	ranges, ok := bmffExclusionByteRanges(file, top, excl)
	if !ok {
		t.Fatal("exclusion resolution failed")
	}
	h := sha256.New()
	hashBMFFTopLevel(context.Background(), file, top, ranges, h)

	want := sha256.New()
	var off [8]byte
	want.Write(off[:]) // offset 0
	want.Write(file[:16])

	if !bytes.Equal(h.Sum(nil), want.Sum(nil)) {
		t.Fatal("subset-excluded hash does not match hand-computed digest")
	}
}

// --- fixture integration -------------------------------------------------------

// videoFixturePools anchors signing and TSA trust at the video fixture's own
// chains (both manifests'), mirroring fixtureSigningPool for the JPEG fixture.
func videoFixturePools(t *testing.T) (signing, tsa *x509.CertPool, data []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/c2pa_signed_video.mp4")
	if err != nil {
		t.Fatal(err)
	}
	jumbf := extractJUMBF(context.Background(), BMFF, data)
	store := parseStore(context.Background(), jumbf)
	if len(store.manifests) == 0 {
		t.Fatal("fixture has no manifests")
	}
	signing, tsa = x509.NewCertPool(), x509.NewCertPool()
	for _, m := range store.manifests {
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(m.signature); err != nil {
			t.Fatalf("decode COSE: %v", err)
		}
		chain := parseChain(msg.Headers.Unprotected["x5chain"])
		if len(chain) == 0 {
			chain = parseChain(msg.Headers.Protected[cose.HeaderLabelX5Chain])
		}
		if len(chain) == 0 {
			t.Fatal("fixture manifest has no x5chain")
		}
		signing.AddCert(chain[len(chain)-1])
		if der, ok := extractTSToken(msg.Headers.Unprotected); ok {
			if sd, ok := parseCMSSignedData(der); ok {
				subjects := map[string]bool{}
				for _, c := range sd.certs {
					subjects[string(c.RawSubject)] = true
				}
				for _, c := range sd.certs {
					if !subjects[string(c.RawIssuer)] || string(c.RawIssuer) == string(c.RawSubject) {
						tsa.AddCert(c)
					}
				}
			}
		}
	}
	return signing, tsa, data
}

func TestRead_SignedMP4(t *testing.T) {
	data, err := os.ReadFile("testdata/c2pa_signed_video.mp4")
	if err != nil {
		t.Fatal(err)
	}
	info := Read(context.Background(), BMFF, bytes.NewReader(data))
	if !info.Present {
		t.Fatal("manifest not found")
	}
	if info.Format != "video/mp4" {
		t.Errorf("Format = %q, want video/mp4", info.Format)
	}
	if info.ClaimGenerator == "" {
		t.Error("ClaimGenerator empty")
	}
}

func TestValidate_SignedMP4_BMFFHashMatches(t *testing.T) {
	signing, tsa, data := videoFixturePools(t)
	r := Validate(context.Background(), BMFF, bytes.NewReader(data),
		WithSigningTrust(signing), WithTimestampTrust(tsa))
	if !r.Has(StatusAssertionBMFFHashMatch) {
		t.Fatalf("no bmffHash.match; statuses: %v", codes(r))
	}
	if !r.Has(StatusClaimSignatureValidated) {
		t.Fatalf("claim signature not validated; statuses: %v", codes(r))
	}
	if r.Has(StatusAssertionBMFFHashMismatch) {
		t.Fatalf("unexpected bmffHash.mismatch; statuses: %v", codes(r))
	}
}

func TestValidate_SignedMP4_TamperedMdat(t *testing.T) {
	signing, tsa, data := videoFixturePools(t)
	i := bytes.Index(data, []byte("mdat"))
	if i < 0 {
		t.Fatal("no mdat box in fixture")
	}
	tampered := append([]byte(nil), data...)
	tampered[i+5000] ^= 0xFF // well inside the mdat payload
	r := Validate(context.Background(), BMFF, bytes.NewReader(tampered),
		WithSigningTrust(signing), WithTimestampTrust(tsa))
	if !r.Has(StatusAssertionBMFFHashMismatch) {
		t.Fatalf("tampered mdat not detected; statuses: %v", codes(r))
	}
	if r.Valid {
		t.Fatal("tampered asset reported valid")
	}
}

func TestValidate_MP4_NoManifest(t *testing.T) {
	data, err := os.ReadFile("testdata/video_no_manifest.mp4")
	if err != nil {
		t.Fatal(err)
	}
	r := Validate(context.Background(), BMFF, bytes.NewReader(data))
	if !r.Has(StatusClaimMissing) {
		t.Fatalf("expected claim.missing; statuses: %v", codes(r))
	}
	if r.Valid {
		t.Fatal("manifest-less asset reported valid")
	}
}

func TestValidate_LegacyBMFFv1_Ignored(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy_bmff_v1.mp4")
	if err != nil {
		t.Fatal(err)
	}
	r := Validate(context.Background(), BMFF, bytes.NewReader(data))
	// The active manifest's only hard binding is a v1 c2pa.hash.bmff, which
	// validators must ignore — leaving no usable hard binding.
	if !r.Has(StatusHardBindingMissing) {
		t.Fatalf("expected hardBinding.missing for v1-only manifest; statuses: %v", codes(r))
	}
	if r.Valid {
		t.Fatal("v1-only manifest reported valid")
	}
}

func TestVerifyHardBinding_BMFFAssertionOnJPEG(t *testing.T) {
	v := &validator{ctx: context.Background(), cfg: defaultConfig(), container: JPEG, data: []byte("not bmff")}
	m := &parsedManifest{assertions: []rawAssertion{{label: "c2pa.hash.bmff.v2"}}}
	v.verifyHardBinding(m, "test")
	if !v.res.Has(StatusHardBindingMissing) {
		t.Fatalf("BMFF binding on a JPEG must be hardBinding.missing; statuses: %v", codes(v.res))
	}
}
