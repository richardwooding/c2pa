package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	cose "github.com/veraison/go-cose"
)

// FuzzRead targets the full extraction pipeline: jpegJUMBF (APP11
// marker-segment reassembly) / pngJUMBF (caBX chunk concatenation) /
// pdfJUMBF (indirect-object scan → embedded file stream) → WalkBoxes
// (recursive LBox/TBox box tree) → parseManifest (CBOR claim/actions decode) →
// signerIdentity (COSE_Sign1 → x509) → rfc3161GenTime (ASN.1 timestamp). Every
// stage walks attacker-controlled bytes pulled from arbitrary files.
//
// Contract: never panic, never loop forever. We don't assert on outputs —
// corrupt input legitimately yields a zero Info (Present=false).
func FuzzRead(f *testing.F) {
	f.Add([]byte{})
	// JPEG SOI + a minimal APP11 "JP" packet (CI+En+Z headers, Z=1) wrapping
	// one empty `jumb` box — exercises jpegJUMBF reassembly + the walker.
	f.Add([]byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xEB, 0x00, 0x12, // APP11, length 18
		0x4A, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // "JP" + En + Z=1
		0x00, 0x00, 0x00, 0x08, 'j', 'u', 'm', 'b', // empty jumb box
	})
	// PNG signature + an empty `caBX` chunk — exercises pngJUMBF.
	f.Add([]byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x00, 'c', 'a', 'B', 'X', // len 0, type caBX
		0x00, 0x00, 0x00, 0x00, // crc
	})
	// A minimal PDF: header, catalog /AF, C2PA file specification, and an
	// embedded file stream holding one empty `jumb` box.
	f.Add([]byte("%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog /AF [3 0 R] >>\nendobj\n" +
		"3 0 obj\n<< /AFRelationship /C2PA_Manifest /EF << /F 4 0 R >> >>\nendobj\n" +
		"4 0 obj\n<< /Length 8 >>\nstream\n\x00\x00\x00\x08jumb\nendstream\nendobj\n" +
		"trailer\n<< /Root 1 0 R >>\n%%EOF\n"))
	// The real signed fixture — gives the mutator a valid manifest (claim +
	// actions + COSE signature + RFC 3161 timestamp) to corrupt from.
	if b, err := os.ReadFile("testdata/c2pa_signed.jpg"); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range []Container{JPEG, PNG, BMFF, RIFF, TIFF, GIF, MP3, SVG, PDF} {
			_ = Read(context.Background(), c, bytes.NewReader(data))
		}
	})
}

// FuzzWalkBoxes targets the recursive JUMBF box-tree walker and jumdLabel
// directly. Boxes are length-prefixed (LBox) and `jumb` superboxes nest, so
// this is the classic spot for integer-overflow on the length field and stack
// growth on adversarial nesting — the latter guarded by maxJUMBFDepth.
//
// Contract: never panic, never loop forever.
func FuzzWalkBoxes(f *testing.F) {
	f.Add([]byte{})
	// A `jumb` superbox holding a valid `jumd` description box (16-byte type
	// UUID + 1 toggle byte, no label) plus one empty `cbor` child.
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x2A, 'j', 'u', 'm', 'b', // jumb, lbox 42
		0x00, 0x00, 0x00, 0x19, 'j', 'u', 'm', 'd', // jumd, lbox 25
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // type UUID
		0x00,                                             // toggles (no label)
		0x00, 0x00, 0x00, 0x09, 'c', 'b', 'o', 'r', 0xA0, // cbor child {}
	})
	// LBox claiming far more than the buffer holds — must bail, not index OOB.
	f.Add([]byte{0x00, 0x00, 0xFF, 0xFF, 'j', 'u', 'm', 'b'})
	// Self-nesting `jumb` chain (no valid jumd at any level) — exercises the
	// depth guard rather than recursing per stripped header.
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x18, 'j', 'u', 'm', 'b', // lbox 24
		0x00, 0x00, 0x00, 0x10, 'j', 'u', 'm', 'b', // lbox 16
		0x00, 0x00, 0x00, 0x08, 'j', 'u', 'm', 'b', // lbox 8 (empty)
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		WalkBoxes(context.Background(), data, func(string, string, []byte) {})
	})
}

// FuzzWalkBoxesRanges targets the offset-aware box-tree builder (parseBoxTree)
// and the manifest-store resolver (parseStore). Unlike WalkBoxes it threads
// absolute offsets through recursion and slices the original buffer by them, so
// it is the new spot for off-by-one / out-of-range arithmetic on adversarial
// LBox fields and nesting.
//
// Contract: never panic, never loop forever.
func FuzzWalkBoxesRanges(f *testing.F) {
	f.Add([]byte{})
	// A `jumb` superbox holding a valid `jumd` description box plus one empty
	// `cbor` child — the minimal shape parseStore navigates.
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x2A, 'j', 'u', 'm', 'b', // jumb, lbox 42
		0x00, 0x00, 0x00, 0x19, 'j', 'u', 'm', 'd', // jumd, lbox 25
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // type UUID
		0x00,                                             // toggles (no label)
		0x00, 0x00, 0x00, 0x09, 'c', 'b', 'o', 'r', 0xA0, // cbor child {}
	})
	// LBox larger than the buffer — must bail without indexing OOB.
	f.Add([]byte{0x00, 0x00, 0xFF, 0xFF, 'j', 'u', 'm', 'b'})
	if b, err := os.ReadFile("testdata/c2pa_signed.jpg"); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = parseBoxTree(context.Background(), data)
		_ = parseStore(context.Background(), data)
	})
}

// FuzzValidate targets the full validation pipeline over arbitrary bytes.
// Online revocation is off by default, keeping the run hermetic (no network).
//
// Contract: never panic, never loop forever; garbage yields Valid=false.
func FuzzValidate(f *testing.F) {
	f.Add([]byte{})
	if b, err := os.ReadFile("testdata/c2pa_signed.jpg"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range []Container{JPEG, PNG, BMFF, RIFF, TIFF, GIF, MP3, SVG, PDF} {
			_ = Validate(context.Background(), c, bytes.NewReader(data))
		}
	})
}

// FuzzVerifyDataHash targets the c2pa.hash.data exclusion-range arithmetic:
// validating attacker-controlled {start,length} ranges against the asset length
// and hashing across the gaps. This is the classic spot for integer overflow,
// overlapping/out-of-order ranges, and out-of-bounds slice panics.
//
// Contract: never panic. Ranges deemed valid must produce a sound hash walk.
func FuzzVerifyDataHash(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0}, 64)
	f.Add([]byte{0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0xCA, 0x59}, 166864)
	f.Fuzz(func(t *testing.T, raw []byte, n int) {
		if n < 0 || n > 1<<20 {
			return
		}
		data := make([]byte, n)
		var list []any
		for i := 0; i+8 <= len(raw); i += 8 {
			start := int64(binary.BigEndian.Uint32(raw[i : i+4]))
			length := int64(binary.BigEndian.Uint32(raw[i+4 : i+8]))
			list = append(list, map[string]any{"start": start, "length": length})
		}
		ranges, ok := exclusionRanges(list, len(data))
		if !ok {
			return
		}
		h := sha256.New()
		hashWithExclusions(data, h, ranges)
		_ = h.Sum(nil)
	})
}

// FuzzVerifyTimestamp targets the CMS SignedData descent that verifies an
// RFC 3161 timestamp token: parsing the SignedData, TSTInfo, and SignerInfo,
// finding the signer, and checking the signed attributes — all over
// attacker-controlled DER. This is where the extended ASN.1 descent (beyond
// rfc3161GenTime's genTime-only walk) must stay panic-free.
//
// Contract: never panic, never loop forever.
func FuzzVerifyTimestamp(f *testing.F) {
	f.Add([]byte{})
	// Seed with the real token extracted from the fixture.
	if b, err := os.ReadFile("testdata/c2pa_signed.jpg"); err == nil {
		jumbf := extractJUMBF(context.Background(), JPEG, b)
		if m := parseStore(context.Background(), jumbf).active(); m != nil {
			var msg cose.Sign1Message
			if msg.UnmarshalCBOR(m.signature) == nil {
				if der, _ := extractTSToken(msg.Headers.Unprotected); len(der) > 0 {
					f.Add(der)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		sd, ok := parseCMSSignedData(data)
		if !ok {
			return
		}
		_, _ = parseTSTInfo(sd.eContent)
		si, ok := parseSignerInfo(sd.signerInfos)
		if !ok {
			return
		}
		_ = findSigner(sd.certs, si)
		_, _ = checkSignedAttrs(si.signedAttrs.Bytes, crypto.SHA256, sd.eContent)
	})
}

// FuzzRFC3161GenTime targets the hand-rolled ASN.1 descent that walks an
// RFC 3161 timestamp (TimeStampResp → CMS SignedData → TSTInfo) down to
// genTime. Nested encoding/asn1.Unmarshal calls over attacker bytes.
//
// Contract: never panic, never loop forever; any structural surprise yields
// the zero time.
func FuzzRFC3161GenTime(f *testing.F) {
	f.Add([]byte{})
	// SEQUENCE { INTEGER 0 } — a PKIStatusInfo-shaped prefix with no token.
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	// A bare GeneralizedTime TLV ("20240806215337Z") — not a ContentInfo.
	f.Add([]byte{
		0x18, 0x0F,
		'2', '0', '2', '4', '0', '8', '0', '6', '2', '1', '5', '3', '3', '7', 'Z',
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = rfc3161GenTime(data)
	})
}

// FuzzBMFFParse targets the BMFF box-tree parser and manifest extractor: box
// sizes are attacker-controlled (32-bit, 64-bit largesize, and size==0
// to-EOF), containers nest (guarded by maxBMFFDepth), and the C2PA uuid box
// payload walk crosses several length fields.
//
// Contract: never panic, never loop forever, offsets stay in bounds.
func FuzzBMFFParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 8, 'f', 't', 'y', 'p'})
	f.Add([]byte{0, 0, 0, 1, 'm', 'd', 'a', 't', 0, 0, 0, 0, 0, 0, 0, 16}) // largesize
	f.Add([]byte{0, 0, 0, 0, 'm', 'd', 'a', 't'})                          // to-EOF
	if b, err := os.ReadFile("testdata/c2pa_signed_video.mp4"); err == nil && len(b) > 4096 {
		f.Add(b[:4096]) // header region incl. ftyp; keeps the corpus light
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		boxes := parseBMFFBoxes(ctx, data)
		var walk func([]*bmffBox, int)
		walk = func(bs []*bmffBox, depth int) {
			if depth > maxBMFFDepth+1 {
				t.Fatal("box tree deeper than the depth cap")
			}
			for _, b := range bs {
				if b.start < 0 || b.end > len(data) || b.start+b.headerLen > b.end {
					t.Fatalf("box out of bounds: %+v (len %d)", b, len(data))
				}
				walk(b.children, depth+1)
			}
		}
		walk(boxes, 0)
		_ = bmffJUMBF(ctx, data)
		_ = bmffHasUpdateManifest(ctx, data)
	})
}

// FuzzBMFFHash targets the exclusion decode + xpath match + range resolution +
// offset-marker hashing pipeline with attacker-controlled assertion CBOR and
// asset bytes.
//
// Contract: never panic; resolved ranges are sound inputs to the hash walk.
func FuzzBMFFHash(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(
		[]byte{0, 0, 0, 8, 'f', 't', 'y', 'p', 0, 0, 0, 12, 'm', 'd', 'a', 't', 1, 2, 3, 4},
		[]byte{0x81, 0xA1, 0x65, 'x', 'p', 'a', 't', 'h', 0x65, '/', 'm', 'd', 'a', 't'}, // [{"xpath":"/mdat"}]
	)
	f.Fuzz(func(t *testing.T, asset, exclCBOR []byte) {
		ctx := context.Background()
		var raw any
		_ = decMode.Unmarshal(exclCBOR, &raw)
		excl, ok := decodeBMFFExclusions(raw)
		if !ok {
			return
		}
		top := parseBMFFBoxes(ctx, asset)
		ranges, ok := bmffExclusionByteRanges(asset, top, excl)
		if !ok {
			return
		}
		h := sha256.New()
		hashBMFFTopLevel(ctx, asset, top, ranges, h)
		_ = h.Sum(nil)
	})
}

// FuzzPDFParse targets the PDF object scan and the embedded-file walk: object
// headers, dictionary lookups, indirect references, the /Length field against
// the `endstream` keyword, and the bounded inflation of a /FlateDecode stream.
//
// Contract: never panic, never loop forever; anything returned is a JUMBF
// superbox exactly as long as its own LBox says.
func FuzzPDFParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("%PDF-1.7\n"))
	// Catalog → file specification → embedded file stream, the §A.4 chain.
	f.Add([]byte("%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog /AF [3 0 R] >>\nendobj\n" +
		"3 0 obj\n<< /AFRelationship /C2PA_Manifest /EF << /F 4 0 R >> >>\nendobj\n" +
		"4 0 obj\n<< /Length 8 >>\nstream\n\x00\x00\x00\x08jumb\nendstream\nendobj\n" +
		"trailer\n<< /Root 1 0 R >>\n%%EOF\n"))
	// A /Length that runs past the object, and an /AF that points at itself.
	f.Add([]byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /AF [1 0 R] " +
		"/AFRelationship /C2PA_Manifest /Length 4294967295 >>\nstream\n\x00\x00\x00\x08jumb"))
	f.Fuzz(func(t *testing.T, data []byte) {
		store := pdfJUMBF(context.Background(), data)
		if store == nil {
			return
		}
		if len(store) < 8 || string(store[4:8]) != "jumb" {
			t.Fatalf("returned %d bytes that are not a jumb superbox", len(store))
		}
		if ln := binary.BigEndian.Uint32(store[:4]); int(ln) != len(store) {
			t.Fatalf("returned %d bytes for an LBox of %d", len(store), ln)
		}
	})
}

// FuzzBoxMap targets the JPEG/PNG/GIF box-map walkers with adversarial
// container bytes. Every box a walker reports is a range something else will
// hash, so a walker that runs off the end or emits an inverted range would turn
// a malformed asset into a panic in the verifier.
//
// Contract: never panic; every box lies inside the data, boxes are ordered and
// non-overlapping, and every permitted exclusion stays inside its own box.
func FuzzBoxMap(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x04, 0x01, 0x01, 0x11, 0xFF, 0xD9})
	f.Add(append(append([]byte{}, pngSignature...),
		0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0x00, 0x00, 0x00, 0x00))
	f.Add(append([]byte("GIF89a"), 1, 0, 1, 0, 0, 0, 0, gifTrailer))
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		for _, c := range []Container{JPEG, PNG, GIF} {
			boxes, ok := assetBoxMap(ctx, c, data)
			if !ok {
				t.Fatalf("%s should have a box map", c)
			}
			pos := 0
			for _, b := range boxes {
				if b.length < 0 || b.start < pos || b.end() > len(data) {
					t.Fatalf("%s: box %+v out of bounds or out of order (len %d, pos %d)",
						c, b, len(data), pos)
				}
				pos = b.end()
				for _, a := range b.allowed {
					if !a.boundedBy(b.length) {
						t.Fatalf("%s: permitted exclusion %+v reaches past box %+v", c, a, b)
					}
				}
			}
		}
	})
}

// FuzzBoxesHash targets the full c2pa.hash.boxes pipeline — assertion decode,
// the lockstep walk against a real box map, exclusion resolution and the
// hashing — with attacker-controlled assertion CBOR and asset bytes.
//
// Contract: never panic, and never report a match for an assertion whose
// exclusions were not resolved.
func FuzzBoxesHash(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(
		append(append([]byte{}, pngSignature...),
			0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0x00, 0x00, 0x00, 0x00),
		// {"boxes":[{"names":["PNGh"],"hash":h'','pad':h''}]}
		[]byte{0xA1, 0x65, 'b', 'o', 'x', 'e', 's', 0x81, 0xA3,
			0x65, 'n', 'a', 'm', 'e', 's', 0x81, 0x64, 'P', 'N', 'G', 'h',
			0x64, 'h', 'a', 's', 'h', 0x40,
			0x63, 'p', 'a', 'd', 0x40},
	)
	f.Fuzz(func(t *testing.T, asset, assertionCBOR []byte) {
		for _, c := range []Container{JPEG, PNG, GIF, PDF} {
			v := &validator{
				ctx:       context.Background(),
				cfg:       validateConfig{maxScan: ValidateMaxScan},
				container: c,
				data:      asset,
			}
			v.verifyBoxesHash(&rawAssertion{label: "c2pa.hash.boxes", data: assertionCBOR},
				"self#jumbf=/c2pa/urn:test", "sha256")
			for _, s := range v.res.Statuses {
				if s.Code == StatusAssertionBoxesHashMatch && len(v.data) == 0 {
					t.Fatalf("%s: reported a match over no asset bytes", c)
				}
			}
		}
	})
}
