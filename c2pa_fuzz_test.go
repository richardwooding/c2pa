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
// marker-segment reassembly) / pngJUMBF (caBX chunk concatenation) → WalkBoxes
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
	// The real signed fixture — gives the mutator a valid manifest (claim +
	// actions + COSE signature + RFC 3161 timestamp) to corrupt from.
	if b, err := os.ReadFile("testdata/c2pa_signed.jpg"); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Read(context.Background(), JPEG, bytes.NewReader(data))
		_ = Read(context.Background(), PNG, bytes.NewReader(data))
		_ = Read(context.Background(), BMFF, bytes.NewReader(data))
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
		0x00,                                        // toggles (no label)
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
		0x00,                                            // toggles (no label)
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
		_ = Validate(context.Background(), JPEG, bytes.NewReader(data))
		_ = Validate(context.Background(), PNG, bytes.NewReader(data))
		_ = Validate(context.Background(), BMFF, bytes.NewReader(data))
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
