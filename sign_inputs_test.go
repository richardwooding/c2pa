package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// signingChain is a freshly minted root + leaf valid around the wall clock.
// The corpus chain is pinned to corpusEpoch and expires in January 2027;
// c2patool evaluates certificate validity against real time, and so does
// NewSigner, so signer tests mint their own.
type signingChain struct {
	key     crypto.Signer
	chain   []*x509.Certificate // leaf, root
	roots   *x509.CertPool
	rootPEM []byte
}

// newSigningChainFor mints a P-256 root and a leaf for key carrying the C2PA
// profile: digitalSignature, emailProtection, not a CA, Organization set so
// c2patool's signature_info.issuer has something to show.
func newSigningChainFor(t testing.TB, key crypto.Signer) signingChain {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "c2pa test root", Organization: []string{"richardwooding/c2pa tests"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "c2pa test signer", Organization: []string{"richardwooding/c2pa tests"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return signingChain{
		key:     key,
		chain:   []*x509.Certificate{leaf, root},
		roots:   roots,
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
	}
}

// newSigningChain is newSigningChainFor with a fresh P-256 key.
func newSigningChain(t testing.TB) signingChain {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newSigningChainFor(t, key)
}

// newTestSigner is the Signer most tests use: a fresh ES256 chain and a named
// claim generator.
func newTestSigner(t testing.TB, opts ...SignerOption) (*Signer, signingChain) {
	t.Helper()
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, append([]SignerOption{WithClaimGenerator("c2pa-sign-test", "1.2")}, opts...)...)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s, sc
}

// createdManifest is the simplest manifest Sign accepts.
func createdManifest(title string) Manifest {
	return Manifest{
		Title:   title,
		Actions: []Action{{Action: ActionCreated, DigitalSourceType: DigitalSourceTypeDigitalCapture}},
	}
}

// openedManifest is what a re-sign uses.
func openedManifest(title string) Manifest {
	return Manifest{Title: title, Actions: []Action{{Action: ActionOpened}}}
}

// signBytes runs Sign in memory and fails the test on error.
func signBytes(t testing.TB, s *Signer, c Container, in []byte, m Manifest) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := s.Sign(context.Background(), c, bytes.NewReader(in), &out, m); err != nil {
		t.Fatalf("Sign(%s): %v", c, err)
	}
	return out.Bytes()
}

// testImage is a 16×16 gradient, enough for every encoder to produce a real
// file with real scan data.
func testImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 16), B: 0x80, A: 0xFF})
		}
	}
	return img
}

// unsignedJPEG is a baseline JPEG from the standard library encoder: SOI,
// APP0-less DQT/SOF/DHT/SOS/EOI — the "no APP0" insertion case.
func unsignedJPEG(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, testImage(), &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// unsignedPNG is a PNG from the standard library encoder.
func unsignedPNG(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// unsignedGIF is a GIF89a from the standard library encoder: header, global
// colour table, one image.
func unsignedGIF(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gif.Encode(&buf, testImage(), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// unsignedWebP is a simple-format WebP: RIFF/WEBP with a lone VP8L chunk whose
// 5-byte header declares a 1×1 opaque image — no VP8X, so the embedder must
// synthesise one.
func unsignedWebP() []byte {
	return riffFile("WEBP", riffChunk("VP8L", []byte{0x2F, 0x00, 0x00, 0x00, 0x00}))
}

// unsignedWAV is a RIFF/WAVE with a 16-byte PCM fmt chunk and four bytes of
// samples.
func unsignedWAV() []byte {
	fmtChunk := []byte{1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x88, 0x58, 0x01, 0, 2, 0, 16, 0}
	return riffFile("WAVE", riffChunk("fmt ", fmtChunk), riffChunk("data", []byte{0, 0, 1, 0}))
}

// unsignedTIFF is a classic TIFF with a real IFD0 — width, length, bits per
// sample, compression, photometric, strip offsets, samples per pixel, rows per
// strip, strip byte counts — and one pixel byte after it.
func unsignedTIFF(bigEndian bool) []byte {
	bo := binary.AppendByteOrder(binary.LittleEndian)
	order := []byte("II")
	if bigEndian {
		bo, order = binary.BigEndian, []byte("MM")
	}
	entries := []struct {
		tag, typ uint16
		value    uint32
	}{
		{256, 3, 1}, {257, 3, 1}, {258, 3, 8}, {259, 3, 1}, {262, 3, 1},
		{273, 4, 0 /* patched below */}, {277, 3, 1}, {278, 3, 1}, {279, 4, 1},
	}
	const ifdAt = 8
	pixelAt := ifdAt + 2 + len(entries)*12 + 4
	out := append([]byte{}, order...)
	out = bo.AppendUint16(out, 42)
	out = bo.AppendUint32(out, ifdAt)
	out = bo.AppendUint16(out, uint16(len(entries)))
	for _, e := range entries {
		out = bo.AppendUint16(out, e.tag)
		out = bo.AppendUint16(out, e.typ)
		out = bo.AppendUint32(out, 1)
		v := e.value
		if e.tag == 273 {
			v = uint32(pixelAt)
		}
		if e.typ == 3 { // SHORT values are left-justified in the 4-byte field
			out = bo.AppendUint16(out, uint16(v))
			out = append(out, 0, 0)
		} else {
			out = bo.AppendUint32(out, v)
		}
	}
	out = bo.AppendUint32(out, 0) // no next IFD
	return append(out, 0x7F)      // the pixel
}

// unsignedMP3 is an ID3v2.4 tag with a title frame followed by two MPEG-1
// Layer III frames of silence (417 bytes each at 128 kbit/s, 44.1 kHz).
func unsignedMP3() []byte {
	tag := id3Tag(4, 0, id3Frame(4, "TIT2", []byte{3, 't', 'i', 't', 'l', 'e'}))
	frame := append([]byte{0xFF, 0xFB, 0x90, 0x00}, make([]byte, 413)...)
	return append(append(tag, frame...), frame...)
}

// unsignedSVG has an XML declaration, no <metadata> and no c2pa prefix, so the
// embedder must create both.
func unsignedSVG() []byte {
	return []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"><rect width=\"1\" height=\"1\"/></svg>\n")
}

// bmffFullBox prefixes payload with a FullBox version and flags of zero.
func bmffFullBox(payload ...[]byte) []byte {
	out := []byte{0, 0, 0, 0}
	for _, p := range payload {
		out = append(out, p...)
	}
	return out
}

// minimalMP4 is the smallest MP4 with a real chunk-offset table: ftyp, a moov
// with one video track whose stco (or co64) points into mdat, and an 8-byte
// mdat. The offset is what the BMFF embedder must rewrite.
func minimalMP4(co64 bool) []byte {
	ftyp := synthBox("ftyp", []byte("isom"), []byte{0, 0, 2, 0}, []byte("isom"), []byte("mp41"))
	build := func(chunkOffset int) []byte {
		var offsets []byte
		if co64 {
			offsets = synthBox("co64", bmffFullBox(binary.BigEndian.AppendUint32(nil, 1), binary.BigEndian.AppendUint64(nil, uint64(chunkOffset))))
		} else {
			offsets = synthBox("stco", bmffFullBox(binary.BigEndian.AppendUint32(nil, 1), binary.BigEndian.AppendUint32(nil, uint32(chunkOffset))))
		}
		stbl := synthBox("stbl",
			synthBox("stsd", bmffFullBox([]byte{0, 0, 0, 1}), synthBox("mp4v", make([]byte, 78))),
			synthBox("stts", bmffFullBox([]byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})),
			synthBox("stsc", bmffFullBox([]byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})),
			synthBox("stsz", bmffFullBox([]byte{0, 0, 0, 8, 0, 0, 0, 1})),
			offsets)
		minf := synthBox("minf",
			synthBox("vmhd", bmffFullBox(make([]byte, 8))),
			synthBox("dinf", synthBox("dref", bmffFullBox([]byte{0, 0, 0, 1}), synthBox("url ", bmffFullBox()))),
			stbl)
		mdia := synthBox("mdia",
			synthBox("mdhd", bmffFullBox(make([]byte, 20))),
			synthBox("hdlr", bmffFullBox([]byte{0, 0, 0, 0, 'v', 'i', 'd', 'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			minf)
		moov := synthBox("moov", synthBox("mvhd", bmffFullBox(make([]byte, 96))), synthBox("trak", synthBox("tkhd", bmffFullBox(make([]byte, 80))), mdia))
		return append(append([]byte{}, ftyp...), moov...)
	}
	head := build(0)
	head = build(len(head) + 8) // the sample sits right after mdat's header
	return append(head, synthBox("mdat", []byte{1, 2, 3, 4, 5, 6, 7, 8})...)
}

// minimalAVIF is the smallest AVIF with a real item location: ftyp, a meta
// with hdlr, pitm and an iloc whose one extent addresses the mdat payload —
// through a base_offset when withBase is set, through extent_offset otherwise.
func minimalAVIF(withBase bool) []byte {
	ftyp := synthBox("ftyp", []byte("avif"), []byte{0, 0, 0, 0}, []byte("avif"), []byte("mif1"))
	build := func(dataOffset int) []byte {
		var iloc []byte
		if withBase {
			iloc = bmffFullBox([]byte{0x44, 0x40}, // offset_size 4, length_size 4, base_offset_size 4
				[]byte{0, 1}, []byte{0, 1}, []byte{0, 0}, binary.BigEndian.AppendUint32(nil, uint32(dataOffset)),
				[]byte{0, 1}, []byte{0, 0, 0, 0}, []byte{0, 0, 0, 8})
		} else {
			iloc = bmffFullBox([]byte{0x44, 0x00}, // offset_size 4, length_size 4, no base
				[]byte{0, 1}, []byte{0, 1}, []byte{0, 0},
				[]byte{0, 1}, binary.BigEndian.AppendUint32(nil, uint32(dataOffset)), []byte{0, 0, 0, 8})
		}
		meta := synthBox("meta", bmffFullBox(),
			synthBox("hdlr", bmffFullBox([]byte{0, 0, 0, 0, 'p', 'i', 'c', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})),
			synthBox("pitm", bmffFullBox([]byte{0, 1})),
			synthBox("iloc", iloc))
		return append(append([]byte{}, ftyp...), meta...)
	}
	head := build(0)
	head = build(len(head) + 8)
	return append(head, synthBox("mdat", []byte{1, 2, 3, 4, 5, 6, 7, 8})...)
}

// unsignedPDF is a small document with a real cross-reference section — a
// table, or a cross-reference stream — which is what a reader follows to the
// catalog and what the writer's incremental update must chain to.
func unsignedPDF(xrefStream bool) []byte {
	d := newPDFDoc().
		obj(1, "<< /Type /Catalog /Pages 2 0 R >>").
		obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>").
		obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>")
	if xrefStream {
		return d.xrefStream(4, 1).bytes()
	}
	return d.xrefTrailer(1).bytes()
}

// bindingMatch and bindingMismatch are the hard-binding status codes a
// container's signed output earns.
func bindingMatch(c Container) StatusCode {
	if c == BMFF {
		return StatusAssertionBMFFHashMatch
	}
	return StatusAssertionDataHashMatch
}

func bindingMismatch(c Container) StatusCode {
	if c == BMFF {
		return StatusAssertionBMFFHashMismatch
	}
	return StatusAssertionDataHashMismatch
}

// unsignedInput returns an unsigned asset of the container, for the containers
// Sign supports.
func unsignedInput(t testing.TB, c Container) []byte {
	t.Helper()
	switch c {
	case JPEG:
		return unsignedJPEG(t)
	case PNG:
		return unsignedPNG(t)
	case GIF:
		return unsignedGIF(t)
	case RIFF:
		return unsignedWebP()
	case TIFF:
		return unsignedTIFF(false)
	case MP3:
		return unsignedMP3()
	case SVG:
		return unsignedSVG()
	case BMFF:
		return fixtureBytes(t, "video_no_manifest.mp4")
	case PDF:
		return unsignedPDF(false)
	}
	t.Fatalf("no unsigned input for %s", c)
	return nil
}

// signableContainers are the containers Sign supports: all nine.
var signableContainers = []Container{JPEG, PNG, GIF, RIFF, TIFF, MP3, SVG, BMFF, PDF}

// tamperOutsideStore returns an offset in a signed asset that the hard binding
// covers but the store does not: the last byte for containers whose store sits
// in the header, and a byte of the first chunk or IFD entry for the two
// containers whose store is appended at the end.
func tamperOutsideStore(c Container, out []byte) int {
	switch c {
	case RIFF:
		return 12 // the first child chunk's FourCC
	case TIFF:
		return 8 + 2 // the first IFD entry's tag
	}
	return len(out) - 1
}

// fixtureBytes reads a testdata file.
func fixtureBytes(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// --- fragmented BMFF (DASH/CMAF) -----------------------------------------------

// fragOpts shapes unsignedFragmentedSet.
type fragOpts struct {
	sidxVersion int  // -1: no 'sidx'; 0 or 1 otherwise
	tfhdBase    bool // 'tfhd' with base-data-offset-present, pointing at its own 'moof'
	free        bool // a 'free' box between 'ftyp' and 'moov' in the init
	emsg        bool // an 'emsg' box before 'moof' in every fragment
	noStyp      bool // omit 'styp'
}

// emsgPayload is a minimal DASH event message: FullBox, scheme, value, timing.
var emsgPayload = bmffFullBox([]byte("urn:test\x00"), []byte{0}, make([]byte, 16))

// unsignedFragmentedSet lays out a DASH/CMAF-shaped set: an initialization
// segment ('ftyp' ['free'] 'moov') and n fragments, each ['styp'] ['sidx']
// ['emsg'] 'moof'('mfhd', 'traf'('tfhd', 'tfdt', 'trun')) 'mdat'. The 'sidx'
// first_offset points at the 'moof' (across an 'emsg' when there is one) and
// its referenced_size is exactly moof+mdat, as real segmenters write; a 'tfhd' with tfhdBase carries
// an absolute base_data_offset equal to its 'moof”s start.
func unsignedFragmentedSet(n int, o fragOpts) (init []byte, frags [][]byte) {
	init = synthBox("ftyp", []byte("iso6"), []byte{0, 0, 0, 0}, []byte("iso6"), []byte("dash"))
	if o.free {
		init = append(init, synthBox("free", make([]byte, 16))...)
	}
	mvhd := synthBox("mvhd", bmffFullBox(make([]byte, 96)))
	trak := synthBox("trak", synthBox("tkhd", bmffFullBox(make([]byte, 80))))
	mvex := synthBox("mvex", synthBox("trex", bmffFullBox(binary.BigEndian.AppendUint32(nil, 1), make([]byte, 16))))
	init = append(init, synthBox("moov", mvhd, trak, mvex)...)

	frags = make([][]byte, n)
	for k := range frags {
		mdat := synthBox("mdat", bytes.Repeat([]byte{byte(0x70 + k%64)}, 40+k%17))
		var head []byte
		if !o.noStyp {
			head = append(head, synthBox("styp", []byte("msdh"), []byte{0, 0, 0, 0}, []byte("msdh"), []byte("msix"))...)
		}
		sidxLen := 0
		if o.sidxVersion >= 0 {
			sidxLen = 8 + 4 + 8 + 8 + 4 + 12
			if o.sidxVersion == 1 {
				sidxLen += 8
			}
		}
		emsgLen := 0
		if o.emsg {
			emsgLen = 8 + len(emsgPayload)
		}
		moofStart := len(head) + sidxLen + emsgLen

		mfhd := synthBox("mfhd", bmffFullBox(binary.BigEndian.AppendUint32(nil, uint32(k+1))))
		var tfhdBody []byte
		if o.tfhdBase {
			tfhdBody = append([]byte{0, 0x00, 0x00, 0x01}, binary.BigEndian.AppendUint32(nil, 1)...)
			tfhdBody = binary.BigEndian.AppendUint64(tfhdBody, uint64(moofStart))
		} else {
			tfhdBody = append([]byte{0, 0x02, 0x00, 0x00}, binary.BigEndian.AppendUint32(nil, 1)...) // default-base-is-moof
		}
		tfhd := synthBox("tfhd", tfhdBody)
		tfdt := synthBox("tfdt", append([]byte{1, 0, 0, 0}, binary.BigEndian.AppendUint64(nil, uint64(k*2000))...))
		trunLen := 8 + 16
		moofLen := 8 + len(mfhd) + 8 + len(tfhd) + len(tfdt) + trunLen
		trun := synthBox("trun", []byte{0, 0, 0x02, 0x01},
			binary.BigEndian.AppendUint32(nil, 1),
			binary.BigEndian.AppendUint32(nil, uint32(moofLen+8)),
			binary.BigEndian.AppendUint32(nil, uint32(len(mdat)-8)))
		moof := synthBox("moof", mfhd, synthBox("traf", tfhd, tfdt, trun))
		if len(moof) != moofLen {
			panic("unsignedFragmentedSet: moof length arithmetic")
		}

		var sidx []byte
		if o.sidxVersion >= 0 {
			body := []byte{byte(o.sidxVersion), 0, 0, 0}
			body = binary.BigEndian.AppendUint32(body, 1)    // reference_ID
			body = binary.BigEndian.AppendUint32(body, 1000) // timescale
			// first_offset counts from the end of the sidx to the first
			// subsegment's moof — across an emsg when there is one.
			if o.sidxVersion == 0 {
				body = binary.BigEndian.AppendUint32(body, uint32(k*2000))  // earliest_presentation_time
				body = binary.BigEndian.AppendUint32(body, uint32(emsgLen)) // first_offset
			} else {
				body = binary.BigEndian.AppendUint64(body, uint64(k*2000))
				body = binary.BigEndian.AppendUint64(body, uint64(emsgLen))
			}
			body = append(body, 0, 0, 0, 1)                                         // reserved, reference_count
			body = binary.BigEndian.AppendUint32(body, uint32(len(moof)+len(mdat))) // reference_type 0 | referenced_size
			body = binary.BigEndian.AppendUint32(body, 2000)                        // subsegment_duration
			body = binary.BigEndian.AppendUint32(body, 0x90000000)                  // starts_with_SAP, SAP_type 1
			sidx = synthBox("sidx", body)
			if len(sidx) != sidxLen {
				panic("unsignedFragmentedSet: sidx length arithmetic")
			}
		}
		var emsg []byte
		if o.emsg {
			emsg = synthBox("emsg", emsgPayload)
		}
		frags[k] = bytes.Join([][]byte{head, sidx, emsg, moof, mdat}, nil)
	}
	return init, frags
}

// topBox returns the first top-level box of type typ, or nil.
func topBox(data []byte, typ string) *bmffBox {
	for _, b := range parseBMFFBoxes(context.Background(), data) {
		if b.typ == typ {
			return b
		}
	}
	return nil
}

// sidxFirstOffset reads a 'sidx' first_offset and the box's end.
func sidxFirstOffset(data []byte, b *bmffBox) (first uint64, end int) {
	payload := b.start + b.headerLen
	if data[payload] == 0 {
		return uint64(binary.BigEndian.Uint32(data[payload+16:])), b.end
	}
	return binary.BigEndian.Uint64(data[payload+20:]), b.end
}

// sidxReferencedSize reads the first reference's referenced_size.
func sidxReferencedSize(data []byte, b *bmffBox) uint32 {
	payload := b.start + b.headerLen
	at := payload + 24 // FullBox, reference_ID, timescale, EPT, first_offset, reserved+count
	if data[payload] != 0 {
		at = payload + 32
	}
	return binary.BigEndian.Uint32(data[at:]) & 0x7FFFFFFF
}

// tfhdBaseOffset reads the base_data_offset of the first 'tfhd' under moof,
// when its flag says one is present.
func tfhdBaseOffset(data []byte, moof *bmffBox) (uint64, bool) {
	for _, traf := range moof.children {
		for _, c := range traf.children {
			if c.typ != "tfhd" {
				continue
			}
			p := c.start + c.headerLen
			if data[p+3]&1 == 0 {
				return 0, false
			}
			return binary.BigEndian.Uint64(data[p+8:]), true
		}
	}
	return 0, false
}

// c2paBoxCount counts the top-level C2PA uuid boxes in data.
func c2paBoxCount(data []byte) int {
	n := 0
	for _, b := range parseBMFFBoxes(context.Background(), data) {
		if b.typ == "uuid" && b.usertype == c2paBoxUUID {
			n++
		}
	}
	return n
}

// fragmentSeekers wraps fragment bytes as the ReadSeekers SignFragmented takes.
func fragmentSeekers(frags [][]byte) []io.ReadSeeker {
	out := make([]io.ReadSeeker, len(frags))
	for i, f := range frags {
		out[i] = bytes.NewReader(f)
	}
	return out
}

// fragmentWriters makes n output buffers and the writers over them.
func fragmentWriters(n int) ([]*bytes.Buffer, []io.Writer) {
	bufs := make([]*bytes.Buffer, n)
	ws := make([]io.Writer, n)
	for i := range bufs {
		bufs[i] = &bytes.Buffer{}
		ws[i] = bufs[i]
	}
	return bufs, ws
}

// signFragmentedSet signs init + frags and returns the signed files.
func signFragmentedSet(t testing.TB, s *Signer, init []byte, frags [][]byte, m Manifest) ([]byte, [][]byte) {
	t.Helper()
	var outInit bytes.Buffer
	bufs, ws := fragmentWriters(len(frags))
	if err := s.SignFragmented(context.Background(), bytes.NewReader(init), fragmentSeekers(frags), &outInit, ws, m); err != nil {
		t.Fatalf("SignFragmented: %v", err)
	}
	out := make([][]byte, len(bufs))
	for i, b := range bufs {
		out[i] = b.Bytes()
	}
	return outInit.Bytes(), out
}

// bunnySet loads the vendored Big Buck Bunny rendition: init plus its eleven
// fragments in file-name order.
func bunnySet(t testing.TB) (init []byte, frags [][]byte, names []string) {
	t.Helper()
	init = fixtureBytes(t, "dash/bunny/BigBuckBunny_2s_init.mp4")
	paths, err := filepath.Glob("testdata/dash/bunny/BigBuckBunny_2s*.m4s")
	if err != nil || len(paths) != 11 {
		t.Fatalf("bunny fragments: %v (%d)", err, len(paths))
	}
	sort.Strings(paths)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		frags = append(frags, data)
		names = append(names, filepath.Base(p))
	}
	return init, frags, names
}
