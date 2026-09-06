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
	"math/big"
	"os"
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
	}
	t.Fatalf("no unsigned input for %s", c)
	return nil
}

// signableContainers are the containers Sign supports so far.
var signableContainers = []Container{JPEG, PNG, GIF, RIFF, TIFF, MP3, SVG}

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
