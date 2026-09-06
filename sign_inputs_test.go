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
	"encoding/pem"
	"image"
	"image/color"
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

// unsignedInput returns an unsigned asset of the container, for the containers
// Sign supports.
func unsignedInput(t testing.TB, c Container) []byte {
	t.Helper()
	switch c {
	case JPEG:
		return unsignedJPEG(t)
	case PNG:
		return unsignedPNG(t)
	}
	t.Fatalf("no unsigned input for %s", c)
	return nil
}

// signableContainers are the containers Sign supports so far.
var signableContainers = []Container{JPEG, PNG}

// fixtureBytes reads a testdata file.
func fixtureBytes(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
