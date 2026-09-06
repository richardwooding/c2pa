package c2pa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// newTestCA returns a self-signed CA certificate and its key.
func newTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// newTestLeaf issues a leaf signed by the given issuer with the given OCSP URL.
func newTestLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, ocspURL string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		OCSPServer:   []string{ocspURL},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testValidator(online bool, client *http.Client) *validator {
	cfg := defaultConfig()
	cfg.onlineRevocation = online
	if client != nil {
		cfg.httpClient = client
	}
	return &validator{ctx: context.Background(), cfg: cfg, visited: map[string]bool{}}
}

// TestRevocation_OCSPRevoked confirms a "revoked" OCSP response yields the
// revoked failure status.
func TestRevocation_OCSPRevoked(t *testing.T) {
	issuer, issuerKey := newTestCA(t)
	var respBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	leaf := newTestLeaf(t, issuer, issuerKey, srv.URL)
	tmpl := ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		RevocationReason: ocsp.Unspecified,
		RevokedAt:        time.Now().Add(-time.Minute),
		ThisUpdate:       time.Now().Add(-time.Minute),
		NextUpdate:       time.Now().Add(time.Hour),
	}
	var err error
	respBytes, err = ocsp.CreateResponse(issuer, issuer, tmpl, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	v := testValidator(true, srv.Client())
	v.checkRevocation([]*x509.Certificate{leaf, issuer}, "test")
	if !v.res.Has(StatusSigningCredentialRevoked) {
		t.Errorf("expected signingCredential.revoked; got %v", codes(v.res))
	}
}

// TestRevocation_OCSPGood confirms a "good" OCSP response produces no revoked
// failure (and no spurious unknown).
func TestRevocation_OCSPGood(t *testing.T) {
	issuer, issuerKey := newTestCA(t)
	var respBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	leaf := newTestLeaf(t, issuer, issuerKey, srv.URL)
	tmpl := ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	var err error
	respBytes, err = ocsp.CreateResponse(issuer, issuer, tmpl, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	v := testValidator(true, srv.Client())
	v.checkRevocation([]*x509.Certificate{leaf, issuer}, "test")
	if v.res.Has(StatusSigningCredentialRevoked) {
		t.Errorf("did not expect revoked for a good response; got %v", codes(v.res))
	}
	if v.res.Has(StatusRevocationUnknown) {
		t.Errorf("did not expect unknown for a good response; got %v", codes(v.res))
	}
}

// TestRevocation_OfflineUnknown confirms the default (offline) path reports an
// informational unknown without making any network call.
func TestRevocation_OfflineUnknown(t *testing.T) {
	issuer, issuerKey := newTestCA(t)
	leaf := newTestLeaf(t, issuer, issuerKey, "http://127.0.0.1:0/never-called")
	v := testValidator(false, nil)
	v.checkRevocation([]*x509.Certificate{leaf, issuer}, "test")
	if !v.res.Has(StatusRevocationUnknown) {
		t.Errorf("expected revocation.unknown when offline; got %v", codes(v.res))
	}
	for _, s := range v.res.Statuses {
		if s.Severity == SeverityFailure {
			t.Errorf("offline revocation must not produce a failure; got %v", s.Code)
		}
	}
}
