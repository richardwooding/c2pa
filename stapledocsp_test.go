package c2pa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestJudgeStapledOCSP(t *testing.T) {
	now := time.Date(2013, 6, 1, 0, 0, 0, 0, time.UTC)
	mk := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	key := func() *ecdsa.PrivateKey {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k
	}
	caKey, leafKey, respKey, badKey := key(), key(), key(), key()
	base := func(sn int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(sn), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		}
	}
	caT := base(1, "ca")
	caT.IsCA, caT.BasicConstraintsValid, caT.KeyUsage = true, true, x509.KeyUsageCertSign
	ca := mk(caT, caT, &caKey.PublicKey, caKey)
	leaf := mk(base(2, "leaf"), ca, &leafKey.PublicKey, caKey)
	okT := base(3, "responder")
	okT.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	responder := mk(okT, ca, &respKey.PublicKey, caKey)
	noEKU := mk(base(4, "responder-no-eku"), ca, &badKey.PublicKey, caKey)

	resp := func(status int, this, next time.Time, rc *x509.Certificate, k *ecdsa.PrivateKey) []byte {
		der, err := ocsp.CreateResponse(ca, rc, ocsp.Response{
			Status: status, SerialNumber: leaf.SerialNumber, ThisUpdate: this, NextUpdate: next,
			RevokedAt: this, Certificate: rc,
		}, k)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	day := 24 * time.Hour
	tests := []struct {
		name     string
		der      []byte
		at       time.Time
		signedAt time.Time
		want     ocspVerdict
	}{
		{"good, issuer-signed", resp(ocsp.Good, now.Add(-day), now.Add(day), ca, caKey), now, time.Time{}, ocspGood},
		{"good, delegated responder", resp(ocsp.Good, now.Add(-day), now.Add(day), responder, respKey), now, time.Time{}, ocspGood},
		{"delegated responder without OCSPSigning", resp(ocsp.Good, now.Add(-day), now.Add(day), noEKU, badKey), now, time.Time{}, ocspUnusable},
		{"revoked", resp(ocsp.Revoked, now.Add(-day), now.Add(day), ca, caKey), now, time.Time{}, ocspRevoked},
		{"thisUpdate after validation time", resp(ocsp.Good, now.Add(day), now.Add(2*day), ca, caKey), now, time.Time{}, ocspUnusable},
		{"expired nextUpdate", resp(ocsp.Good, now.Add(-3*day), now.Add(-day), ca, caKey), now, time.Time{}, ocspUnusable},
		{"expired now but valid at signing time", resp(ocsp.Good, now.Add(-3*day), now.Add(-day), ca, caKey), now.Add(-2 * day), now.Add(-2 * day), ocspGood},
	}
	for _, tc := range tests {
		if got := judgeStapledOCSP(tc.der, leaf, ca, now, tc.at, tc.signedAt); got != tc.want {
			t.Errorf("%s: verdict = %v, want %v", tc.name, got, tc.want)
		}
	}
}
