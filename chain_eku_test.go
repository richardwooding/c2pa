package c2pa

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func TestSigningEKUOK(t *testing.T) {
	cases := []struct {
		name string
		cert x509.Certificate
		want bool
	}{
		{"c2pa-kp-claimSigning", x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUClaimSigning}}, true},
		{"documentSigning", x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUDocumentSigning}}, true},
		{"emailProtection", x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}, true},
		{"serverAuth only", x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, false},
		{"no EKU", x509.Certificate{}, false},
	}
	for _, c := range cases {
		if got := signingEKUOK(&c.cert); got != c.want {
			t.Errorf("%s: signingEKUOK = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClaimSigningEKUOK(t *testing.T) {
	if !claimSigningEKUOK(&x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUClaimSigning}}) {
		t.Error("c2pa-kp-claimSigning must be accepted")
	}
	for name, c := range map[string]x509.Certificate{
		"emailProtection": {ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}},
		"documentSigning": {UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUDocumentSigning}},
		"no EKU":          {},
	} {
		if claimSigningEKUOK(&c) {
			t.Errorf("%s alone must be rejected in strict mode", name)
		}
	}
}
