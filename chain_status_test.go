package c2pa

import (
	"crypto/x509"
	"testing"
)

func TestChainErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want StatusCode
	}{
		{"unknown authority", x509.UnknownAuthorityError{}, StatusSigningCredentialUntrusted},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, StatusSigningCredentialExpired},
		{"pathLenConstraint exceeded", x509.CertificateInvalidError{Reason: x509.TooManyIntermediates}, StatusSigningCredentialUntrusted},
		{"CA not authorized to sign", x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, StatusSigningCredentialUntrusted},
		{"incompatible usage", x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}, StatusSigningCredentialInvalid},
	} {
		if got, _ := chainErrorStatus(tc.err); got != tc.want {
			t.Errorf("%s: status = %s, want %s", tc.name, got, tc.want)
		}
	}
}
