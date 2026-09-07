package c2pa

import (
	"bytes"
	"crypto/x509"
	"io"

	"golang.org/x/crypto/ocsp"
)

// maxRevocationBody caps how much of an OCSP/CRL HTTP response is read.
const maxRevocationBody = 8 << 20

// checkRevocation checks the signing leaf certificate's revocation status via
// OCSP, falling back to CRL. It runs only when online revocation is enabled
// (WithOnlineRevocation); otherwise it records an informational "unknown".
//
// Revocation is soft-fail: a missing endpoint, network error, or unparseable
// response yields an informational "unknown" status — never a validation
// failure. Only a definitive "revoked" answer is a failure. This avoids turning
// a flaky responder into a false rejection.
//
// revokedCode is the code a definitive answer records: signingCredential.revoked
// for the claim signer, cawg.identity.credential_revoked for a CAWG identity.
func (v *validator) checkRevocation(chain []*x509.Certificate, uri string, revokedCode StatusCode) {
	if !v.cfg.onlineRevocation {
		v.add(StatusRevocationUnknown, uri, "online revocation checking disabled", nil)
		return
	}
	if len(chain) < 2 {
		v.add(StatusRevocationUnknown, uri, "no issuer certificate to check revocation against", nil)
		return
	}
	leaf, issuer := chain[0], chain[1]
	if revoked, ok := v.ocspRevoked(leaf, issuer); ok {
		if revoked {
			v.add(revokedCode, uri, "signing certificate revoked (OCSP)", nil)
		}
		return
	}
	if revoked, ok := v.crlRevoked(leaf, issuer); ok {
		if revoked {
			v.add(revokedCode, uri, "signing certificate revoked (CRL)", nil)
		}
		return
	}
	v.add(StatusRevocationUnknown, uri, "revocation status could not be determined", nil)
}

// ocspRevoked queries the leaf's OCSP responder. It returns (revoked, ok); ok
// is false on any soft-fail condition (no responder, network/parse error, or an
// "unknown" responder answer).
func (v *validator) ocspRevoked(leaf, issuer *x509.Certificate) (revoked, ok bool) {
	if len(leaf.OCSPServer) == 0 {
		return false, false
	}
	reqBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, false
	}
	httpResp, err := v.cfg.httpClient.Post(leaf.OCSPServer[0], "application/ocsp-request", bytes.NewReader(reqBytes))
	if err != nil {
		return false, false
	}
	defer func() { _ = httpResp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxRevocationBody))
	if err != nil {
		return false, false
	}
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return false, false
	}
	switch resp.Status {
	case ocsp.Good:
		return false, true
	case ocsp.Revoked:
		return true, true
	default: // ocsp.Unknown
		return false, false
	}
}

// crlRevoked fetches the leaf's CRL distribution point(s) and checks whether the
// leaf's serial number is listed, verifying the CRL is issued by issuer. Soft-
// fail like ocspRevoked.
func (v *validator) crlRevoked(leaf, issuer *x509.Certificate) (revoked, ok bool) {
	for _, url := range leaf.CRLDistributionPoints {
		httpResp, err := v.cfg.httpClient.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxRevocationBody))
		_ = httpResp.Body.Close()
		if err != nil {
			continue
		}
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			continue
		}
		if crl.CheckSignatureFrom(issuer) != nil {
			continue // not issued by this issuer; ignore
		}
		for i := range crl.RevokedCertificateEntries {
			if crl.RevokedCertificateEntries[i].SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}
