package c2pa

import (
	"crypto/x509"
	"time"

	cose "github.com/veraison/go-cose"
	"golang.org/x/crypto/ocsp"
)

// Stapled OCSP status codes (§15.4): the signer's OCSP responses ride in the
// COSE unprotected header (rVals.ocspVals), so revocation can be assessed
// offline and as of signing time.
const (
	StatusOCSPNotRevoked StatusCode = "signingCredential.ocsp.notRevoked"
	StatusOCSPRevoked    StatusCode = "signingCredential.ocsp.revoked"
	StatusOCSPSkipped    StatusCode = "signingCredential.ocsp.skipped"
)

func init() {
	statusSeverity[StatusOCSPNotRevoked] = SeveritySuccess
	statusSeverity[StatusOCSPRevoked] = SeverityFailure
	statusSeverity[StatusOCSPSkipped] = SeverityInformational
}

// stapledOCSPResponses returns the DER OCSP responses stapled in the COSE
// envelope's unprotected rVals.ocspVals header, or nil.
func stapledOCSPResponses(envelope []byte) [][]byte {
	var msg cose.Sign1Message
	if msg.UnmarshalCBOR(envelope) != nil {
		return nil
	}
	rv, ok := msg.Headers.Unprotected["rVals"]
	if !ok {
		return nil
	}
	var vals any
	switch m := rv.(type) {
	case map[any]any:
		vals = m["ocspVals"]
	case map[string]any:
		vals = m["ocspVals"]
	}
	list, _ := vals.([]any)
	var out [][]byte
	for _, e := range list {
		if b, ok := e.([]byte); ok && len(b) > 0 {
			out = append(out, b)
		}
	}
	return out
}

// checkStapledOCSP assesses the leaf's stapled OCSP responses. signedAt is the
// trusted time-stamp's genTime (zero when none): a response is judged at
// signing time when that is known, else at the validation clock. It reports
// whether the stapled responses settled revocation (good or revoked); when they
// did not, the caller falls back to the online check.
func (v *validator) checkStapledOCSP(m *parsedManifest, chain []*x509.Certificate, uri string, signedAt time.Time) (settled bool) {
	responses := stapledOCSPResponses(m.signature)
	if len(responses) == 0 || len(chain) < 2 {
		return false
	}
	now := v.cfg.clock()
	at := now
	if !signedAt.IsZero() {
		at = signedAt
	}
	leaf, issuer := chain[0], chain[1]
	for _, der := range responses {
		resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
		if err != nil {
			continue // wrong certificate, bad signature, or unauthorised responder
		}
		if resp.ThisUpdate.After(now) || (!resp.NextUpdate.IsZero() && resp.NextUpdate.Before(at)) {
			continue
		}
		switch resp.Status {
		case ocsp.Good:
			v.add(StatusOCSPNotRevoked, uri, "stapled OCSP response: not revoked", nil)
			return true
		case ocsp.Revoked:
			if !signedAt.IsZero() && resp.RevokedAt.After(signedAt) {
				v.add(StatusOCSPNotRevoked, uri, "stapled OCSP response: revoked only after signing", nil)
				return true
			}
			v.add(StatusOCSPRevoked, uri, "stapled OCSP response: signing certificate revoked", nil)
			v.add(StatusSigningCredentialRevoked, uri, "signing certificate revoked (stapled OCSP)", nil)
			v.dropStatus(uri, StatusClaimSignatureValidated)
			v.dropStatus(uri, StatusSigningCredentialTrusted)
			return true
		}
	}
	v.add(StatusOCSPSkipped, uri, "no usable stapled OCSP response for the signing certificate", nil)
	return false
}
