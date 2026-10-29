package c2pa

import (
	"crypto/x509"
	"slices"
	"time"

	cose "github.com/veraison/go-cose"
	"golang.org/x/crypto/ocsp"
)

// Stapled OCSP (§15.4): the signer's OCSP responses ride in the COSE
// unprotected header (rVals.ocspVals), so revocation can be assessed offline
// and as of signing time. The status codes live in statuscodes.go.

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
func (v *validator) checkStapledOCSP(m *parsedManifest, chain []*x509.Certificate, uri string, signedAt, verifyTime time.Time) (settled bool) {
	responses := stapledOCSPResponses(m.signature)
	if len(responses) == 0 {
		return false
	}
	// The issuer need not be in the presented chain (a leaf issued directly by
	// a trust anchor presents only itself), so take it from the built path.
	path, err := buildTrustedPath(chain, v.signingTrustPool(), verifyTime)
	if err != nil || len(path) < 2 {
		return false
	}
	now := v.cfg.clock()
	at := now
	if !signedAt.IsZero() {
		at = signedAt
	}
	leaf, issuer := path[0], path[1]
	for _, der := range responses {
		switch verdict := judgeStapledOCSP(der, leaf, issuer, now, at, signedAt); verdict {
		case ocspGood:
			v.add(StatusOCSPNotRevoked, uri, "stapled OCSP response: not revoked", nil)
			return true
		case ocspRevoked:
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

type ocspVerdict int

const (
	ocspUnusable ocspVerdict = iota
	ocspGood
	ocspRevoked
)

// judgeStapledOCSP decides what one stapled response says about leaf. It is
// unusable when it is for another certificate, badly signed, from a delegated
// responder that is not authorised to sign OCSP (no id-kp-OCSPSigning), not
// yet valid at the validation clock now, or past nextUpdate at the time it is
// judged (at: signing time when known, else now).
func judgeStapledOCSP(der []byte, leaf, issuer *x509.Certificate, now, at, signedAt time.Time) ocspVerdict {
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return ocspUnusable
	}
	if resp.Certificate != nil && !resp.Certificate.Equal(issuer) &&
		!slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return ocspUnusable
	}
	if resp.ThisUpdate.After(now) || (!resp.NextUpdate.IsZero() && resp.NextUpdate.Before(at)) {
		return ocspUnusable
	}
	switch resp.Status {
	case ocsp.Good:
		return ocspGood
	case ocsp.Revoked:
		if !signedAt.IsZero() && resp.RevokedAt.After(signedAt) {
			return ocspGood // revoked only after the claim was signed
		}
		return ocspRevoked
	}
	return ocspUnusable
}
