package c2pa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// oidEKUDocumentSigning is id-kp-documentSigning (RFC 9336), a C2PA-acceptable
// signing EKU that Go's crypto/x509 has no named constant for, so it surfaces
// in Certificate.UnknownExtKeyUsage instead of ExtKeyUsage.
var oidEKUDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

// oidRSASSAPSS is id-RSASSA-PSS. C2PA RSA signing certificates commonly encode
// their SubjectPublicKeyInfo with this algorithm OID rather than rsaEncryption.
// Go's crypto/x509 does not parse such an SPKI into a usable key — it leaves
// Certificate.PublicKey nil — which breaks both COSE verification and chain
// building. parseCert below repairs that without altering the signed TBS bytes.
var oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

// parseCert parses a DER certificate, repairing the RSA-PSS SubjectPublicKeyInfo
// case: when crypto/x509 leaves PublicKey nil because the SPKI uses id-RSASSA-PSS,
// the RSA key is extracted from the SPKI and assigned to the exported PublicKey
// field. x509.Verify (via CheckSignature) and cose.NewVerifier both read that
// field, so this makes the cert usable while leaving its signed TBS untouched
// (rewriting the SPKI OID would invalidate the certificate's own signature).
func parseCert(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if c.PublicKey == nil {
		if pk := rsaPSSPublicKey(c); pk != nil {
			c.PublicKey = pk
			c.PublicKeyAlgorithm = x509.RSA
		}
	}
	return c, nil
}

// rsaPSSPublicKey extracts the RSA public key from a certificate whose SPKI uses
// the id-RSASSA-PSS algorithm OID, or returns nil if it is not such a key.
func rsaPSSPublicKey(c *x509.Certificate) *rsa.PublicKey {
	var spki struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSASSAPSS) {
		return nil
	}
	pub, err := x509.ParsePKCS1PublicKey(spki.SubjectPublicKey.RightAlign())
	if err != nil {
		return nil
	}
	return pub
}

// allX5ChainDER extracts every DER certificate from an x5chain header value
// (leaf first), handling the single-[]byte, [][]byte, and []any encodings. It
// is the full-chain counterpart of firstX5ChainDER (which grabs only the leaf).
func allX5ChainDER(v any) [][]byte {
	switch x := v.(type) {
	case []byte:
		return [][]byte{x}
	case [][]byte:
		return x
	case []any:
		var out [][]byte
		for _, e := range x {
			if b, ok := e.([]byte); ok {
				out = append(out, b)
			}
		}
		return out
	}
	return nil
}

// parseChain parses an x5chain header value into certificates (leaf first). A
// single malformed certificate poisons the whole chain (returns nil) rather
// than yielding a misleading partial path.
func parseChain(v any) []*x509.Certificate {
	ders := allX5ChainDER(v)
	if len(ders) == 0 {
		return nil
	}
	out := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		c, err := parseCert(der)
		if err != nil {
			return nil
		}
		out = append(out, c)
	}
	return out
}

// verifyChain builds and validates a certificate chain from leaf-first certs to
// an anchor in roots at verifyTime, then applies the C2PA certificate-profile
// checks that crypto/x509 does not enforce. ekuOK decides whether the leaf's
// extended key usage is acceptable for its role (signing vs timestamping).
// It records status entries under uri and reports whether the chain is trusted.
func (v *validator) verifyChain(certs []*x509.Certificate, roots *x509.CertPool, verifyTime time.Time, ekuOK func(*x509.Certificate) bool, uri string) bool {
	if len(certs) == 0 {
		v.add(StatusSigningCredentialInvalid, uri, "no certificate chain", nil)
		return false
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   verifyTime,
		// Enforce the C2PA EKU rule manually below; x509's KeyUsages handling is
		// too lenient about chains for our needs.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var unknownAuth x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		switch {
		case errors.As(err, &unknownAuth):
			v.add(StatusSigningCredentialUntrusted, uri, "chain does not reach a trust anchor", err)
		case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
			v.add(StatusSigningCredentialExpired, uri, "certificate not valid at signing time", err)
		default:
			v.add(StatusSigningCredentialInvalid, uri, "certificate chain verification failed", err)
		}
		return false
	}
	if !v.checkCertProfile(chains[0], leaf, ekuOK, uri) {
		return false
	}
	v.add(StatusSigningCredentialTrusted, uri, "certificate chain validated", nil)
	return true
}

// checkCertProfile applies the manual C2PA certificate-profile constraints to a
// built path and records a failure status for each violation. The rules
// themselves live in certProfileViolations, which NewSigner applies to its own
// chain — the signer refuses exactly what the validator would fail.
func (v *validator) checkCertProfile(path []*x509.Certificate, leaf *x509.Certificate, ekuOK func(*x509.Certificate) bool, uri string) bool {
	violations := certProfileViolations(path, leaf, ekuOK)
	for _, msg := range violations {
		v.add(StatusSigningCredentialInvalid, uri, msg, nil)
	}
	return len(violations) == 0
}

// certProfileViolations lists the C2PA certificate-profile constraints (§14.5.2)
// a built path breaks: leaf keyUsage digitalSignature, a present+constrained
// EKU (no anyExtendedKeyUsage), leaf-is-not-CA, and no weak signature
// algorithms / short RSA keys anywhere in the path. Empty means it conforms.
func certProfileViolations(path []*x509.Certificate, leaf *x509.Certificate, ekuOK func(*x509.Certificate) bool) []string {
	var out []string
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		out = append(out, "leaf keyUsage lacks digitalSignature")
	}
	if leafHasAnyEKU(leaf) {
		out = append(out, "leaf EKU includes anyExtendedKeyUsage")
	}
	if !ekuOK(leaf) {
		out = append(out, "leaf EKU missing or not acceptable for its role")
	}
	if leaf.IsCA {
		out = append(out, "leaf certificate is a CA")
	}
	for _, c := range path {
		if weakSigAlg(c.SignatureAlgorithm) {
			out = append(out, "weak signature algorithm in chain")
			break
		}
		if pk, isRSA := c.PublicKey.(*rsa.PublicKey); isRSA && pk.N.BitLen() < 2048 {
			out = append(out, "RSA key shorter than 2048 bits in chain")
			break
		}
	}
	return out
}

func leafHasAnyEKU(leaf *x509.Certificate) bool {
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// signingEKUOK accepts a C2PA content-signing leaf: it must carry an EKU, and
// it must include one of emailProtection, codeSigning, or id-kp-documentSigning.
func signingEKUOK(leaf *x509.Certificate) bool {
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageEmailProtection || e == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(oidEKUDocumentSigning) {
			return true
		}
	}
	return false
}

// timestampEKUOK accepts a TSA leaf: it must include id-kp-timeStamping.
func timestampEKUOK(leaf *x509.Certificate) bool {
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}

// weakSigAlg reports whether a certificate signature algorithm is forbidden by
// the C2PA profile (SHA-1 / MD5 / MD2 family).
func weakSigAlg(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}
