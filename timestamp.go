package c2pa

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"hash"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// Object identifiers used by the RFC 3161 / CMS descent.
var (
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidCTTSTInfo     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256RSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384RSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512RSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// verifyTimestamp verifies the RFC 3161 timestamp embedded in the COSE
// signature, if present. It fully verifies the CMS SignedData signature, that
// the timestamp's messageImprint covers this signature (via the C2PA
// CounterSignature structure), and that the TSA certificate chains to the
// trusted timestamp pool. On success it returns the genTime and trusted=true;
// that time then pins the signing certificate's validity window. A timestamp
// that is absent is informational (timestamps are optional); one that is
// present but invalid is a failure.
func (v *validator) verifyTimestamp(m *parsedManifest, uri string) (genTime time.Time, trusted bool) {
	var msg cose.Sign1Message
	if msg.UnmarshalCBOR(m.signature) != nil {
		return time.Time{}, false
	}
	tokenDER, v2 := extractTSToken(msg.Headers.Unprotected)
	if len(tokenDER) == 0 {
		v.add(StatusTimeStampMissing, uri, "no timestamp present", nil)
		return time.Time{}, false
	}

	protected, signature, ok := coseParts(m.signature)
	if !ok {
		v.add(StatusTimeStampMismatch, uri, "could not decode COSE structure for timestamp binding", nil)
		return time.Time{}, false
	}
	// The bytes the timestamp covers: a COSE CounterSignature structure. V1
	// (sigTst) counter-signs the claim payload; V2 (sigTst2) counter-signs the
	// CBOR-encoded signature value.
	var counterPayload []byte
	if v2 {
		counterPayload, _ = cbor.Marshal(signature)
	} else {
		counterPayload = m.claimBytes
	}
	tbs := coseCountersignData(counterPayload, protected)

	gt, code := v.verifyTimestampToken(tokenDER, tbs, uri)
	if code != StatusTimeStampValidated {
		// gt is non-zero only for StatusTimeStampUntrusted — a token bound to
		// this signature whose TSA merely does not anchor.
		return gt, false
	}
	v.add(StatusTimeStampValidated, uri, "timestamp verified", nil)
	return gt, true
}

// verifyTimestampToken parses and verifies an RFC 3161 timestamp token (a CMS
// SignedData): it checks the messageImprint against tbs, verifies the CMS
// signer signature and its messageDigest/contentType signed attributes, and
// chains the TSA certificate to the trusted timestamp pool. It returns the
// genTime and the resulting status code (StatusTimeStampValidated on success).
func (v *validator) verifyTimestampToken(der, tbs []byte, uri string) (time.Time, StatusCode) {
	sd, ok := parseCMSSignedData(der)
	if !ok {
		v.add(StatusTimeStampMismatch, uri, "malformed timestamp token", nil)
		return time.Time{}, StatusTimeStampMismatch
	}

	tstInfo, ok := parseTSTInfo(sd.eContent)
	if !ok {
		v.add(StatusTimeStampMismatch, uri, "malformed TSTInfo", nil)
		return time.Time{}, StatusTimeStampMismatch
	}

	// 1. messageImprint must cover tbs.
	imprintHash, ok := hashByOID(tstInfo.imprintAlg)
	if !ok {
		v.add(StatusTimeStampMismatch, uri, "unsupported messageImprint algorithm", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	imprintHash.Write(tbs)
	if subtle.ConstantTimeCompare(imprintHash.Sum(nil), tstInfo.imprint) != 1 {
		v.add(StatusTimeStampMismatch, uri, "timestamp does not cover this signature", nil)
		return time.Time{}, StatusTimeStampMismatch
	}

	// 2. CMS signer info + signature.
	si, ok := parseSignerInfo(sd.signerInfos)
	if !ok {
		v.add(StatusTimeStampMismatch, uri, "malformed or multiple timestamp signers", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	signer := findSigner(sd.certs, si)
	if signer == nil {
		v.add(StatusTimeStampUntrusted, uri, "timestamp signer certificate not found", nil)
		return time.Time{}, StatusTimeStampUntrusted
	}
	digest, ok := digestCryptoHash(si.digestAlg)
	if !ok {
		v.add(StatusTimeStampMismatch, uri, "unsupported timestamp digest algorithm", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	// signedAttrs are mandatory for an RFC 3161 token.
	if len(si.signedAttrs.FullBytes) == 0 {
		v.add(StatusTimeStampMismatch, uri, "timestamp signer has no signed attributes", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	// messageDigest signed attr must equal hash(eContent); contentType must be id-ct-TSTInfo.
	mdOK, ctOK := checkSignedAttrs(si.signedAttrs.Bytes, digest, sd.eContent)
	if !ctOK || !mdOK {
		v.add(StatusTimeStampMismatch, uri, "timestamp signed attributes do not match content", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	// Verify the signature over the DER SET OF signedAttrs: on the wire the
	// attributes are [0] IMPLICIT (0xA0); the signature covers them as a
	// universal SET OF (0x31). Re-tag without re-sorting (the TSA emits DER).
	toVerify := append([]byte(nil), si.signedAttrs.FullBytes...)
	if toVerify[0] != 0xA0 {
		v.add(StatusTimeStampMismatch, uri, "unexpected signed-attributes encoding", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	toVerify[0] = 0x31
	sigAlg := x509SigAlg(si.sigAlg, si.digestAlg)
	if sigAlg == x509.UnknownSignatureAlgorithm {
		v.add(StatusTimeStampMismatch, uri, "unsupported timestamp signature algorithm", nil)
		return time.Time{}, StatusTimeStampMismatch
	}
	if err := signer.CheckSignature(sigAlg, toVerify, si.signature); err != nil {
		v.add(StatusTimeStampMismatch, uri, "timestamp signature did not verify", err)
		return time.Time{}, StatusTimeStampMismatch
	}

	// 3. Chain the TSA certificate to the trusted timestamp pool at genTime.
	// An untrusted chain still returns the genTime: everything cryptographic —
	// the imprint binding to THIS signature, the signed attributes, the CMS
	// signature — has passed by here, so the time is attested, just not by an
	// authority the pool anchors. The caller decides what that is good for.
	if !v.verifyTSAChain(signer, sd.certs, tstInfo.genTime, uri) {
		return tstInfo.genTime, StatusTimeStampUntrusted
	}
	return tstInfo.genTime, StatusTimeStampValidated
}

// verifyTSAChain builds and validates the TSA certificate chain to the trusted
// timestamp pool, requiring the id-kp-timeStamping EKU.
func (v *validator) verifyTSAChain(signer *x509.Certificate, certs []*x509.Certificate, genTime time.Time, uri string) bool {
	inter := x509.NewCertPool()
	for _, c := range certs {
		if c != signer {
			inter.AddCert(c)
		}
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:         v.timestampTrustPool(),
		Intermediates: inter,
		CurrentTime:   genTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		v.add(StatusTimeStampUntrusted, uri, "timestamp authority not trusted", err)
		return false
	}
	if !timestampEKUOK(signer) {
		v.add(StatusTimeStampUntrusted, uri, "timestamp signer lacks id-kp-timeStamping EKU", nil)
		return false
	}
	return true
}

// cmsSignedData is the subset of a CMS SignedData the timestamp verifier needs.
type cmsSignedData struct {
	eContent    []byte // TSTInfo DER (the encapsulated content)
	certs       []*x509.Certificate
	signerInfos asn1.RawValue // SET OF SignerInfo
}

// parseCMSSignedData descends an RFC 3161 token (a TimeStampResp wrapping a CMS
// ContentInfo, or a bare ContentInfo) to the SignedData and extracts the
// encapsulated TSTInfo, the certificates, and the signerInfos. Defensive at
// every step.
func parseCMSSignedData(der []byte) (cmsSignedData, bool) {
	var out cmsSignedData
	contentInfo := timestampContentInfo(der)
	var ci struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(contentInfo, &ci); err != nil {
		return out, false
	}
	var sd struct {
		Version     int
		DigestAlgos asn1.RawValue `asn1:"set"`
		Encap       struct {
			OID     asn1.ObjectIdentifier
			Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
		}
		Certs       asn1.RawValue `asn1:"optional,tag:0"`
		CRLs        asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return out, false
	}
	var eContent []byte
	if _, err := asn1.Unmarshal(sd.Encap.Content.Bytes, &eContent); err != nil {
		return out, false
	}
	out.eContent = eContent
	out.signerInfos = sd.SignerInfos
	if len(sd.Certs.Bytes) > 0 {
		if certs, err := x509.ParseCertificates(sd.Certs.Bytes); err == nil {
			for _, c := range certs {
				if c.PublicKey == nil {
					if pk := rsaPSSPublicKey(c); pk != nil {
						c.PublicKey = pk
						c.PublicKeyAlgorithm = x509.RSA
					}
				}
				out.certs = append(out.certs, c)
			}
		}
	}
	return out, true
}

// timestampContentInfo returns the CMS ContentInfo holding the timestamp's
// SignedData, from either a bare ContentInfo — what C2PA's sigTst/sigTst2 hold
// — or one wrapped in an RFC 3161 TimeStampResp. Both are two-element
// SEQUENCEs, so only their first element tells them apart: a ContentInfo's is
// an OID, a PKIStatusInfo's is a SEQUENCE. Assuming TimeStampResp descends into
// a bare ContentInfo's [0] wrapper and fails for every C2PA timestamp.
func timestampContentInfo(der []byte) []byte {
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return der
	}
	if len(resp.Token.FullBytes) == 0 {
		return der
	}
	var contentType asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &contentType); err == nil {
		// The first element is a content type, so this is already a ContentInfo.
		return der
	}
	return resp.Token.FullBytes
}

// tstInfoFields holds the TSTInfo fields the verifier needs.
type tstInfoFields struct {
	imprintAlg asn1.ObjectIdentifier
	imprint    []byte
	genTime    time.Time
}

func parseTSTInfo(eContent []byte) (tstInfoFields, bool) {
	var out tstInfoFields
	var tst struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint struct {
			Alg struct {
				Algorithm asn1.ObjectIdentifier
				Params    asn1.RawValue `asn1:"optional"`
			}
			Hashed []byte
		}
		SerialNumber *big.Int
		GenTime      time.Time       `asn1:"generalized"`
		Rest         []asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(eContent, &tst); err != nil {
		return out, false
	}
	out.imprintAlg = tst.MessageImprint.Alg.Algorithm
	out.imprint = tst.MessageImprint.Hashed
	out.genTime = tst.GenTime
	return out, true
}

// signerInfoFields holds the CMS SignerInfo fields the verifier needs.
type signerInfoFields struct {
	sid         asn1.RawValue
	digestAlg   asn1.ObjectIdentifier
	signedAttrs asn1.RawValue // [0] IMPLICIT SET OF Attribute
	sigAlg      asn1.ObjectIdentifier
	signature   []byte
}

// parseSignerInfo parses the single SignerInfo from a SET OF SignerInfo,
// requiring exactly one signer (RFC 3161 tokens are single-signer).
func parseSignerInfo(set asn1.RawValue) (signerInfoFields, bool) {
	var out signerInfoFields
	var si struct {
		Version   int
		SID       asn1.RawValue
		DigestAlg struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue `asn1:"optional"`
		}
		SignedAttrs asn1.RawValue `asn1:"optional,tag:0"`
		SigAlg      struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue `asn1:"optional"`
		}
		Signature     []byte
		UnsignedAttrs asn1.RawValue `asn1:"optional,tag:1"`
	}
	rest, err := asn1.Unmarshal(set.Bytes, &si)
	if err != nil || len(rest) != 0 {
		return out, false // malformed, or more than one signer
	}
	out.sid = si.SID
	out.digestAlg = si.DigestAlg.Algorithm
	out.signedAttrs = si.SignedAttrs
	out.sigAlg = si.SigAlg.Algorithm
	out.signature = si.Signature
	return out, true
}

// checkSignedAttrs verifies the messageDigest attribute equals hash(eContent)
// and the contentType attribute is id-ct-TSTInfo. signedAttrsContent is the
// content (without the [0] header) of the SET OF Attribute.
func checkSignedAttrs(signedAttrsContent []byte, digest crypto.Hash, eContent []byte) (mdOK, ctOK bool) {
	want := hashBytes(digest, eContent)
	b := signedAttrsContent
	for len(b) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		rest, err := asn1.Unmarshal(b, &attr)
		if err != nil {
			return mdOK, ctOK
		}
		b = rest
		switch {
		case attr.Type.Equal(oidMessageDigest):
			var md []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &md); err == nil &&
				subtle.ConstantTimeCompare(md, want) == 1 {
				mdOK = true
			}
		case attr.Type.Equal(oidContentType):
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &oid); err == nil && oid.Equal(oidCTTSTInfo) {
				ctOK = true
			}
		}
	}
	return mdOK, ctOK
}

// findSigner locates the certificate matching a SignerInfo's SignerIdentifier,
// by issuer+serial (SEQUENCE) or by subjectKeyIdentifier ([0] OCTET STRING).
func findSigner(certs []*x509.Certificate, si signerInfoFields) *x509.Certificate {
	// subjectKeyIdentifier form: context [0].
	if si.sid.Class == asn1.ClassContextSpecific && si.sid.Tag == 0 {
		ski := si.sid.Bytes
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && subtle.ConstantTimeCompare(c.SubjectKeyId, ski) == 1 {
				return c
			}
		}
		return nil
	}
	// issuerAndSerialNumber form.
	var ias struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	if _, err := asn1.Unmarshal(si.sid.FullBytes, &ias); err != nil {
		return nil
	}
	for _, c := range certs {
		if c.SerialNumber.Cmp(ias.SerialNumber) == 0 &&
			subtle.ConstantTimeCompare(c.RawIssuer, ias.Issuer.FullBytes) == 1 {
			return c
		}
	}
	return nil
}

// extractTSToken pulls the first RFC 3161 token from a COSE sigTst (V1) or
// sigTst2 (V2) unprotected header, reporting which form it came from.
func extractTSToken(unprotected map[any]any) (der []byte, v2 bool) {
	for _, k := range []struct {
		name string
		v2   bool
	}{{"sigTst", false}, {"sigTst2", true}} {
		tst, ok := unprotected[k.name].(map[any]any)
		if !ok {
			continue
		}
		tokens, ok := tst["tstTokens"].([]any)
		if !ok {
			continue
		}
		for _, tk := range tokens {
			mm, ok := tk.(map[any]any)
			if !ok {
				continue
			}
			if d, ok := mm["val"].([]byte); ok && len(d) > 0 {
				return d, k.v2
			}
		}
	}
	return nil, false
}

// coseParts decodes a COSE_Sign1 (optionally tag 18) into its protected-header
// content bytes and signature bytes.
func coseParts(coseSign1 []byte) (protectedContent, signature []byte, ok bool) {
	raw := coseSign1
	var tag cbor.RawTag
	if err := cbor.Unmarshal(raw, &tag); err == nil && tag.Number == 18 {
		raw = []byte(tag.Content)
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &arr); err != nil || len(arr) != 4 {
		return nil, nil, false
	}
	if err := cbor.Unmarshal(arr[0], &protectedContent); err != nil {
		return nil, nil, false
	}
	if err := cbor.Unmarshal(arr[3], &signature); err != nil {
		return nil, nil, false
	}
	return protectedContent, signature, true
}

// coseCountersignData builds the COSE Sig_structure with the CounterSignature
// context that C2PA timestamps cover: ["CounterSignature", body_protected,
// external_aad (empty), payload].
func coseCountersignData(payload, protectedContent []byte) []byte {
	b, _ := cbor.Marshal([]any{"CounterSignature", protectedContent, []byte{}, payload})
	return b
}

// hashByOID maps a digest-algorithm OID to a hash.Hash.
func hashByOID(oid asn1.ObjectIdentifier) (hash.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256.New(), true
	case oid.Equal(oidSHA384):
		return crypto.SHA384.New(), true
	case oid.Equal(oidSHA512):
		return crypto.SHA512.New(), true
	}
	return nil, false
}

func hashBytes(h crypto.Hash, b []byte) []byte {
	d := h.New()
	d.Write(b)
	return d.Sum(nil)
}

// digestCryptoHash maps a digest OID to crypto.Hash (for checkSignedAttrs).
func digestCryptoHash(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

// x509SigAlg maps a CMS signatureAlgorithm OID (combined with the digest OID
// for the bare rsaEncryption case) to an x509.SignatureAlgorithm.
func x509SigAlg(sigOID, digestOID asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case sigOID.Equal(oidSHA256RSA):
		return x509.SHA256WithRSA
	case sigOID.Equal(oidSHA384RSA):
		return x509.SHA384WithRSA
	case sigOID.Equal(oidSHA512RSA):
		return x509.SHA512WithRSA
	case sigOID.Equal(oidECDSASHA256):
		return x509.ECDSAWithSHA256
	case sigOID.Equal(oidECDSASHA384):
		return x509.ECDSAWithSHA384
	case sigOID.Equal(oidECDSASHA512):
		return x509.ECDSAWithSHA512
	case sigOID.Equal(oidRSAEncryption):
		switch {
		case digestOID.Equal(oidSHA256):
			return x509.SHA256WithRSA
		case digestOID.Equal(oidSHA384):
			return x509.SHA384WithRSA
		case digestOID.Equal(oidSHA512):
			return x509.SHA512WithRSA
		}
	}
	return x509.UnknownSignatureAlgorithm
}
