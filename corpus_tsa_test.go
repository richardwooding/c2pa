package c2pa

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// A test-only RFC 3161 / CMS writer, the exact inverse of timestamp.go's
// reader. There is no CMS library here on purpose (CLAUDE.md rejects adding
// one), so this hand-emits the structures parseCMSSignedData, parseTSTInfo,
// parseSignerInfo and checkSignedAttrs consume.
//
// The binding rule is not reimplemented: callers pass tbs, produced by the
// package's own coseParts + coseCountersignData, so a generated token cannot
// drift from what the validator computes.

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSAPolicy  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidSHA1Digest = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

type tsAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tsMessageImprint struct {
	Alg    tsAlgID
	Hashed []byte
}

type tsTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tsMessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
}

type tsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type tsIssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type tsSignerInfo struct {
	Version     int
	SID         asn1.RawValue
	DigestAlg   tsAlgID
	SignedAttrs asn1.RawValue `asn1:"optional,tag:0"`
	SigAlg      tsAlgID
	Signature   []byte
}

type tsEncapContentInfo struct {
	OID     asn1.ObjectIdentifier
	Content []byte `asn1:"explicit,optional,tag:0"`
}

type tsSignedData struct {
	Version     int
	DigestAlgos []tsAlgID `asn1:"set"`
	Encap       tsEncapContentInfo
	Certs       asn1.RawValue  `asn1:"optional,tag:0"`
	SignerInfos []tsSignerInfo `asn1:"set"`
}

type tsContentInfo struct {
	OID     asn1.ObjectIdentifier
	Content tsSignedData `asn1:"explicit,tag:0"`
}

type tsPKIStatusInfo struct {
	Status int
}

type tsTimeStampResp struct {
	Status tsPKIStatusInfo
	Token  asn1.RawValue
}

// testTSA is a generated timestamp authority: a self-signed root and a leaf
// carrying id-kp-timeStamping, which is all verifyTSAChain requires (it does
// not apply the C2PA cert profile to the TSA chain).
//
// It signs with RSA PKCS#1 v1.5 rather than ECDSA, and that is load-bearing
// rather than a preference: an ECDSA DER signature is a SEQUENCE{r,s} whose
// length varies with the leading bits of r and s, so a freshly minted token
// changes size between build passes and buildAsset's exclusion fixpoint never
// settles. PKCS#1 v1.5 is both fixed-length and deterministic, so the whole
// token is byte-identical across passes. It also reuses the shared RSA keys,
// so adding a TSA costs no key generation at all.
type testTSA struct {
	leaf    *x509.Certificate
	root    *x509.Certificate
	key     crypto.Signer
	certDER []byte
}

func (ta *testTSA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ta.root)
	return p
}

type tsaOpt func(*tsaProfile)

type tsaProfile struct {
	notBefore time.Time
	notAfter  time.Time
	ekus      []x509.ExtKeyUsage
}

// tsaAnyEKU is the only way to reach timestampEKUOK's rejection: a leaf simply
// lacking id-kp-timeStamping fails inside x509.Verify first, which reports
// timeStamp.untrusted before the EKU check ever runs.
func tsaAnyEKU() tsaOpt {
	return func(p *tsaProfile) { p.ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }
}

func tsaValidity(notBefore, notAfter time.Time) tsaOpt {
	return func(p *tsaProfile) { p.notBefore, p.notAfter = notBefore, notAfter }
}

func newTestTSA(t testing.TB, opts ...tsaOpt) *testTSA {
	t.Helper()
	p := &tsaProfile{
		notBefore: corpusEpoch.Add(-30 * 24 * time.Hour),
		notAfter:  corpusEpoch.Add(365 * 24 * time.Hour),
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	for _, o := range opts {
		o(p)
	}

	k := testKeys(t)
	rootKey := k.rsaCA
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "c2pa corpus TSA root"},
		NotBefore:             p.notBefore,
		NotAfter:              p.notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("tsa root cert: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse tsa root: %v", err)
	}

	leafKey := k.rsa
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "c2pa corpus TSA"},
		NotBefore:             p.notBefore,
		NotAfter:              p.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           p.ekus,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{0xC0, 0x11, 0xEC, 0x7E, 0xD0, 0x01},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("tsa leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse tsa leaf: %v", err)
	}

	return &testTSA{
		leaf:    leaf,
		root:    root,
		key:     leafKey,
		certDER: append(append([]byte{}, leafDER...), rootDER...),
	}
}

type tsTokenOpt func(*tsTokenProfile)

type tsTokenProfile struct {
	genTime          time.Time
	wrapInResp       bool
	imprintOverride  []byte
	imprintAlgSHA1   bool
	omitSignedAttrs  bool
	universalAttrs   bool
	badMessageDigest bool
	badContentType   bool
	corruptSignature bool
	useSKI           bool
	omitCerts        bool
	twoSigners       bool
}

func tsWrapInResp() tsTokenOpt { return func(p *tsTokenProfile) { p.wrapInResp = true } }
func tsGenTime(t time.Time) tsTokenOpt {
	return func(p *tsTokenProfile) { p.genTime = t }
}
func tsWrongImprint() tsTokenOpt {
	return func(p *tsTokenProfile) { p.imprintOverride = []byte("nope") }
}
func tsSHA1Imprint() tsTokenOpt     { return func(p *tsTokenProfile) { p.imprintAlgSHA1 = true } }
func tsOmitSignedAttrs() tsTokenOpt { return func(p *tsTokenProfile) { p.omitSignedAttrs = true } }
func tsUniversalAttrs() tsTokenOpt  { return func(p *tsTokenProfile) { p.universalAttrs = true } }
func tsBadMessageDigest() tsTokenOpt {
	return func(p *tsTokenProfile) { p.badMessageDigest = true }
}
func tsBadContentType() tsTokenOpt   { return func(p *tsTokenProfile) { p.badContentType = true } }
func tsCorruptSignature() tsTokenOpt { return func(p *tsTokenProfile) { p.corruptSignature = true } }
func tsSubjectKeyID() tsTokenOpt     { return func(p *tsTokenProfile) { p.useSKI = true } }
func tsOmitCerts() tsTokenOpt        { return func(p *tsTokenProfile) { p.omitCerts = true } }
func tsTwoSigners() tsTokenOpt       { return func(p *tsTokenProfile) { p.twoSigners = true } }

func derSet(valueTLV []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valueTLV}
}

func mustDER(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1 marshal: %v", err)
	}
	return b
}

// mintTSToken builds an RFC 3161 token whose messageImprint covers tbs. tbs
// must come from coseCountersignData so the token binds to the signature the
// validator will recompute.
func mintTSToken(t testing.TB, ta *testTSA, tbs []byte, opts ...tsTokenOpt) []byte {
	t.Helper()
	p := &tsTokenProfile{genTime: corpusEpoch}
	for _, o := range opts {
		o(p)
	}

	imprintAlg := oidSHA256
	if p.imprintAlgSHA1 {
		imprintAlg = oidSHA1Digest
	}
	imprint := hashBytes(crypto.SHA256, tbs)
	if p.imprintOverride != nil {
		imprint = hashBytes(crypto.SHA256, p.imprintOverride)
	}

	eContent := mustDER(t, tsTSTInfo{
		Version: 1,
		Policy:  oidTSAPolicy,
		MessageImprint: tsMessageImprint{
			Alg:    tsAlgID{Algorithm: imprintAlg, Parameters: asn1.NullRawValue},
			Hashed: imprint,
		},
		SerialNumber: big.NewInt(42),
		GenTime:      p.genTime.UTC().Truncate(time.Second),
	})

	digestContent := eContent
	if p.badMessageDigest {
		digestContent = append(append([]byte{}, eContent...), 0x00)
	}
	ctOID := oidCTTSTInfo
	if p.badContentType {
		ctOID = oidSignedData
	}

	attrs := []tsAttribute{
		{Type: oidContentType, Values: derSet(mustDER(t, ctOID))},
		{Type: oidMessageDigest, Values: derSet(mustDER(t, hashBytes(crypto.SHA256, digestContent)))},
	}

	signedAttrsUniversal, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		t.Fatalf("marshal signedAttrs: %v", err)
	}

	// The signature covers the attributes as a universal SET (0x31); the wire
	// form is [0] IMPLICIT (0xA0) with identical length octets. Emitting the
	// universal tag instead is what tsUniversalAttrs reproduces.
	sigInput := signedAttrsUniversal
	wireAttrs := append([]byte{}, signedAttrsUniversal...)
	if !p.universalAttrs {
		wireAttrs[0] = 0xA0
	}

	sig, err := ta.key.Sign(rand.Reader, hashBytes(crypto.SHA256, sigInput), crypto.SHA256)
	if err != nil {
		t.Fatalf("tsa sign: %v", err)
	}
	if p.corruptSignature {
		sig[len(sig)-1] ^= 0xFF
	}

	sid := asn1.RawValue{FullBytes: mustDER(t, tsIssuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: ta.leaf.RawIssuer},
		SerialNumber: ta.leaf.SerialNumber,
	})}
	version := 1
	if p.useSKI {
		sid = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: false, Bytes: ta.leaf.SubjectKeyId}
		version = 3
	}

	si := tsSignerInfo{
		Version:     version,
		SID:         sid,
		DigestAlg:   tsAlgID{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
		SignedAttrs: asn1.RawValue{FullBytes: wireAttrs},
		SigAlg:      tsAlgID{Algorithm: oidSHA256RSA, Parameters: asn1.NullRawValue},
		Signature:   sig,
	}
	if p.omitSignedAttrs {
		si.SignedAttrs = asn1.RawValue{}
	}

	signers := []tsSignerInfo{si}
	if p.twoSigners {
		signers = append(signers, si)
	}

	sd := tsSignedData{
		Version:     3,
		DigestAlgos: []tsAlgID{{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}},
		Encap:       tsEncapContentInfo{OID: oidCTTSTInfo, Content: eContent},
		SignerInfos: signers,
	}
	if !p.omitCerts {
		sd.Certs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: ta.certDER}
	}

	contentInfo := mustDER(t, tsContentInfo{OID: oidSignedData, Content: sd})
	if !p.wrapInResp {
		return contentInfo
	}
	return mustDER(t, tsTimeStampResp{
		Status: tsPKIStatusInfo{Status: 0},
		Token:  asn1.RawValue{FullBytes: contentInfo},
	})
}

// tstHeader is the COSE unprotected-header container extractTSToken walks.
func tstHeader(der []byte) map[any]any {
	return map[any]any{"tstTokens": []any{map[any]any{"val": der}}}
}
