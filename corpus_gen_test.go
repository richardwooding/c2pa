package c2pa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// corpusEpoch is the pinned wall clock for every generated case; certificates
// and clocks are anchored here so results never depend on the run date.
var corpusEpoch = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func jumbfUUID(tag string) [16]byte {
	var u [16]byte
	copy(u[:], tag)
	copy(u[4:], []byte{0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71})
	return u
}

var (
	uuidC2PA = jumbfUUID("c2pa")
	uuidCBOR = jumbfUUID("cbor")
	uuidJSON = jumbfUUID("json")
)

func boxHeader(size int, tbox string) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint32(h[:4], uint32(size))
	copy(h[4:], tbox)
	return h
}

func leafBox(tbox string, payload []byte) []byte {
	return append(boxHeader(8+len(payload), tbox), payload...)
}

// jumdBox emits the description box. Toggles bit 1 (0x02) is what makes the
// parser read the label at all; without it the box is anonymous.
func jumdBox(typeUUID [16]byte, label string) []byte {
	payload := make([]byte, 0, 17+len(label)+1)
	payload = append(payload, typeUUID[:]...)
	payload = append(payload, 0x03)
	payload = append(payload, label...)
	payload = append(payload, 0x00)
	return leafBox("jumd", payload)
}

func superBox(typeUUID [16]byte, label string, children ...[]byte) []byte {
	content := jumdBox(typeUUID, label)
	for _, c := range children {
		content = append(content, c...)
	}
	return append(boxHeader(8+len(content), "jumb"), content...)
}

func assertionBox(label string, payload []byte) []byte {
	return superBox(uuidCBOR, label, leafBox("cbor", payload))
}

func jsonAssertionBox(label string, payload []byte) []byte {
	return superBox(uuidJSON, label, leafBox("json", payload))
}

// corpusKeys are minted once per run: RSA-2048 generation is the single
// expensive operation in the corpus and must not repeat per case.
type corpusKeys struct {
	ec     *ecdsa.PrivateKey
	ec384  *ecdsa.PrivateKey
	ed     ed25519.PrivateKey
	rsa    *rsa.PrivateKey
	rsaCA  *rsa.PrivateKey
	weakEC *ecdsa.PrivateKey
}

var (
	keysOnce sync.Once
	keys     *corpusKeys
	keysErr  error
)

func testKeys(t testing.TB) *corpusKeys {
	t.Helper()
	keysOnce.Do(func() {
		k := &corpusKeys{}
		if k.ec, keysErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); keysErr != nil {
			return
		}
		if k.ec384, keysErr = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); keysErr != nil {
			return
		}
		if _, k.ed, keysErr = ed25519.GenerateKey(rand.Reader); keysErr != nil {
			return
		}
		if k.rsa, keysErr = rsa.GenerateKey(rand.Reader, 2048); keysErr != nil {
			return
		}
		if k.rsaCA, keysErr = rsa.GenerateKey(rand.Reader, 2048); keysErr != nil {
			return
		}
		if k.weakEC, keysErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); keysErr != nil {
			return
		}
		keys = k
	})
	if keysErr != nil {
		t.Fatalf("generate corpus keys: %v", keysErr)
	}
	return keys
}

type certProfile struct {
	notBefore  time.Time
	notAfter   time.Time
	keyUsage   x509.KeyUsage
	ekus       []x509.ExtKeyUsage
	isCA       bool
	ocspURL    string
	caSigAlg   x509.SignatureAlgorithm
	omitKeyUse bool
}

type certOpt func(*certProfile)

func certExpired() certOpt {
	return func(p *certProfile) {
		p.notBefore = corpusEpoch.Add(-2 * 365 * 24 * time.Hour)
		p.notAfter = corpusEpoch.Add(-365 * 24 * time.Hour)
	}
}

func certNoDigitalSignature() certOpt {
	return func(p *certProfile) { p.keyUsage = x509.KeyUsageKeyEncipherment; p.omitKeyUse = false }
}

func certAnyEKU() certOpt {
	return func(p *certProfile) { p.ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }
}

func certNoEKU() certOpt {
	return func(p *certProfile) { p.ekus = nil }
}

func certIsCA() certOpt {
	return func(p *certProfile) { p.isCA = true }
}

// certSHA1 weakens the root's self-signature only. A SHA-1 leaf is rejected by
// x509.Verify itself and surfaces as signingCredential.untrusted, so it never
// reaches chain.go's weakSigAlg check; Go does not re-verify a root's own
// self-signature, so this is the path that does.
func certSHA1() certOpt {
	return func(p *certProfile) { p.caSigAlg = x509.SHA1WithRSA }
}

func defaultCertProfile() *certProfile {
	return &certProfile{
		notBefore: corpusEpoch.Add(-24 * time.Hour),
		notAfter:  corpusEpoch.Add(365 * 24 * time.Hour),
		keyUsage:  x509.KeyUsageDigitalSignature,
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
}

type signerBundle struct {
	chain  []*x509.Certificate
	roots  *x509.CertPool
	key    crypto.Signer
	alg    cose.Algorithm
	chainD [][]byte
}

func newCorpusCA(t testing.TB, key *rsa.PrivateKey, sigAlg x509.SignatureAlgorithm) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "c2pa corpus root"},
		NotBefore:             corpusEpoch.Add(-30 * 24 * time.Hour),
		NotAfter:              corpusEpoch.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create corpus CA: %v", err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse corpus CA: %v", err)
	}
	return crt, key
}

func newCorpusSigner(t testing.TB, alg cose.Algorithm, opts ...certOpt) *signerBundle {
	t.Helper()
	k := testKeys(t)

	var pub any
	var key crypto.Signer
	switch alg {
	case cose.AlgorithmES256:
		pub, key = &k.ec.PublicKey, k.ec
	case cose.AlgorithmES384:
		pub, key = &k.ec384.PublicKey, k.ec384
	case cose.AlgorithmEdDSA:
		pub, key = k.ed.Public(), k.ed
	case cose.AlgorithmPS256:
		pub, key = &k.rsa.PublicKey, k.rsa
	default:
		t.Fatalf("unsupported corpus algorithm %v", alg)
	}

	p := defaultCertProfile()
	for _, o := range opts {
		o(p)
	}

	caSigAlg := x509.SHA256WithRSA
	if p.caSigAlg != 0 {
		caSigAlg = p.caSigAlg
	}
	ca, caKey := newCorpusCA(t, k.rsaCA, caSigAlg)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "c2pa corpus signer"},
		NotBefore:             p.notBefore,
		NotAfter:              p.notAfter,
		KeyUsage:              p.keyUsage,
		ExtKeyUsage:           p.ekus,
		BasicConstraintsValid: true,
		IsCA:                  p.isCA,
	}
	if p.isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if p.ocspURL != "" {
		tmpl.OCSPServer = []string{p.ocspURL}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatalf("create corpus leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse corpus leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	return &signerBundle{
		chain:  []*x509.Certificate{leaf, ca},
		roots:  roots,
		key:    key,
		alg:    alg,
		chainD: [][]byte{leaf.Raw, ca.Raw},
	}
}

type manifestSpec struct {
	label         string
	claimV2       bool
	signer        *signerBundle
	assertions    []assertionSpec
	claimExtra    map[string]any
	emptyClaim    bool
	omitSig       bool
	omitX5Chain   bool
	corruptSig    bool
	forceAlg      cose.Algorithm
	attachPayload []byte
	attachSelf    bool
	dataHashAlg   string
	noHardBinding bool
	extraBinding  *assertionSpec
}

type assertionSpec struct {
	label string
	value any
	json  bool
	raw   []byte
}

func mustMarshalCBOR(t testing.TB, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("marshal cbor: %v", err)
	}
	return b
}

func hashOf(t testing.TB, alg string, b []byte) []byte {
	t.Helper()
	h, ok := hashByName(alg)
	if !ok {
		t.Fatalf("unsupported hash %q", alg)
	}
	h.Write(b)
	return h.Sum(nil)
}

// buildManifest assembles assertions, then the claim that hashes them, then the
// COSE signature over that claim — the same dependency order the validator
// unwinds in reverse.
func buildManifest(t testing.TB, spec manifestSpec) []byte {
	t.Helper()
	alg := spec.dataHashAlg
	if alg == "" {
		alg = "sha256"
	}

	var assertionBoxes [][]byte
	var claimEntries []any
	for _, a := range spec.assertions {
		payload := a.raw
		if payload == nil {
			payload = mustMarshalCBOR(t, a.value)
		}
		var bx []byte
		if a.json {
			bx = jsonAssertionBox(a.label, payload)
		} else {
			bx = assertionBox(a.label, payload)
		}
		assertionBoxes = append(assertionBoxes, bx)
		claimEntries = append(claimEntries, map[string]any{
			"url":  "self#jumbf=c2pa.assertions/" + a.label,
			"hash": hashOf(t, alg, bx[8:]),
		})
	}

	claimLabel := "c2pa.claim"
	if spec.claimV2 {
		claimLabel = "c2pa.claim.v2"
	}

	claim := map[string]any{
		"alg":        alg,
		"signature":  "self#jumbf=c2pa.signature",
		"assertions": claimEntries,
		"dc:title":   "corpus.jpg",
		"dc:format":  "image/jpeg",
		"instanceID": "xmp:iid:corpus-0001",
	}
	if spec.claimV2 {
		claim["claim_generator_info"] = map[string]any{"name": "c2pa-corpus", "version": "1.0"}
	} else {
		claim["claim_generator"] = "c2pa-corpus/1.0"
	}
	for k, v := range spec.claimExtra {
		claim[k] = v
	}

	claimBytes := mustMarshalCBOR(t, claim)

	children := [][]byte{superBox(uuidC2PA, "c2pa.assertions", assertionBoxes...)}
	if spec.emptyClaim {
		children = append(children, superBox(uuidCBOR, claimLabel))
	} else {
		children = append(children, superBox(uuidCBOR, claimLabel, leafBox("cbor", claimBytes)))
	}
	if !spec.omitSig {
		sig := signClaim(t, spec, claimBytes)
		children = append(children, superBox(uuidCBOR, "c2pa.signature", leafBox("cbor", sig)))
	}

	label := spec.label
	if label == "" {
		label = "urn:uuid:00000000-0000-4000-8000-000000000001"
	}
	return superBox(uuidC2PA, label, children...)
}

func signClaim(t testing.TB, spec manifestSpec, claimBytes []byte) []byte {
	t.Helper()
	sb := spec.signer
	signer, err := cose.NewSigner(sb.alg, sb.key)
	if err != nil {
		t.Fatalf("cose signer: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = sb.alg
	if !spec.omitX5Chain {
		msg.Headers.Unprotected["x5chain"] = sb.chainD
	}
	msg.Payload = claimBytes
	if spec.attachPayload != nil {
		msg.Payload = spec.attachPayload
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("cose sign: %v", err)
	}
	if spec.corruptSig {
		msg.Signature[0] ^= 0xFF
	}
	if spec.forceAlg != 0 {
		msg.Headers.Protected[cose.HeaderLabelAlgorithm] = spec.forceAlg
	}
	if spec.attachPayload == nil && !spec.attachSelf {
		msg.Payload = nil
	}
	b, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	return b
}

func storeBox(manifests ...[]byte) []byte {
	return superBox(uuidC2PA, "c2pa", manifests...)
}
