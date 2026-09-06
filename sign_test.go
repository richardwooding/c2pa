package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/veraison/go-cose"
)

// TestSignRoundTrip is the contract: what Sign writes, Validate trusts, Read
// summarises, and the container's box map sees as exactly one C2PA box.
func TestSignRoundTrip(t *testing.T) {
	s, sc := newTestSigner(t)
	for _, c := range signableContainers {
		t.Run(string(c), func(t *testing.T) {
			in := unsignedInput(t, c)
			out := signBytes(t, s, c, in, createdManifest("round trip"))

			res := Validate(context.Background(), c, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Valid {
				t.Fatalf("expected valid, got %v: %v", codes(res), res.FirstFailure())
			}
			for _, want := range []StatusCode{StatusClaimSignatureValidated, StatusSigningCredentialTrusted,
				StatusAssertionHashedURIMatch, bindingMatch(c)} {
				if !res.Has(want) {
					t.Errorf("missing %s: %v", want, codes(res))
				}
			}
			if res.Info.Title != "round trip" || res.Info.ClaimGenerator != "c2pa-sign-test/1.2" || !res.Info.Present {
				t.Errorf("Info = %+v", res.Info)
			}
			if got := res.VerifiedSigner(); got != "c2pa test signer" {
				t.Errorf("VerifiedSigner = %q", got)
			}
			if info := Read(context.Background(), c, bytes.NewReader(out)); info.Title != "round trip" || info.SignedBy != "c2pa test signer" {
				t.Errorf("Read = %+v", info)
			}
			store, err := ExtractStore(context.Background(), c, bytes.NewReader(out))
			if err != nil || checkStore(store) != nil {
				t.Errorf("ExtractStore did not return the store: %v", err)
			}
			boxes, ok := assetBoxMap(context.Background(), c, out)
			if !ok {
				return // only JPEG, PNG and GIF have a box map
			}
			n := 0
			for _, name := range boxNames(boxes) {
				if name == "C2PA" {
					n++
				}
			}
			if n != 1 {
				t.Errorf("box map names C2PA %d times: %v", n, boxNames(boxes))
			}
		})
	}
}

// TestSignAlgorithms covers every algorithm the profile allows, inferred from
// the key, and pins that alg lands in the PROTECTED header.
func TestSignAlgorithms(t *testing.T) {
	k := testKeys(t)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		key  crypto.Signer
		alg  cose.Algorithm
	}{
		{"ES256", k.ec, cose.AlgorithmES256},
		{"ES384", k.ec384, cose.AlgorithmES384},
		{"ES512", p521, cose.AlgorithmES512},
		{"EdDSA", k.ed, cose.AlgorithmEdDSA},
		{"PS256", k.rsa, cose.AlgorithmPS256},
	}
	in := unsignedJPEG(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := newSigningChainFor(t, tc.key)
			s, err := NewSigner(sc.key, sc.chain)
			if err != nil {
				t.Fatal(err)
			}
			out := signBytes(t, s, JPEG, in, createdManifest(tc.name))
			res := Validate(context.Background(), JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Valid {
				t.Fatalf("expected valid, got %v", codes(res))
			}
			m := parseStore(context.Background(), extractJUMBF(context.Background(), JPEG, out)).active()
			var msg cose.Sign1Message
			if err := msg.UnmarshalCBOR(m.signature); err != nil {
				t.Fatal(err)
			}
			if got, _ := msg.Headers.Protected.Algorithm(); got != tc.alg {
				t.Errorf("protected alg = %v, want %v", got, tc.alg)
			}
			if _, ok := msg.Headers.Protected[cose.HeaderLabelX5Chain]; !ok {
				t.Errorf("x5chain is not in the protected header")
			}
			for k := range msg.Headers.Unprotected {
				if k != "pad" && k != "pad2" {
					t.Errorf("unprotected header carries %v; only padding belongs there", k)
				}
			}
		})
	}
}

// TestSignTamperOutsideStore is the binding at work: a byte changed anywhere
// outside the manifest store is a hash mismatch.
func TestSignTamperOutsideStore(t *testing.T) {
	s, sc := newTestSigner(t)
	for _, c := range signableContainers {
		t.Run(string(c), func(t *testing.T) {
			out := signBytes(t, s, c, unsignedInput(t, c), createdManifest("tamper"))
			tampered := append([]byte(nil), out...)
			tampered[tamperOutsideStore(c, tampered)] ^= 0xFF
			res := Validate(context.Background(), c, bytes.NewReader(tampered), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Has(bindingMismatch(c)) || res.Valid {
				t.Errorf("edit went unnoticed: %v", codes(res))
			}
		})
	}
}

// TestSignResign pins chaining: the prior manifest is carried verbatim, the
// new one is active and names it parentOf, and the ingredient's hash — which
// our validator never checks — is over the prior superbox's content.
func TestSignResign(t *testing.T) {
	s, sc := newTestSigner(t)
	ctx := context.Background()
	for _, c := range signableContainers {
		t.Run(string(c), func(t *testing.T) {
			first := signBytes(t, s, c, unsignedInput(t, c), createdManifest("first"))
			firstStore := parseStore(ctx, extractJUMBF(ctx, c, first))
			firstLabel := firstStore.active().label

			var out bytes.Buffer
			if err := s.Sign(ctx, c, bytes.NewReader(first), &out, createdManifest("again")); !errors.Is(err, ErrManifestInvalid) {
				t.Fatalf("c2pa.created on a signed asset should be refused, got %v", err)
			}
			if out.Len() != 0 {
				t.Fatalf("a refused sign wrote %d bytes", out.Len())
			}
			second := signBytes(t, s, c, first, openedManifest("second"))

			res := Validate(ctx, c, bytes.NewReader(second), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Valid {
				t.Fatalf("expected valid, got %v: %v", codes(res), res.FirstFailure())
			}
			if res.ActiveManifestLabel == firstLabel || res.Info.Title != "second" {
				t.Errorf("active manifest should be the new one: %q title %q", res.ActiveManifestLabel, res.Info.Title)
			}
			if !res.Has(StatusIngredientManifestValidated) {
				t.Errorf("the prior manifest should resolve and validate as the ingredient: %v", codes(res))
			}
			store := extractJUMBF(ctx, c, second)
			ps := parseStore(ctx, store)
			if len(ps.manifests) != 2 || ps.manifests[0].label != firstLabel {
				t.Fatalf("store should hold the prior manifest first: %d manifests", len(ps.manifests))
			}
			var priorFull []byte
			for _, b := range parseBoxTree(ctx, store) {
				for _, m := range b.children {
					if m.label == firstLabel {
						priorFull = m.full
					}
				}
			}
			if !bytes.Contains(extractJUMBF(ctx, c, first), priorFull) {
				t.Errorf("the prior manifest was not carried verbatim")
			}
			// The ingredient hash check our own validator lacks.
			var ing map[string]any
			for _, a := range ps.active().assertions {
				if a.label == "c2pa.ingredient.v3" {
					if err := decMode.Unmarshal(a.data, &ing); err != nil {
						t.Fatal(err)
					}
				}
			}
			ref, _ := ing["activeManifest"].(map[string]any)
			h, _ := hashByName("sha256")
			h.Write(priorFull[8:])
			if got, _ := ref["hash"].([]byte); !bytes.Equal(got, h.Sum(nil)) {
				t.Errorf("ingredient activeManifest.hash is not the hash of the prior superbox payload")
			}
			if ref["url"] != "self#jumbf=/c2pa/"+firstLabel {
				t.Errorf("ingredient url = %v", ref["url"])
			}
			if _, ok := ing["validationResults"].(map[string]any); !ok {
				t.Errorf("ingredient lacks validationResults, which c2pa-rs requires")
			}
		})
	}
}

// TestSignResignFixture chains a manifest c2pa-rs wrote: the fixture's own
// test PKI is untrusted here, so the pool carries both anchors.
func TestSignResignFixture(t *testing.T) {
	s, sc := newTestSigner(t)
	ctx := context.Background()
	pool, fixture := fixtureSigningPool(t)
	pool.AddCert(sc.chain[1])

	var out bytes.Buffer
	if err := s.Sign(ctx, JPEG, bytes.NewReader(fixture), &out, createdManifest("x")); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("created on the signed fixture should be refused, got %v", err)
	}
	second := signBytes(t, s, JPEG, fixture, openedManifest("opened fixture"))
	res := Validate(ctx, JPEG, bytes.NewReader(second), WithSigningTrust(pool),
		WithTimestampTrust(fixtureTimestampPool(t)), WithOnlineRevocation(false))
	if !res.Valid {
		t.Fatalf("expected valid, got %v: %v", codes(res), res.FirstFailure())
	}
	if !res.Has(StatusIngredientManifestValidated) || res.Info.Title != "opened fixture" {
		t.Errorf("chain not recorded: %v %+v", codes(res), res.Info)
	}
	if len(parseStore(ctx, extractJUMBF(ctx, JPEG, second)).manifests) != 2 {
		t.Errorf("store should hold the fixture's manifest and ours")
	}
}

// TestSignOpenedUnsigned: ActionOpened on an asset with no manifest writes a
// minimal parentOf ingredient so the actions assertion stays well-formed.
func TestSignOpenedUnsigned(t *testing.T) {
	s, sc := newTestSigner(t)
	out := signBytes(t, s, PNG, unsignedPNG(t), openedManifest("opened"))
	res := Validate(context.Background(), PNG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Valid || res.Has(StatusIngredientManifestMismatch) {
		t.Fatalf("got %v", codes(res))
	}
}

// TestSignErrors pins every refusal, and that a refused sign writes nothing.
func TestSignErrors(t *testing.T) {
	s, _ := newTestSigner(t)
	ctx := context.Background()
	jpg := unsignedJPEG(t)
	good := createdManifest("ok")
	cases := []struct {
		name      string
		container Container
		in        []byte
		m         Manifest
		want      error
	}{
		{"unsupported container", Container("tga"), jpg, good, ErrUnsupportedContainer},
		{"encrypted pdf", PDF, bytes.Replace(unsignedPDF(false), []byte("/Root 1 0 R"), []byte("/Root 1 0 R /Encrypt 7 0 R"), 1), good, ErrUnsupportedContainer},
		{"pdf without a usable xref", PDF, newPDFDoc().obj(1, "<< /Type /Catalog >>").trailer(1).bytes(), good, ErrUnsupportedContainer},
		{"fragmented mp4", BMFF, fragmentedFlatAsset(t, 2, 1, 1, 1, nil).asset, good, ErrFragmentedBMFF},
		{"mp4 with trailing bytes", BMFF, append(minimalMP4(false), 1, 2, 3), good, ErrMalformedAsset},
		{"no actions", JPEG, jpg, Manifest{Title: "x"}, ErrManifestInvalid},
		{"wrong first action", JPEG, jpg, Manifest{Actions: []Action{{Action: "c2pa.edited"}}}, ErrManifestInvalid},
		{"second inception action", JPEG, jpg, Manifest{Actions: []Action{{Action: ActionCreated}, {Action: ActionOpened}}}, ErrManifestInvalid},
		{"reserved label", JPEG, jpg, Manifest{Actions: good.Actions, Assertions: []Assertion{{Label: "c2pa.hash.data", Value: 1}}}, ErrManifestInvalid},
		{"duplicate label", JPEG, jpg, Manifest{Actions: good.Actions, Assertions: []Assertion{{Label: "com.x", Value: 1}, {Label: "com.x", Value: 2}}}, ErrManifestInvalid},
		{"value and json", JPEG, jpg, Manifest{Actions: good.Actions, Assertions: []Assertion{{Label: "com.x", Value: 1, JSON: []byte(`{}`)}}}, ErrManifestInvalid},
		{"bad json", JPEG, jpg, Manifest{Actions: good.Actions, Assertions: []Assertion{{Label: "com.x", JSON: []byte(`{`)}}}, ErrManifestInvalid},
		{"unencodable value", JPEG, jpg, Manifest{Actions: good.Actions, Assertions: []Assertion{{Label: "com.x", Value: make(chan int)}}}, ErrManifestInvalid},
		{"not a jpeg", JPEG, []byte("hello"), good, ErrMalformedAsset},
		{"png as jpeg", JPEG, unsignedPNG(t), good, ErrMalformedAsset},
		{"empty", PNG, nil, good, ErrMalformedAsset},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := s.Sign(ctx, tc.container, bytes.NewReader(tc.in), &out, tc.m)
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
			if out.Len() != 0 {
				t.Errorf("wrote %d bytes on error", out.Len())
			}
		})
	}
	if err := s.Sign(ctx, JPEG, nil, &bytes.Buffer{}, good); !errors.Is(err, ErrNoInput) {
		t.Errorf("nil reader: %v", err)
	}
	if err := s.Sign(ctx, JPEG, bytes.NewReader(jpg), nil, good); !errors.Is(err, ErrNoInput) {
		t.Errorf("nil writer: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Sign(cancelled, JPEG, bytes.NewReader(jpg), &bytes.Buffer{}, good); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ctx: %v", err)
	}
}

// TestNewSignerRejects pins the chain and key checks: they are the validator's
// own certificate-profile rules, applied before the first asset.
func TestNewSignerRejects(t *testing.T) {
	sc := newSigningChain(t)
	other := newSigningChain(t)
	k := testKeys(t)
	weakRSA := newCorpusSigner(t, cose.AlgorithmPS256) // fine key; used only for its cert shape below
	_ = weakRSA
	cases := []struct {
		name  string
		key   crypto.Signer
		chain []*x509.Certificate
		opts  []SignerOption
		want  error
	}{
		{"nil key", nil, sc.chain, nil, ErrSignerKey},
		{"empty chain", sc.key, nil, nil, ErrSignerChain},
		{"key does not match leaf", other.key, sc.chain, nil, ErrSignerChain},
		{"chain does not link", sc.key, []*x509.Certificate{sc.chain[0], other.chain[1]}, nil, ErrSignerChain},
		{"no EKU", newCorpusSigner(t, cose.AlgorithmES256, certNoEKU()).key, newCorpusSigner(t, cose.AlgorithmES256, certNoEKU()).chain, nil, ErrSignerChain},
		{"any EKU", k.ec, newCorpusSigner(t, cose.AlgorithmES256, certAnyEKU()).chain, nil, ErrSignerChain},
		{"leaf is a CA", k.ec, newCorpusSigner(t, cose.AlgorithmES256, certIsCA()).chain, nil, ErrSignerChain},
		{"expired leaf", k.ec, newCorpusSigner(t, cose.AlgorithmES256, certExpired()).chain, nil, ErrSignerChain},
		{"empty generator", sc.key, sc.chain, []SignerOption{WithClaimGenerator("", "")}, ErrSignerOption},
		{"bad hash", sc.key, sc.chain, []SignerOption{WithHashAlgorithm("sha1")}, ErrSignerOption},
		{"bad vendor", sc.key, sc.chain, []SignerOption{WithVendor("has space")}, ErrSignerOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigner(tc.key, tc.chain, tc.opts...); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
	// Unsupported key sizes and curves.
	if p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader); err == nil {
		if _, err := NewSigner(p224, sc.chain); !errors.Is(err, ErrSignerKey) {
			t.Errorf("P-224: got %v", err)
		}
	}
	// A single self-signed leaf is accepted (it is its own anchor).
	selfKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	selfChain := newSigningChainFor(t, selfKey)
	if _, err := NewSigner(selfKey, selfChain.chain[:1]); err != nil {
		t.Errorf("leaf-only chain (root omitted) should be accepted: %v", err)
	}
	if _, err := NewSigner(sc.key, sc.chain, WithVendor("ACME")); err != nil {
		t.Errorf("vendor: %v", err)
	}
}

// TestSignVendorLabel pins the label form urn:c2pa:<uuid>:<vendor>.
func TestSignVendorLabel(t *testing.T) {
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithVendor("Acme"))
	if err != nil {
		t.Fatal(err)
	}
	out := signBytes(t, s, PNG, unsignedPNG(t), createdManifest("v"))
	res := Validate(context.Background(), PNG, bytes.NewReader(out), WithSigningTrust(sc.roots))
	label := res.ActiveManifestLabel
	if len(label) != len("urn:c2pa:")+36+len(":acme") || label[:9] != "urn:c2pa:" || label[len(label)-5:] != ":acme" {
		t.Errorf("label = %q", label)
	}
}

// TestSignDeterministic: two signs of one input produce stores of equal size
// whose assertion boxes are byte-identical — no random salt, no timestamps —
// so the only differences are the label, the instance ID and the signature.
func TestSignDeterministic(t *testing.T) {
	s, _ := newTestSigner(t)
	ctx := context.Background()
	in := unsignedPNG(t)
	a := signBytes(t, s, PNG, in, createdManifest("det"))
	b := signBytes(t, s, PNG, in, createdManifest("det"))
	if len(a) != len(b) {
		t.Fatalf("sizes differ: %d vs %d", len(a), len(b))
	}
	ma := parseStore(ctx, extractJUMBF(ctx, PNG, a)).active()
	mb := parseStore(ctx, extractJUMBF(ctx, PNG, b)).active()
	if len(ma.assertions) != len(mb.assertions) {
		t.Fatal("assertion counts differ")
	}
	for i := range ma.assertions {
		if !bytes.Equal(ma.assertions[i].boxContent, mb.assertions[i].boxContent) {
			t.Errorf("assertion %s differs between two signs", ma.assertions[i].label)
		}
	}
	if ma.label == mb.label {
		t.Errorf("labels should be fresh per sign")
	}
}

// TestCOSEPadExact sweeps the reserve so every CBOR width boundary is crossed:
// the envelope must land on the exact size and still verify.
func TestCOSEPadExact(t *testing.T) {
	sc := newSigningChain(t)
	claim := []byte("claim bytes")
	msg, err := newSign1(rand.Reader, sc.key, cose.AlgorithmES256, [][]byte{sc.chain[0].Raw}, claim)
	if err != nil {
		t.Fatal(err)
	}
	base, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, sc.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := marshalSign1Padded(msg, len(base)-1); err == nil {
		t.Errorf("a reserve below the envelope must be an error, never a truncation")
	}
	// A "pad" entry is at least 5 bytes, so 1..4 bytes of slack cannot be
	// filled; the reserve is 1024 bytes over the fixed parts, so the pipeline
	// never asks for that. It must still be an error, not a wrong size.
	for need := 1; need < 5; need++ {
		if out, err := marshalSign1Padded(msg, len(base)+need); err == nil {
			t.Errorf("need %d: padded to %d bytes, which should be impossible", need, len(out))
		}
	}
	for need := 5; need < 700; need++ {
		out, err := marshalSign1Padded(msg, len(base)+need)
		if err != nil {
			t.Fatalf("need %d: %v", need, err)
		}
		if len(out) != len(base)+need {
			t.Fatalf("need %d: got %d bytes", need, len(out))
		}
		if need%97 == 0 {
			var m cose.Sign1Message
			if err := m.UnmarshalCBOR(out); err != nil {
				t.Fatalf("need %d: %v", need, err)
			}
			m.Payload = claim
			if err := m.Verify(nil, verifier); err != nil {
				t.Fatalf("need %d: padded envelope no longer verifies: %v", need, err)
			}
		}
	}
	for _, need := range []int{65536 + 3, 65536 + 9, 70000} {
		if out, err := marshalSign1Padded(msg, len(base)+need); err != nil || len(out) != len(base)+need {
			t.Errorf("need %d: %v (%d bytes)", need, err, len(out))
		}
	}
}

// messageOnlySigner is a key that can only sign whole messages, the way
// WebCrypto's SubtleCrypto.sign and some HSM APIs can: Sign refuses a digest
// and counts the attempt, SignMessage hashes per opts and signs with the
// in-memory key. It stands in for the browser key c2pa-inspector wraps.
type messageOnlySigner struct {
	key       crypto.Signer
	signCalls int
}

func (m *messageOnlySigner) Public() crypto.PublicKey { return m.key.Public() }

func (m *messageOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	m.signCalls++
	return nil, errors.New("messageOnlySigner: digest signing is not available")
}

func (m *messageOnlySigner) SignMessage(rnd io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("messageOnlySigner: nil opts")
	}
	if opts.HashFunc() == 0 {
		return m.key.Sign(rnd, msg, opts) // Ed25519 signs the message itself
	}
	h := opts.HashFunc().New()
	h.Write(msg)
	return m.key.Sign(rnd, h.Sum(nil), opts)
}

// TestSignMessageSigner: a crypto.MessageSigner key signs through the
// Sig_structure path for every algorithm, its Sign is never called, and the
// envelope is the size the crypto.Signer path reserves.
func TestSignMessageSigner(t *testing.T) {
	ec256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		key  crypto.Signer
		alg  cose.Algorithm
	}{
		{"ES256", ec256, cose.AlgorithmES256},
		{"ES384", ec384, cose.AlgorithmES384},
		{"PS256", rsaKey, cose.AlgorithmPS256},
		{"EdDSA", edKey, cose.AlgorithmEdDSA},
	}
	in := unsignedJPEG(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := newSigningChainFor(t, tc.key)
			ms := &messageOnlySigner{key: tc.key}
			s, err := NewSigner(ms, sc.chain)
			if err != nil {
				t.Fatal(err)
			}
			out := signBytes(t, s, JPEG, in, createdManifest(tc.name))
			res := Validate(context.Background(), JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Valid {
				t.Fatalf("expected valid, got %v", codes(res))
			}
			if ms.signCalls != 0 {
				t.Errorf("Sign was called %d times; a message signer must only see SignMessage", ms.signCalls)
			}
			m := parseStore(context.Background(), extractJUMBF(context.Background(), JPEG, out)).active()
			var msg cose.Sign1Message
			if err := msg.UnmarshalCBOR(m.signature); err != nil {
				t.Fatal(err)
			}
			if got, _ := msg.Headers.Protected.Algorithm(); got != tc.alg {
				t.Errorf("protected alg = %v, want %v", got, tc.alg)
			}
			ref, err := NewSigner(tc.key, sc.chain)
			if err != nil {
				t.Fatal(err)
			}
			if refOut := signBytes(t, ref, JPEG, in, createdManifest(tc.name)); len(refOut) != len(out) {
				t.Errorf("message-signer output is %d bytes, crypto.Signer output %d; the reserve must not depend on the signer kind", len(out), len(refOut))
			}
		})
	}
}

// TestECDSARawFromDER pins the DER → r‖s conversion against Go's own
// signatures, including ones whose integers need a leading-zero pad, and
// refuses malformed input rather than emitting a short signature.
func TestECDSARawFromDER(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		n := (curve.Params().BitSize + 7) / 8
		digest := make([]byte, 32)
		for i := range 64 {
			digest[0] = byte(i)
			der, err := ecdsa.SignASN1(rand.Reader, key, digest)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := ecdsaRawFromDER(der, curve)
			if err != nil {
				t.Fatalf("%s: %v", curve.Params().Name, err)
			}
			if len(raw) != 2*n {
				t.Fatalf("%s: raw length %d, want %d", curve.Params().Name, len(raw), 2*n)
			}
			r, s := new(big.Int).SetBytes(raw[:n]), new(big.Int).SetBytes(raw[n:])
			if !ecdsa.Verify(&key.PublicKey, digest, r, s) {
				t.Fatalf("%s: converted signature does not verify", curve.Params().Name)
			}
		}
	}
	for name, der := range map[string][]byte{
		"empty":        nil,
		"not sequence": {0x02, 0x01, 0x01},
		"trailing":     append(mustSignASN1(t), 0x00),
		"zero r":       {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01},
		"oversized":    {0x30, 0x25, 0x02, 0x21, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x01, 0x01},
	} {
		if _, err := ecdsaRawFromDER(der, elliptic.P256()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustSignASN1(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ecdsa.SignASN1(rand.Reader, key, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// largeUnsignedPDF is a minimal PDF whose one stream is padding bytes long, so
// a store appended by Sign lands past Read's triage cap.
func largeUnsignedPDF(padding int) []byte {
	var b bytes.Buffer
	offsets := make([]int, 5)
	b.WriteString("%PDF-1.4\n")
	obj := func(n int, body string) {
		offsets[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Contents 4 0 R >>")
	offsets[4] = b.Len()
	fmt.Fprintf(&b, "4 0 obj\n<< /Length %d >>\nstream\n", padding)
	b.Write(bytes.Repeat([]byte{' '}, padding))
	b.WriteString("\nendstream\nendobj\n")
	xref := b.Len()
	b.WriteString("xref\n0 5\n0000000000 65535 f \n")
	for _, off := range offsets[1:] {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
	return b.Bytes()
}

// TestExtractStore_PastReadCap: ExtractStore finds a store Validate would
// find, even past Read's 16 MiB triage cap — the primitive a signer uses to
// decide created/opened, and a viewer uses to show the manifest.
func TestExtractStore_PastReadCap(t *testing.T) {
	s, sc := newTestSigner(t)
	ctx := context.Background()
	signed := signBytes(t, s, PDF, largeUnsignedPDF(MaxScan+4096), createdManifest("big"))
	if Read(ctx, PDF, bytes.NewReader(signed)).Present {
		t.Fatal("Read saw a store past its cap; the test asset is not large enough")
	}
	store, err := ExtractStore(ctx, PDF, bytes.NewReader(signed))
	if err != nil || len(store) == 0 {
		t.Fatalf("ExtractStore = %d bytes, %v; want the store past MaxScan", len(store), err)
	}
	res := Validate(ctx, PDF, bytes.NewReader(signed), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Valid {
		t.Fatalf("Validate: %v", codes(res))
	}
	// And Sign chains rather than refusing: it sees the same store.
	out := signBytes(t, s, PDF, signed, openedManifest("bigger"))
	if !Validate(ctx, PDF, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false)).Has(StatusIngredientManifestValidated) {
		t.Fatal("re-sign of the large PDF did not chain the prior manifest")
	}
}
