package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
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
				StatusAssertionHashedURIMatch, StatusAssertionDataHashMatch} {
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
			if !res.Has(StatusAssertionDataHashMismatch) || res.Valid {
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
		{"unsupported container", BMFF, fixtureBytes(t, "video_no_manifest.mp4"), good, ErrUnsupportedContainer},
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
