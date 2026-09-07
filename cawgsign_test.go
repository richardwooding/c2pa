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
	"errors"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// identityTestSigner is a Signer with a distinct identity key and chain.
func identityTestSigner(t testing.TB, idKey crypto.Signer, opts ...SignerOption) (*Signer, signingChain, signingChain) {
	t.Helper()
	if idKey == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		idKey = k
	}
	idChain := newSigningChainFor(t, idKey)
	s, sc := newTestSigner(t, append([]SignerOption{WithIdentitySigner(idChain.key, idChain.chain)}, opts...)...)
	return s, sc, idChain
}

// identityManifest is createdManifest plus an identity that vouches for the
// actions too, as a creator.
func identityManifest(title string) Manifest {
	m := createdManifest(title)
	m.Identity = IdentityInfo{Roles: []string{RoleCreator}, References: []string{"c2pa.actions.v2"}}
	return m
}

// validateSigned runs Validate with both roots anchored.
func validateSigned(t testing.TB, c Container, out []byte, sc, idChain signingChain, extra ...ValidateOption) ValidationResult {
	t.Helper()
	opts := append([]ValidateOption{WithSigningTrust(sc.roots), WithIdentityTrust(idChain.roots), WithOnlineRevocation(false)}, extra...)
	return Validate(context.Background(), c, bytes.NewReader(out), opts...)
}

func TestSignIdentityRoundTrip(t *testing.T) {
	s, sc, idChain := identityTestSigner(t, nil)
	for _, c := range signableContainers {
		t.Run(string(c), func(t *testing.T) {
			out := signBytes(t, s, c, unsignedInput(t, c), identityManifest("identity "+string(c)))
			res := validateSigned(t, c, out, sc, idChain)
			if !res.Valid || !res.Has(bindingMatch(c)) {
				t.Fatalf("valid=%v %v", res.Valid, codes(res))
			}
			if len(res.Identities) != 1 {
				t.Fatalf("identities = %d", len(res.Identities))
			}
			id := res.Identities[0]
			if !id.Valid || !id.Trusted || id.Name() != "c2pa test signer" || id.SigType != identitySigTypeX509 {
				t.Errorf("identity = %+v name %q", id, id.Name())
			}
			if !equalStrings(id.Roles, []string{RoleCreator}) || !equalStrings(id.Referenced, []string{bindingLabelFor(c), "c2pa.actions.v2"}) {
				t.Errorf("roles %v referenced %v", id.Roles, id.Referenced)
			}
			if !hasAt(res, StatusIdentityTrusted, res.ActiveManifestLabel+"/cawg.identity") {
				t.Errorf("no cawg.identity.trusted: %v", codes(res))
			}
			// The claim's own verdict stands on its own.
			if res.VerifiedSigner() != "c2pa test signer" {
				t.Errorf("VerifiedSigner = %q", res.VerifiedSigner())
			}
			// Without identity anchors: genuine but unproven.
			res = Validate(context.Background(), c, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if !res.Valid || len(res.Identities) != 1 || !res.Identities[0].Valid || res.Identities[0].Trusted || res.Identities[0].Name() != "" {
				t.Errorf("unanchored: valid=%v %+v", res.Valid, res.Identities)
			}
		})
	}
}

func bindingLabelFor(c Container) string {
	if c == BMFF {
		return "c2pa.hash.bmff.v3"
	}
	return "c2pa.hash.data"
}

// TestSignIdentityClaimShape: the identity is a gathered assertion, last in the
// store, its references are the claim's own entries byte for byte, its payload
// is in c2pa-rs's field order, and pad1 is present and empty.
func TestSignIdentityClaimShape(t *testing.T) {
	s, _, _ := identityTestSigner(t, nil)
	out := signBytes(t, s, JPEG, unsignedJPEG(t), identityManifest("shape"))
	ctx := context.Background()
	store, err := ExtractStore(ctx, JPEG, bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	m := parseStore(ctx, store).active()
	if m == nil {
		t.Fatal("no manifest")
	}
	last := m.assertions[len(m.assertions)-1]
	if last.label != identityLabel {
		t.Fatalf("last assertion is %q, want the identity", last.label)
	}
	created, _ := m.claim["created_assertions"].([]any)
	gathered, _ := m.claim["gathered_assertions"].([]any)
	if len(gathered) != 1 || len(created) != 2 {
		t.Fatalf("created %d gathered %d", len(created), len(gathered))
	}
	g, _ := gathered[0].(map[string]any)
	if g["url"] != assertionURL(identityLabel) {
		t.Errorf("gathered entry = %v", g)
	}
	for _, e := range created {
		if em, _ := e.(map[string]any); em["url"] == assertionURL(identityLabel) {
			t.Errorf("identity must not be a created assertion")
		}
	}

	ia, sp, unevaluated, err := decodeIdentityAssertion(last.data)
	if err != nil || len(unevaluated) != 0 {
		t.Fatalf("decode: %v %v", err, unevaluated)
	}
	if len(ia.Pad1) != 0 || ia.Pad2 != nil {
		t.Errorf("pads: pad1 %d bytes, pad2 present %v; want empty pad1 and no pad2", len(ia.Pad1), ia.Pad2 != nil)
	}
	// Field order: the payload's first key is referenced_assertions, then
	// sig_type, then role — what c2pa-rs re-serialises before verifying.
	var keys []string
	var raw map[string]cbor.RawMessage
	if err := identityDecMode.Unmarshal(ia.SignerPayload, &raw); err != nil {
		t.Fatal(err)
	}
	pos := func(k string) int { return bytes.Index(ia.SignerPayload, []byte(k)) }
	keys = []string{"referenced_assertions", "sig_type", "role"}
	for i := 1; i < len(keys); i++ {
		if pos(keys[i-1]) < 0 || pos(keys[i]) < pos(keys[i-1]) {
			t.Errorf("payload key order: %v at %d/%d", keys, pos(keys[i-1]), pos(keys[i]))
		}
	}
	entries := claimAssertionEntries(m.claim)
	for _, ref := range sp.ReferencedAssertions {
		if bytes.Index(ia.SignerPayload, []byte("url")) > bytes.Index(ia.SignerPayload, []byte("hash")) {
			t.Errorf("hashed-uri key order: url must precede hash")
		}
		e, ok := claimEntryForLabel(entries, assertionLabelFromURL(ref.URL))
		if !ok || !bytes.Equal(e.hash, ref.Hash) || ref.Alg != "" {
			t.Errorf("reference %q does not match the claim's entry (found %v)", ref.URL, ok)
		}
	}
	if !equalStrings(sp.Roles, []string{RoleCreator}) || sp.SigType != identitySigTypeX509 {
		t.Errorf("payload = %+v", sp)
	}
}

func TestSignIdentityKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.Signer{"rsa-pss": rsaKey, "ed25519": edKey, "p384": p384}
	for name, k := range keys {
		t.Run(name, func(t *testing.T) {
			s, sc, idChain := identityTestSigner(t, k)
			out := signBytes(t, s, PNG, unsignedPNG(t), identityManifest(name))
			res := validateSigned(t, PNG, out, sc, idChain)
			if !res.Valid || len(res.Identities) != 1 || !res.Identities[0].Trusted {
				t.Fatalf("valid=%v %+v %v", res.Valid, res.Identities, codes(res))
			}
		})
	}
	t.Run("message signer", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, sc, idChain := identityTestSigner(t, &messageOnlySigner{key: k})
		out := signBytes(t, s, JPEG, unsignedJPEG(t), identityManifest("message signer"))
		res := validateSigned(t, JPEG, out, sc, idChain)
		if !res.Valid || len(res.Identities) != 1 || !res.Identities[0].Trusted {
			t.Fatalf("valid=%v %+v %v", res.Valid, res.Identities, codes(res))
		}
	})
	t.Run("identity is the claim key", func(t *testing.T) {
		sc := newSigningChain(t)
		s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("t", "1"), WithIdentitySigner(sc.key, sc.chain))
		if err != nil {
			t.Fatal(err)
		}
		out := signBytes(t, s, JPEG, unsignedJPEG(t), identityManifest("same key"))
		res := validateSigned(t, JPEG, out, sc, sc)
		if !res.Valid || len(res.Identities) != 1 || !res.Identities[0].Trusted {
			t.Fatalf("valid=%v %+v %v", res.Valid, res.Identities, codes(res))
		}
	})
}

func TestSignIdentityTimestamped(t *testing.T) {
	ta := liveTSA(t)
	requests := 0
	srv := newTSAServer(t, ta, func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
		requests++
		tsaReply(t, w, ta, req, tsRawImprint(req.MessageImprint.Hashed), tsNonce(req.Nonce))
	})
	s, sc, idChain := identityTestSigner(t, nil, WithTimestampAuthority(srv.URL))
	out := signBytes(t, s, JPEG, unsignedJPEG(t), identityManifest("timestamped"))
	res := validateSigned(t, JPEG, out, sc, idChain, WithTimestampTrust(ta.pool()))
	if !res.Valid {
		t.Fatalf("%v", codes(res))
	}
	if !hasAt(res, StatusTimeStampValidated, res.ActiveManifestLabel) || !hasAt(res, StatusTimeStampValidated, res.ActiveManifestLabel+"/cawg.identity") {
		t.Errorf("both signatures should be timestamped: %v", codes(res))
	}
	if res.SignedAt.IsZero() || res.Identities[0].SignedAt.IsZero() {
		t.Errorf("SignedAt claim %v identity %v", res.SignedAt, res.Identities[0].SignedAt)
	}
	if requests != 2 {
		t.Errorf("TSA requests = %d, want one per signature", requests)
	}
}

func TestSignIdentityFragmented(t *testing.T) {
	s, sc, idChain := identityTestSigner(t, nil)
	init, frags := unsignedFragmentedSet(4, fragOpts{})
	m := identityManifest("fragmented identity")
	outInit, outFrags := signFragmentedSet(t, s, init, frags, m)
	res := ValidateFragmented(context.Background(), bytes.NewReader(outInit), readersOf(outFrags...),
		WithSigningTrust(sc.roots), WithIdentityTrust(idChain.roots), WithOnlineRevocation(false))
	if !res.Valid || !res.Has(StatusAssertionBMFFHashMatch) {
		t.Fatalf("valid=%v %v", res.Valid, codes(res))
	}
	if len(res.Identities) != 1 || !res.Identities[0].Trusted || !equalStrings(res.Identities[0].Referenced, []string{"c2pa.hash.bmff.v3", "c2pa.actions.v2"}) {
		t.Errorf("identities = %+v", res.Identities)
	}
}

func TestSignIdentityResign(t *testing.T) {
	s, sc, idChain := identityTestSigner(t, nil)
	first := signBytes(t, s, JPEG, unsignedJPEG(t), identityManifest("first"))
	m := openedManifest("second")
	m.Identity = IdentityInfo{Roles: []string{RoleEditor}}
	second := signBytes(t, s, JPEG, first, m)
	res := validateSigned(t, JPEG, second, sc, idChain)
	if !res.Valid || len(res.Identities) != 1 || !equalStrings(res.Identities[0].Roles, []string{RoleEditor}) {
		t.Fatalf("valid=%v %+v %v", res.Valid, res.Identities, codes(res))
	}
	// The prior manifest's identity was validated in the ingredient walk.
	if !res.Has(StatusIngredientManifestValidated) {
		t.Errorf("ingredient not validated: %v", codes(res))
	}
	var identityStatuses int
	for _, st := range res.Statuses {
		if st.Code == StatusIdentityTrusted {
			identityStatuses++
		}
	}
	if identityStatuses != 2 {
		t.Errorf("expected the prior and the new identity both trusted, got %d", identityStatuses)
	}
}

func TestSignIdentityErrors(t *testing.T) {
	plain, _ := newTestSigner(t)
	s, _, _ := identityTestSigner(t, nil)
	cases := []struct {
		name string
		s    *Signer
		m    func() Manifest
		want error
	}{
		{"identity without signer", plain, func() Manifest {
			m := createdManifest("x")
			m.Identity.Roles = []string{RoleCreator}
			return m
		}, ErrManifestInvalid},
		{"unknown reference", s, func() Manifest {
			m := createdManifest("x")
			m.Identity.References = []string{"com.example.absent"}
			return m
		}, ErrManifestInvalid},
		{"hard binding referenced explicitly", s, func() Manifest {
			m := createdManifest("x")
			m.Identity.References = []string{"c2pa.hash.data"}
			return m
		}, ErrManifestInvalid},
		{"duplicate reference", s, func() Manifest {
			m := createdManifest("x")
			m.Identity.References = []string{"c2pa.actions.v2", "c2pa.actions.v2"}
			return m
		}, ErrManifestInvalid},
		{"role not a label", s, func() Manifest {
			m := createdManifest("x")
			m.Identity.Roles = []string{"creator"}
			return m
		}, ErrManifestInvalid},
		{"caller writes cawg.identity", plain, func() Manifest {
			m := createdManifest("x")
			m.Assertions = []Assertion{{Label: "cawg.identity", Value: map[string]any{"x": 1}}}
			return m
		}, ErrManifestInvalid},
		{"caller writes cawg.identity__1", s, func() Manifest {
			m := createdManifest("x")
			m.Assertions = []Assertion{{Label: "cawg.identity__1", Value: map[string]any{"x": 1}}}
			return m
		}, ErrManifestInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := tc.s.Sign(context.Background(), JPEG, bytes.NewReader(unsignedJPEG(t)), &out, tc.m())
			if !errors.Is(err, tc.want) || out.Len() != 0 {
				t.Errorf("err = %v, wrote %d", err, out.Len())
			}
		})
	}
	// A reference to a caller assertion works; the identity vouches for it.
	m := createdManifest("caller ref")
	m.Assertions = []Assertion{{Label: "com.example.note", Value: map[string]any{"note": "hi"}}}
	m.Identity.References = []string{"com.example.note"}
	out := signBytes(t, s, JPEG, unsignedJPEG(t), m)
	res := Validate(context.Background(), JPEG, bytes.NewReader(out), WithOnlineRevocation(false))
	if len(res.Identities) != 1 || !equalStrings(res.Identities[0].Referenced, []string{"c2pa.hash.data", "com.example.note"}) {
		t.Errorf("identities = %+v", res.Identities)
	}
}

func TestNewSignerIdentityChecks(t *testing.T) {
	sc := newSigningChain(t)
	other := newSigningChain(t)
	cases := []struct {
		name string
		opt  SignerOption
		want error
	}{
		{"nil identity key", WithIdentitySigner(nil, sc.chain), ErrSignerKey},
		{"identity chain empty", WithIdentitySigner(sc.key, nil), ErrSignerChain},
		{"identity leaf does not match key", WithIdentitySigner(sc.key, other.chain), ErrSignerChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("t", "1"), tc.opt)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestMarshalIdentityPadded: every reserve from the base size up to base+300
// is hit exactly, pads are zero, and a reserve below the base is refused.
func TestMarshalIdentityPadded(t *testing.T) {
	ia := identityAssertion{
		SignerPayload: must(identityEncMode.Marshal(identitySignerPayload{
			ReferencedAssertions: []identityHashedURI{{URL: assertionURL("c2pa.hash.data"), Hash: make([]byte, 32)}},
			SigType:              identitySigTypeX509,
		})),
		Signature: make([]byte, 500),
	}
	base, err := marshalIdentityPadded(ia, 0)
	if err == nil {
		t.Fatalf("a reserve of 0 must be refused, got %d bytes", len(base))
	}
	base, err = identityEncMode.Marshal(identityAssertion{SignerPayload: ia.SignerPayload, Signature: ia.Signature, Pad1: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	for reserve := len(base); reserve < len(base)+300; reserve++ {
		out, err := marshalIdentityPadded(ia, reserve)
		if err != nil {
			t.Fatalf("reserve %d: %v", reserve, err)
		}
		if len(out) != reserve {
			t.Fatalf("reserve %d: got %d bytes", reserve, len(out))
		}
		got, _, _, err := decodeIdentityAssertion(out)
		if err != nil || !allZero(got.Pad1) || !allZero(got.Pad2) || !bytes.Equal(got.SignerPayload, ia.SignerPayload) {
			t.Fatalf("reserve %d: decode %v", reserve, err)
		}
	}
	if _, err := marshalIdentityPadded(ia, len(base)-1); err == nil {
		t.Errorf("a reserve below the base must be refused")
	}
}

// TestIdentityReserveExact: the placeholder and the signed assertion are the
// same size for every payload shape — the property the layout fixpoint needs.
func TestIdentityReserveExact(t *testing.T) {
	s, _, _ := identityTestSigner(t, nil)
	for _, info := range []IdentityInfo{
		{},
		{Roles: []string{RoleCreator}},
		{Roles: []string{RoleCreator, RoleEditor, "com.example.a-very-long-role-label-indeed"}},
		{References: []string{"c2pa.actions.v2"}},
	} {
		template := identityTemplate("c2pa.hash.data", info, 32)
		coseRes := coseReserveSize(s.identity.sigLen, s.identity.chainDER, false)
		reserve, err := identityReserveSize(template, coseRes)
		if err != nil {
			t.Fatal(err)
		}
		boxes := []namedBox{{"c2pa.hash.data", assertionBox("c2pa.hash.data", []byte{1, 2, 3})}, {"c2pa.actions.v2", assertionBox("c2pa.actions.v2", []byte{4})}}
		sp, err := identityPayload("sha256", boxes, info)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := s.signIdentity(context.Background(), sp, coseRes, reserve, false)
		if err != nil {
			t.Fatalf("%+v: %v", info, err)
		}
		if len(out) != reserve {
			t.Errorf("%+v: %d bytes, reserve %d", info, len(out), reserve)
		}
	}
}
