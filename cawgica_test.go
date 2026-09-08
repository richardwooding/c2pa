package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// icaBuild is the aggregation credential the corpus writes; icaOpts mutate it.
type icaBuild struct {
	alg           cose.Algorithm
	key           crypto.Signer
	pub           crypto.PublicKey
	untagged      bool
	noAlg         bool
	badAlg        bool
	contentType   any // nil: application/vc; otherwise the value written
	noContentType bool
	detached      bool
	payload       []byte // overrides the credential JSON
	issuer        any    // overrides "issuer"; nil: the did:jwk of key
	noContext     bool
	noType        bool
	validFrom     string // "" for the default (a day before the corpus epoch); "-" to omit
	validUntil    string
	noIdentities  bool
	badIdentity   bool
	hashAsArray   bool
	wrongHash     bool
	extraRole     bool
	wrongKey      bool // sign with a key other than the issuer's
	tsKind        int  // 0 none, 1 sigTst, 2 sigTst2
	tsa           *testTSA
	tsGenTime     time.Time
	sigType       string // signer_payload sig_type; default ICA
}

type icaOpt func(*icaBuild)

// icaEd25519 is the default aggregator key.
func icaEd25519(t testing.TB) (crypto.Signer, crypto.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// didJWK encodes a public key as a did:jwk.
func didJWK(t testing.TB, pub crypto.PublicKey) string {
	t.Helper()
	var jwk map[string]string
	switch k := pub.(type) {
	case ed25519.PublicKey:
		jwk = map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(k)}
	case *ecdsa.PublicKey:
		point, err := k.Bytes() // 0x04 || X || Y
		if err != nil {
			t.Fatal(err)
		}
		size := (len(point) - 1) / 2
		x, y := point[1:1+size], point[1+size:]
		jwk = map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}
	default:
		t.Fatalf("no JWK for %T", pub)
	}
	b, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(b)
}

// icaAssertionBytes builds a cawg.identity assertion carrying an identity
// claims aggregation credential over the boxed hard binding.
func icaAssertionBytes(t testing.TB, boxes []namedBox, opts ...icaOpt) []byte {
	t.Helper()
	b := &icaBuild{alg: cose.AlgorithmEdDSA, sigType: identitySigTypeICA}
	for _, o := range opts {
		o(b)
	}
	if b.key == nil {
		b.key, b.pub = icaEd25519(t)
	}
	var refs []identityHashedURI
	for _, nb := range boxes {
		if strings.HasPrefix(nb.label, "c2pa.hash.") {
			refs = append(refs, identityHashedURI{URL: assertionURL(nb.label), Hash: hashOf(t, "sha256", nb.box[8:])})
		}
	}
	sp := identitySignerPayload{ReferencedAssertions: refs, SigType: b.sigType}
	payload, err := identityEncMode.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}

	// The credential.
	credRefs := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		h := r.Hash
		if b.wrongHash {
			h = append([]byte{}, h...)
			h[0] ^= 1
		}
		var hv any = base64.StdEncoding.EncodeToString(h)
		if b.hashAsArray {
			// c2pa-rs: the ASCII bytes of the base64 string, as a JSON array of
			// numbers (Go would marshal a []byte as base64 again).
			ascii := []byte(base64.StdEncoding.EncodeToString(h))
			nums := make([]int, len(ascii))
			for i, c := range ascii {
				nums[i] = int(c)
			}
			hv = nums
		}
		credRefs = append(credRefs, map[string]any{"url": r.URL, "hash": hv})
	}
	asset := map[string]any{"referenced_assertions": credRefs, "sig_type": identitySigTypeICA}
	if b.extraRole {
		asset["role"] = []string{"cawg.creator"}
	}
	identities := []any{map[string]any{
		"type": "cawg.social_media", "name": "Corpus Cat", "username": "corpuscat",
		"uri": "https://social.example/corpuscat", "verifiedAt": corpusEpoch.Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		"provider": map[string]any{"id": "https://social.example", "name": "Social Example"},
	}}
	if b.badIdentity {
		identities = []any{map[string]any{"type": "cawg.affiliation", "provider": map[string]any{"id": "https://x.example"}}}
	}
	if b.noIdentities {
		identities = []any{}
	}
	cred := map[string]any{
		"@context":          []string{icaContextVC, icaContextCAWG},
		"type":              []string{icaTypeVC, icaTypeCAWG},
		"credentialSubject": map[string]any{"verifiedIdentities": identities, "c2paAsset": asset},
	}
	if b.noContext {
		delete(cred, "@context")
	}
	if b.noType {
		cred["type"] = []string{icaTypeVC}
	}
	switch {
	case b.issuer != nil:
		cred["issuer"] = b.issuer
	default:
		cred["issuer"] = didJWK(t, b.pub)
	}
	switch b.validFrom {
	case "":
		cred["validFrom"] = corpusEpoch.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	case "-":
	default:
		cred["validFrom"] = b.validFrom
	}
	if b.validUntil != "" {
		cred["validUntil"] = b.validUntil
	}
	credJSON := b.payload
	if credJSON == nil {
		// The corpus lays the asset out to a fixpoint, so the credential must
		// have the same length in every pass; a hash written as a JSON array
		// of numbers does not (1–3 digits per byte). Pad to a fixed size.
		const target = 4096
		probe, err := json.Marshal(cred)
		if err != nil {
			t.Fatal(err)
		}
		if deficit := target - len(probe) - len(`,"pad":""`); deficit >= 0 {
			cred["pad"] = strings.Repeat("x", deficit)
		} else {
			t.Fatalf("credential is %d bytes, over the %d padding target", len(probe), target)
		}
		if credJSON, err = json.Marshal(cred); err != nil {
			t.Fatal(err)
		}
		if len(credJSON) != target {
			t.Fatalf("padded credential is %d bytes, want %d", len(credJSON), target)
		}
	}

	// The COSE_Sign1 around it.
	signKey := b.key
	if b.wrongKey {
		signKey, _ = icaEd25519(t)
	}
	signer, err := cose.NewSigner(b.alg, signKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = b.alg
	if !b.noContentType {
		if b.contentType != nil {
			msg.Headers.Protected[cose.HeaderLabelContentType] = b.contentType
		} else {
			msg.Headers.Protected[cose.HeaderLabelContentType] = icaContentType
		}
	}
	msg.Payload = credJSON
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	if b.noAlg {
		delete(msg.Headers.Protected, cose.HeaderLabelAlgorithm)
		msg.Headers.RawProtected = nil
	}
	if b.badAlg {
		// Rewritten after signing: go-cose refuses to sign with a header alg
		// that is not the signer's. The alg check precedes the signature check.
		msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.Algorithm(-65535)
		msg.Headers.RawProtected = nil
	}
	if b.detached {
		msg.Payload = nil
	}
	env, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if b.tsKind != 0 {
		protected, signature, ok := coseParts(env)
		if !ok {
			t.Fatal("coseParts")
		}
		var tsOpts []tsTokenOpt
		if !b.tsGenTime.IsZero() {
			tsOpts = append(tsOpts, tsGenTime(b.tsGenTime))
		}
		counter := credJSON
		label := "sigTst"
		if b.tsKind == 2 {
			counter, _ = cbor.Marshal(signature)
			label = "sigTst2"
		}
		der := mintTSToken(t, b.tsa, coseCountersignData(counter, protected), tsOpts...)
		msg.Headers.Unprotected[label] = sigTstHeader(der)
		msg.Headers.RawUnprotected = nil
		if env, err = msg.MarshalCBOR(); err != nil {
			t.Fatal(err)
		}
	}
	if b.untagged {
		env = env[1:] // drop the tag; the array follows
	}
	out, err := identityEncMode.Marshal(identityAssertion{SignerPayload: payload, Signature: env, Pad1: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// icaCorpusAsset is a corpus JPEG carrying one aggregation-credential identity.
func icaCorpusAsset(t testing.TB, sb *signerBundle, spec manifestSpec, opts ...icaOpt) []byte {
	t.Helper()
	spec.signer = sb
	spec.claimV2 = true
	if spec.assertions == nil {
		spec.assertions = []assertionSpec{markerAssertion()}
	}
	spec.derived = func(t testing.TB, boxes []namedBox) []assertionSpec {
		return []assertionSpec{{label: identityLabel, raw: icaAssertionBytes(t, boxes, opts...)}}
	}
	return buildAsset(t, JPEG, spec)
}

func TestICACredentialValid(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	for _, tc := range []struct {
		name string
		opts []icaOpt
	}{
		{"ed25519 did:jwk", nil},
		{"hash as byte array (c2pa-rs)", []icaOpt{func(b *icaBuild) { b.hashAsArray = true }}},
		{"es256 did:jwk", []icaOpt{func(b *icaBuild) {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			b.alg, b.key, b.pub = cose.AlgorithmES256, k, &k.PublicKey
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asset := icaCorpusAsset(t, sb, manifestSpec{}, tc.opts...)
			res := runCorpus(t, JPEG, asset, sb)
			if !res.Valid {
				t.Fatalf("expected valid: %v: %v", codes(res), res.FirstFailure())
			}
			if !hasAt(res, StatusICACredentialValid, identityURI) || !hasAt(res, StatusIdentityWellFormed, identityURI) {
				t.Errorf("statuses: %v", codes(res))
			}
			if len(res.Identities) != 1 {
				t.Fatalf("identities = %d", len(res.Identities))
			}
			id := res.Identities[0]
			if !id.Valid || id.Trusted || id.Name() != "" || id.SigType != identitySigTypeICA || !strings.HasPrefix(id.Issuer, "did:jwk:") {
				t.Errorf("identity = %+v", id)
			}
			if len(id.VerifiedIdentities) != 1 || id.VerifiedIdentities[0].Type != "cawg.social_media" ||
				id.VerifiedIdentities[0].Provider.Name != "Social Example" || id.VerifiedIdentities[0].VerifiedAt.IsZero() {
				t.Errorf("verified identities = %+v", id.VerifiedIdentities)
			}
		})
	}
}

func TestICACredentialIssuerObject(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	key, pub := icaEd25519(t)
	asset := icaCorpusAsset(t, sb, manifestSpec{}, func(b *icaBuild) {
		b.key, b.pub = key, pub
		b.issuer = map[string]any{"id": didJWK(t, pub), "name": "Example Aggregator"}
	})
	res := runCorpus(t, JPEG, asset, sb)
	if !res.Valid || !hasAt(res, StatusICACredentialValid, identityURI) {
		t.Fatalf("%v", codes(res))
	}
}

func TestICACredentialDefects(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ta := newTestTSA(t)
	cases := []struct {
		name string
		opt  icaOpt
		want StatusCode
	}{
		{"untagged COSE_Sign1", func(b *icaBuild) { b.untagged = true }, StatusICAInvalidCOSESign1},
		{"no alg", func(b *icaBuild) { b.noAlg = true }, StatusICAInvalidAlg},
		{"unknown alg", func(b *icaBuild) { b.badAlg = true }, StatusICAInvalidAlg},
		{"no content type", func(b *icaBuild) { b.noContentType = true }, StatusICAInvalidContentType},
		{"wrong content type", func(b *icaBuild) { b.contentType = "application/json" }, StatusICAInvalidContentType},
		{"numeric content type", func(b *icaBuild) { b.contentType = uint64(50) }, StatusICAInvalidContentType},
		{"detached payload", func(b *icaBuild) { b.detached = true }, StatusICAInvalidVerifiableCredential},
		{"payload not JSON", func(b *icaBuild) { b.payload = []byte("not json") }, StatusICAInvalidVerifiableCredential},
		{"missing @context", func(b *icaBuild) { b.noContext = true }, StatusICAInvalidVerifiableCredential},
		{"missing CAWG type", func(b *icaBuild) { b.noType = true }, StatusICAInvalidVerifiableCredential},
		{"issuer not a DID", func(b *icaBuild) { b.issuer = "https://aggregator.example" }, StatusICAInvalidIssuer},
		{"issuer did:web", func(b *icaBuild) { b.issuer = "did:web:aggregator.example" }, StatusICADIDUnsupportedMethod},
		{"issuer did:jwk not base64", func(b *icaBuild) { b.issuer = "did:jwk:!!!" }, StatusICAInvalidDIDDocument},
		{"issuer did:jwk not a key", func(b *icaBuild) {
			b.issuer = "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"oct","k":"AAAA"}`))
		}, StatusICAInvalidDIDDocument},
		{"signed with another key", func(b *icaBuild) { b.wrongKey = true }, StatusICASignatureMismatch},
		{"validFrom missing", func(b *icaBuild) { b.validFrom = "-" }, StatusICAValidFromMissing},
		{"validFrom unparseable", func(b *icaBuild) { b.validFrom = "yesterday" }, StatusICAValidFromInvalid},
		{"validFrom in the future", func(b *icaBuild) { b.validFrom = corpusEpoch.Add(time.Hour).UTC().Format(time.RFC3339) }, StatusICAValidFromInvalid},
		{"validUntil in the past", func(b *icaBuild) { b.validUntil = corpusEpoch.Add(-time.Hour).UTC().Format(time.RFC3339) }, StatusICAValidUntilInvalid},
		{"no verified identities", func(b *icaBuild) { b.noIdentities = true }, StatusICAVerifiedIdentitiesMissing},
		{"verified identity without provider name", func(b *icaBuild) { b.badIdentity = true }, StatusICAVerifiedIdentitiesInvalid},
		{"c2paAsset hash differs", func(b *icaBuild) { b.wrongHash = true }, StatusICASignerPayloadMismatch},
		{"c2paAsset role differs", func(b *icaBuild) { b.extraRole = true }, StatusICASignerPayloadMismatch},
		{"validFrom after the credential's time-stamp", func(b *icaBuild) {
			b.tsKind, b.tsa, b.tsGenTime = 2, ta, corpusEpoch.Add(-72*time.Hour)
		}, StatusICAValidFromInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := icaCorpusAsset(t, sb, manifestSpec{}, tc.opt)
			res := runCorpus(t, JPEG, asset, sb, WithTimestampTrust(ta.pool()))
			if !hasAt(res, tc.want, identityURI) {
				t.Fatalf("missing %s: %v", tc.want, codes(res))
			}
			if res.Valid || hasAt(res, StatusICACredentialValid, identityURI) || hasAt(res, StatusIdentityWellFormed, identityURI) {
				t.Errorf("a defective credential must not be valid: valid=%v %v", res.Valid, codes(res))
			}
			if len(res.Identities) != 1 || res.Identities[0].Valid || res.Identities[0].Trusted {
				t.Errorf("identity = %+v", res.Identities)
			}
		})
	}
}

func TestICACredentialTimestamp(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ta := newTestTSA(t)
	stamped := func(b *icaBuild) { b.tsKind, b.tsa = 2, ta }
	asset := icaCorpusAsset(t, sb, manifestSpec{}, stamped)

	res := runCorpus(t, JPEG, asset, sb, WithTimestampTrust(ta.pool()))
	if !res.Valid || !hasAt(res, StatusICATimeStampValidated, identityURI) || !hasAt(res, StatusICACredentialValid, identityURI) {
		t.Fatalf("trusted TSA: valid=%v %v", res.Valid, codes(res))
	}
	if !res.Identities[0].SignedAt.Equal(corpusEpoch) {
		t.Errorf("SignedAt = %v", res.Identities[0].SignedAt)
	}
	// An unanchored TSA: the token is not validated, and that is a failure.
	res = runCorpus(t, JPEG, asset, sb, WithTimestampTrust(emptyPool()))
	if res.Valid || !hasAt(res, StatusICATimeStampInvalid, identityURI) || !res.Identities[0].SignedAt.IsZero() {
		t.Errorf("untrusted TSA: valid=%v %v", res.Valid, codes(res))
	}
	// A v1 sigTst is ignored, as the spec says: no time-stamp status at all.
	asset = icaCorpusAsset(t, sb, manifestSpec{}, func(b *icaBuild) { b.tsKind, b.tsa = 1, ta })
	res = runCorpus(t, JPEG, asset, sb, WithTimestampTrust(ta.pool()))
	if !res.Valid || hasAt(res, StatusICATimeStampValidated, identityURI) || hasAt(res, StatusICATimeStampInvalid, identityURI) {
		t.Errorf("v1 sigTst: valid=%v %v", res.Valid, codes(res))
	}
	// The manifest's own trusted time-stamp bounds the credential too.
	asset = icaCorpusAsset(t, sb, manifestSpec{tsKind: 2, tsa: ta}, func(b *icaBuild) {
		b.validFrom = corpusEpoch.Add(30 * time.Minute).UTC().Format(time.RFC3339)
	})
	res = Validate(context.Background(), JPEG, bytes.NewReader(asset), WithSigningTrust(sb.roots), WithTimestampTrust(ta.pool()),
		WithClock(func() time.Time { return corpusEpoch.Add(2 * time.Hour) }), WithOnlineRevocation(false))
	if res.Valid || !hasAt(res, StatusICAValidFromInvalid, identityURI) || res.SignedAt.IsZero() {
		t.Errorf("validFrom after the manifest time-stamp: valid=%v signedAt=%v %v", res.Valid, res.SignedAt, codes(res))
	}
}

// TestICAFixture: c2pa-rs's did:jwk fixture verifies offline.
func TestICAFixture(t *testing.T) {
	data := fixtureBytes(t, "cawg_ica.jpg")
	res := Validate(context.Background(), JPEG, bytes.NewReader(data), WithOnlineRevocation(false))
	if len(res.Identities) != 1 {
		t.Fatalf("identities = %d", len(res.Identities))
	}
	id := res.Identities[0]
	iuri := res.ActiveManifestLabel + "/cawg.identity"
	if !hasAt(res, StatusICACredentialValid, iuri) || !hasAt(res, StatusIdentityWellFormed, iuri) {
		t.Errorf("statuses: %v", codes(res))
	}
	for _, s := range res.Statuses {
		if s.URI == iuri && s.Severity == SeverityFailure {
			t.Errorf("identity failure: %s %s", s.Code, s.Explanation)
		}
	}
	if !id.Valid || id.Trusted || id.SigType != identitySigTypeICA || !strings.HasPrefix(id.Issuer, "did:jwk:") || id.Name() != "" {
		t.Errorf("identity = %+v", id)
	}
	if !equalStrings(id.Referenced, []string{"c2pa.hash.data"}) {
		t.Errorf("referenced = %v", id.Referenced)
	}
	types := make([]string, 0, len(id.VerifiedIdentities))
	for _, vi := range id.VerifiedIdentities {
		types = append(types, vi.Type)
	}
	if !equalStrings(types, []string{"cawg.document_verification", "cawg.affiliation", "cawg.social_media", "cawg.crypto_wallet"}) {
		t.Errorf("verified identity types = %v", types)
	}
	if id.VerifiedIdentities[2].Name != "Silly Cats 929" || id.VerifiedIdentities[2].Username != "username" || id.VerifiedIdentities[0].Provider.Name != "Example ID Verifier" {
		t.Errorf("verified identities = %+v", id.VerifiedIdentities)
	}
}

func TestJWKPublicKey(t *testing.T) {
	_, pub := icaEd25519(t)
	if k, _, err := icaIssuerKey(didJWK(t, pub) + "#0"); err != nil || !k.(ed25519.PublicKey).Equal(pub) {
		t.Errorf("did:jwk Ed25519 round trip: %v", err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if k, _, err := icaIssuerKey(didJWK(t, &ec.PublicKey)); err != nil || !k.(*ecdsa.PublicKey).Equal(&ec.PublicKey) {
		t.Errorf("did:jwk P-256 round trip: %v", err)
	}
	for _, bad := range []string{"", "did:", "did:jwk", "did:jwk:", "did:key:z6Mk", "urn:x"} {
		if _, _, err := icaIssuerKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`, `{"kty":"OKP","crv":"X25519","x":"AA"}`, `{"kty":"RSA","n":"AQ","e":"AQ"}`, `[]`} {
		if _, err := jwkPublicKey([]byte(bad)); err == nil {
			t.Errorf("JWK %s accepted", bad)
		}
	}
	if !keyFitsAlg(cose.AlgorithmEdDSA, pub) || keyFitsAlg(cose.AlgorithmES256, pub) || !keyFitsAlg(cose.AlgorithmES256, &ec.PublicKey) || keyFitsAlg(cose.AlgorithmES384, &ec.PublicKey) {
		t.Error("keyFitsAlg")
	}
}

func TestICAHashShapes(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 32)
	b64 := base64.StdEncoding.EncodeToString(want)
	nums := make([]int, len(b64))
	for i := range b64 {
		nums[i] = int(b64[i])
	}
	arr, _ := json.Marshal(nums)
	for _, in := range []string{`"` + b64 + `"`, `"` + base64.RawURLEncoding.EncodeToString(want) + `"`, string(arr)} {
		var h icaHash
		if err := json.Unmarshal([]byte(in), &h); err != nil || !bytes.Equal(h, want) {
			t.Errorf("%s → %x (%v)", in, []byte(h), err)
		}
	}
	var h icaHash
	if err := json.Unmarshal([]byte(`{"x":1}`), &h); err == nil {
		t.Error("object accepted as a hash")
	}
	if err := json.Unmarshal([]byte(`[1,2,300]`), &h); err == nil {
		t.Error("out-of-range byte accepted")
	}
}

// Issuer trust for aggregation credentials (WithIdentityIssuers, issue #57).
//
// The credential's cryptography and the aggregator's standing are separate
// questions, and only the caller can answer the second — CAWG publishes no
// list of aggregators to believe. These tests pin all three outcomes: no
// opinion expressed, issuer believed, issuer ruled out.

func TestICAIssuerTrust(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	key, pub := icaEd25519(t)
	withKey := func(b *icaBuild) { b.key, b.pub = key, pub }
	issuer := didJWK(t, pub)
	other := "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5vYm9keSJ9"

	for _, tc := range []struct {
		name    string
		opts    []ValidateOption
		trusted bool
		code    StatusCode
	}{
		{"no list configured", nil, false, StatusIdentityWellFormed},
		{"issuer on the list", []ValidateOption{WithIdentityIssuers(issuer)}, true, StatusIdentityTrusted},
		{"issuer among several", []ValidateOption{WithIdentityIssuers(other, issuer)}, true, StatusIdentityTrusted},
		{"issuer not on the list", []ValidateOption{WithIdentityIssuers(other)}, false, StatusICAUntrustedIssuer},
		// Go hands a variadic function a nil slice for zero arguments, so this
		// must not be mistaken for the option being absent.
		{"empty list trusts nobody", []ValidateOption{WithIdentityIssuers()}, false, StatusICAUntrustedIssuer},
		// A DID URL fragment names a verification method within the same DID.
		{"list entry carries a fragment", []ValidateOption{WithIdentityIssuers(issuer + "#0")}, true, StatusIdentityTrusted},
		{"list entry padded with space", []ValidateOption{WithIdentityIssuers("  " + issuer + "\n")}, true, StatusIdentityTrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asset := icaCorpusAsset(t, sb, manifestSpec{}, withKey)
			res := runCorpus(t, JPEG, asset, sb, tc.opts...)
			assertICAIssuerOutcome(t, res, tc.trusted, tc.code)
		})
	}
}

// assertICAIssuerOutcome checks one issuer-trust verdict end to end: the status
// recorded, the roll-up, and what Identity then admits to knowing.
func assertICAIssuerOutcome(t *testing.T, res ValidationResult, trusted bool, code StatusCode) {
	t.Helper()
	if !hasAt(res, code, identityURI) {
		t.Errorf("want %s at the identity URI; got %v", code, codes(res))
	}
	// The credential itself verified in every case; only its issuer's standing
	// differs, and that must stay visible.
	if !hasAt(res, StatusICACredentialValid, identityURI) {
		t.Errorf("the credential verified and should say so: %v", codes(res))
	}

	untrusted := code == StatusICAUntrustedIssuer
	if res.Valid == untrusted {
		t.Errorf("result valid = %v with %s", res.Valid, code)
	}
	if len(res.Identities) != 1 {
		t.Fatalf("identities = %d", len(res.Identities))
	}
	id := res.Identities[0]
	if id.Trusted != trusted {
		t.Errorf("Identity.Trusted = %v, want %v", id.Trusted, trusted)
	}
	// Valid keeps one meaning across both sig types: well-formed or trusted
	// was recorded. An untrusted issuer is neither.
	if id.Valid == untrusted {
		t.Errorf("Identity.Valid = %v with %s", id.Valid, code)
	}
	// Name() answers only for a proven actor — the VerifiedSigner rule.
	want := ""
	if trusted {
		want = "Corpus Cat" // the corpus credential's verifiedIdentities[0].name
	}
	if id.Name() != want {
		t.Errorf("Name() = %q, want %q", id.Name(), want)
	}
	if untrusted && hasAt(res, StatusIdentityWellFormed, identityURI) {
		t.Error("an untrusted issuer must not also be reported well-formed")
	}
}

// TestICAIssuerFragmentInCredential: the fragment may be on either side. A
// credential naming "did:…#0" as its issuer is the same aggregator as the bare
// DID an operator configured.
func TestICAIssuerFragmentInCredential(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	key, pub := icaEd25519(t)
	bare := didJWK(t, pub)
	asset := icaCorpusAsset(t, sb, manifestSpec{}, func(b *icaBuild) {
		b.key, b.pub = key, pub
		b.issuer = bare + "#0"
	})
	res := runCorpus(t, JPEG, asset, sb, WithIdentityIssuers(bare))
	assertICAIssuerOutcome(t, res, true, StatusIdentityTrusted)
}

// TestICAIssuerTrustDoesNotTouchX509: the two trust lists are separate, and an
// aggregator DID must not vouch for an X.509 identity or vice versa.
func TestICAIssuerTrustDoesNotTouchX509(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	_, pub := icaEd25519(t)
	asset := identityAsset(t, claimSB, idSB)
	res := runCorpus(t, JPEG, asset, claimSB, WithIdentityIssuers(didJWK(t, pub)))
	if !res.Valid {
		t.Fatalf("an X.509 identity should be unaffected: %v", codes(res))
	}
	if len(res.Identities) != 1 || res.Identities[0].Trusted {
		t.Errorf("an aggregator DID must not anchor an X.509 identity: %+v", res.Identities)
	}
	if !hasAt(res, StatusIdentityWellFormed, identityURI) {
		t.Errorf("the X.509 identity should still be well-formed: %v", codes(res))
	}
	if hasAt(res, StatusICAUntrustedIssuer, identityURI) {
		t.Error("untrusted_issuer is for aggregation credentials only")
	}
}

// TestICAFixtureTrustedIssuer: the same round trip over c2pa-rs's real
// credential — learn the issuer from the first pass, then trust it. Proves the
// DID we present is the DID an operator would paste back in.
func TestICAFixtureTrustedIssuer(t *testing.T) {
	data := fixtureBytes(t, "cawg_ica.jpg")
	first := Validate(context.Background(), JPEG, bytes.NewReader(data), WithOnlineRevocation(false))
	if len(first.Identities) != 1 || first.Identities[0].Issuer == "" {
		t.Fatalf("no issuer to trust: %+v", first.Identities)
	}
	issuer := first.Identities[0].Issuer

	res := Validate(context.Background(), JPEG, bytes.NewReader(data),
		WithOnlineRevocation(false), WithIdentityIssuers(issuer))
	iuri := res.ActiveManifestLabel + "/cawg.identity"
	if !hasAt(res, StatusIdentityTrusted, iuri) {
		t.Fatalf("want cawg.identity.trusted: %v", codes(res))
	}
	id := res.Identities[0]
	if !id.Valid || !id.Trusted {
		t.Errorf("identity = %+v", id)
	}
	// The aggregator's word about who this is, now that we have said we
	// believe the aggregator.
	if id.Name() != "First-Name Last-Name" {
		t.Errorf("Name() = %q, want the credential's first verified identity", id.Name())
	}
	t.Logf("trusted aggregator %s vouches for %q", issuer, id.Name())
}
