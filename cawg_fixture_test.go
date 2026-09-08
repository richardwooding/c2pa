package c2pa

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// cawgFixture is c2pa-rs's C_with_CAWG_data.jpg: a claim signed by the C2PA
// test CA (untrusted here) carrying one cawg.identity assertion — an Ed25519
// X.509 identity referencing cawg.training-mining and c2pa.hash.data, no
// timestamp on the identity signature.
func cawgFixture(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cawg_x509.jpg")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureIdentityAssertion returns the fixture's cawg.identity assertion bytes.
func fixtureIdentityAssertion(t testing.TB) rawAssertion {
	t.Helper()
	ctx := context.Background()
	store, err := ExtractStore(ctx, JPEG, bytes.NewReader(cawgFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	m := parseStore(ctx, store).active()
	if m == nil {
		t.Fatal("no manifest in fixture")
	}
	for _, a := range m.assertions {
		if a.label == identityLabel {
			return a
		}
	}
	t.Fatal("fixture has no cawg.identity assertion")
	return rawAssertion{}
}

func TestCAWGFixtureValidates(t *testing.T) {
	ctx := context.Background()
	res := Validate(ctx, JPEG, bytes.NewReader(cawgFixture(t)))
	if len(res.Identities) != 1 {
		t.Fatalf("identities = %d, want 1", len(res.Identities))
	}
	id := res.Identities[0]
	iuri := res.ActiveManifestLabel + "/cawg.identity"
	if id.Label != "cawg.identity" || id.URI != iuri || id.SigType != identitySigTypeX509 {
		t.Errorf("identity = %+v", id)
	}
	if want := []string{"cawg.training-mining", "c2pa.hash.data"}; !equalStrings(id.Referenced, want) {
		t.Errorf("referenced = %v, want %v", id.Referenced, want)
	}
	if !id.Valid || id.Trusted || id.Name() != "" || len(id.Chain) != 2 {
		t.Errorf("valid=%v trusted=%v name=%q chain=%d; want valid, untrusted, no name, 2 certs", id.Valid, id.Trusted, id.Name(), len(id.Chain))
	}
	// The identity's bytes are the ones the claim signed: it is a gathered
	// assertion whose hashed_uri matched.
	if !hasAt(res, StatusAssertionHashedURIMatch, "self#jumbf=c2pa.assertions/cawg.identity") {
		t.Errorf("no hashedURI.match for the identity assertion: %v", codes(res))
	}
	for _, want := range []StatusCode{StatusClaimSignatureValidated, StatusTimeStampMissing, StatusIdentityWellFormed} {
		if !hasAt(res, want, iuri) {
			t.Errorf("missing %s at %s: %v", want, iuri, codes(res))
		}
	}
	if hasAt(res, StatusIdentityTrusted, iuri) || hasAt(res, StatusSigningCredentialUntrusted, iuri) {
		t.Errorf("an unanchored identity must be well-formed, neither trusted nor a failure: %v", codes(res))
	}
	// The claim signer is untrusted under the embedded list; that is the
	// claim's verdict, not the identity's.
	if !hasAt(res, StatusSigningCredentialUntrusted, res.ActiveManifestLabel) || res.Valid {
		t.Errorf("fixture claim should be untrusted and invalid: valid=%v %v", res.Valid, codes(res))
	}

	// Anchoring the identity's own intermediate proves the actor.
	pool := x509.NewCertPool()
	pool.AddCert(id.Chain[len(id.Chain)-1])
	res = Validate(ctx, JPEG, bytes.NewReader(cawgFixture(t)), WithIdentityTrust(pool))
	if len(res.Identities) != 1 || !res.Identities[0].Trusted || res.Identities[0].Name() != "C2PA Signer" {
		t.Fatalf("anchored identity = %+v, name %q", res.Identities, res.Identities[0].Name())
	}
	if !hasAt(res, StatusIdentityTrusted, iuri) || hasAt(res, StatusIdentityWellFormed, iuri) || !hasAt(res, StatusSigningCredentialTrusted, iuri) {
		t.Errorf("anchored identity statuses: %v", codes(res))
	}
	// The claim's trust decision is untouched by identity anchors.
	if res.VerifiedSigner() != "" {
		t.Errorf("identity anchors must not vouch for the claim signer: %q", res.VerifiedSigner())
	}
}

// TestCAWGFixtureEncodingParity pins the wire order c2pa-rs uses — and
// re-serialises for verification — by re-encoding the fixture's decoded
// assertion and signer_payload with identityEncMode and requiring the exact
// stored bytes. If this fails, files this library signs will not verify in
// c2patool.
func TestCAWGFixtureEncodingParity(t *testing.T) {
	a := fixtureIdentityAssertion(t)
	ia, sp, unevaluated, err := decodeIdentityAssertion(a.data)
	if err != nil {
		t.Fatal(err)
	}
	if len(unevaluated) != 0 {
		t.Errorf("unexpected unevaluated fields %v", unevaluated)
	}
	payload, err := identityEncMode.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, ia.SignerPayload) {
		t.Errorf("re-encoded signer_payload differs from the stored bytes:\n got %x\nwant %x", payload, []byte(ia.SignerPayload))
	}
	whole, err := identityEncMode.Marshal(ia)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, a.data) {
		t.Errorf("re-encoded assertion differs from the stored bytes (len %d vs %d)", len(whole), len(a.data))
	}
	// And the sorted order is NOT what c2pa-rs writes — the trap the encoder
	// exists for.
	sorted, err := encMode.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sorted, ia.SignerPayload) {
		t.Errorf("core-deterministic order unexpectedly equals the stored bytes; the parity test no longer guards anything")
	}
	// Pads: c2pa-rs writes both, zero-filled.
	if len(ia.Pad1) == 0 || ia.Pad2 == nil || !allZero(ia.Pad1) || !allZero(ia.Pad2) {
		t.Errorf("fixture pads: pad1 %d bytes, pad2 %v", len(ia.Pad1), ia.Pad2 != nil)
	}
	var top map[string]cbor.RawMessage
	if err := identityDecMode.Unmarshal(a.data, &top); err != nil || len(top) != 4 {
		t.Errorf("fixture assertion keys = %d (%v)", len(top), err)
	}
}

// hasAt reports whether code was recorded at exactly uri.
func hasAt(res ValidationResult, code StatusCode, uri string) bool {
	for _, s := range res.Statuses {
		if s.Code == code && s.URI == uri {
			return true
		}
	}
	return false
}

// FuzzIdentityAssertion drives the identity decoder and the reference and pad
// checks with arbitrary CBOR. Contract: never panic; a decode error and a
// validation outcome are both fine.
func FuzzIdentityAssertion(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	if b, err := os.ReadFile("testdata/cawg_x509.jpg"); err == nil {
		ctx := context.Background()
		if store, err := ExtractStore(ctx, JPEG, bytes.NewReader(b)); err == nil {
			if m := parseStore(ctx, store).active(); m != nil {
				for _, a := range m.assertions {
					if a.label == identityLabel {
						f.Add(a.data)
					}
				}
			}
		}
	}
	entries := []claimAssertionEntry{
		{url: "self#jumbf=c2pa.assertions/c2pa.hash.data", hash: make([]byte, 32)},
		{url: "self#jumbf=c2pa.assertions/com.example.marker", hash: bytes.Repeat([]byte{1}, 32), alg: "sha256"},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v := &validator{cfg: defaultConfig(), res: ValidationResult{}}
		m := &parsedManifest{label: "urn:uuid:fuzz", claim: map[string]any{"alg": "sha256"}}
		a := rawAssertion{label: identityLabel, tbox: "cbor", data: data}
		id := v.verifyIdentity(m, a, entries, "urn:uuid:fuzz/cawg.identity", time.Time{})
		if id.Valid && !v.res.Statuses[len(v.res.Statuses)-1].Code.isIdentitySuccess() {
			t.Fatalf("Valid identity without a success code: %v", v.res.Statuses)
		}
	})
}

func (c StatusCode) isIdentitySuccess() bool {
	return c == StatusIdentityWellFormed || c == StatusIdentityTrusted
}
