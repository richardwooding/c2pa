package c2pa

import (
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CAWG identity assertions (Creator Assertions Working Group, Identity Assertion
// 1.1, https://cawg.io/identity/1.1/). A cawg.identity assertion lets a named
// actor — a photographer, a newsroom — sign a list of the manifest's assertions
// with their OWN credential, independently of the claim generator's signature.
// signer_payload names the assertions (always including the hard binding, so
// the actor vouches for the content bytes), sig_type says what kind of
// credential signed it, signature holds that signature, and pad1/pad2 are
// zero-filled size stabilisers.
//
// Wire format facts this file depends on: c2pa-rs serialises the assertion in
// STRUCT-DECLARATION order — signer_payload {referenced_assertions [{url, alg?,
// hash}], sig_type, role?}, signature, pad1, pad2? — and on validation
// deserialises signer_payload into its struct and re-serialises it as the COSE
// payload. So a signer must produce exactly that field order for c2patool to
// verify it (identityEncMode), and a validator must verify the signer_payload
// bytes AS STORED rather than re-encoding them (identityAssertion.SignerPayload
// is a cbor.RawMessage), which is correct for every producer that stores what
// it signed.

const (
	// identityLabel is the CAWG identity assertion label; further instances are
	// labelled cawg.identity__1, cawg.identity__2, ….
	identityLabel = "cawg.identity"
	// identitySigTypeX509 is a COSE_Sign1 by an X.509 credential (spec §8.2).
	identitySigTypeX509 = "cawg.x509.cose"
	// identitySigTypeICA is a W3C verifiable credential issued by an identity
	// claims aggregator (spec §8.1). Recognised, not evaluated.
	identitySigTypeICA = "cawg.identity_claims_aggregation"
)

// identityHashedURI is one referenced_assertions entry. Field order is the wire
// order (see the file comment).
type identityHashedURI struct {
	URL  string `cbor:"url"`
	Alg  string `cbor:"alg,omitempty"`
	Hash []byte `cbor:"hash"`
}

// identitySignerPayload is the signed part of an identity assertion. Field
// order is the wire order. The expected_* fields are not modelled: the validator
// reports their presence as not evaluated.
type identitySignerPayload struct {
	ReferencedAssertions []identityHashedURI `cbor:"referenced_assertions"`
	SigType              string              `cbor:"sig_type"`
	Roles                []string            `cbor:"role,omitempty"`
}

// identityAssertion is the assertion itself. SignerPayload keeps the stored
// bytes, which are what the signature covers.
type identityAssertion struct {
	SignerPayload cbor.RawMessage `cbor:"signer_payload"`
	Signature     []byte          `cbor:"signature"`
	Pad1          []byte          `cbor:"pad1"`
	Pad2          []byte          `cbor:"pad2,omitempty"`
}

// identityUnevaluatedFields are the signer_payload fields the spec defines that
// this validator recognises but does not check (nor does c2pa-rs).
var identityUnevaluatedFields = []string{"expected_partial_claim", "expected_claim_generator", "expected_countersigners"}

// identityEncMode is core-deterministic CBOR except that struct fields keep
// their declaration order, which is how c2pa-rs writes — and re-encodes for
// verification — the identity assertion.
var identityEncMode = func() cbor.EncMode {
	opts := cbor.CoreDetEncOptions()
	opts.Sort = cbor.SortNone
	em, err := opts.EncMode()
	if err != nil {
		panic(err) // static options; can't fail
	}
	return em
}()

// identityDecMode is decMode plus a duplicate-key rule: fxamacker keeps the
// LAST duplicate for a map target but the FIRST for a struct target, so an
// assertion with two signer_payload keys could be type-checked against one and
// verified against the other. c2pa-rs rejects duplicate fields; so do we.
var identityDecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DefaultMapType: reflect.TypeFor[map[string]any](),
		DupMapKey:      cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(err) // static options; can't fail
	}
	return dm
}()

// isIdentityLabel reports whether an assertion label is a CAWG identity
// assertion: cawg.identity or a multiple-instance form cawg.identity__N.
func isIdentityLabel(label string) bool {
	return label == identityLabel || strings.HasPrefix(label, identityLabel+"__")
}

// isCBORByteString reports whether raw encodes a CBOR byte string (major type
// 2, untagged). Used where the spec demands a bstr and a text string or number
// must be refused rather than coerced.
func isCBORByteString(raw []byte) bool {
	return len(raw) > 0 && raw[0]>>5 == 2
}

// decodeIdentityAssertion decodes a cawg.identity assertion, enforcing the
// required fields and types of the spec's identity rule (§5.2): signer_payload
// a map with a non-empty referenced_assertions list (url and hash in each), a
// text sig_type and an optional role list; signature and pad1 byte strings;
// pad2 a byte string when present. Unknown fields are ignored (§7.1);
// unevaluated names the recognised-but-unchecked expected_* fields present.
func decodeIdentityAssertion(data []byte) (ia identityAssertion, sp identitySignerPayload, unevaluated []string, err error) {
	var top map[string]cbor.RawMessage
	if err := identityDecMode.Unmarshal(data, &top); err != nil {
		return ia, sp, nil, fmt.Errorf("identity assertion is not a CBOR map: %w", err)
	}
	for _, key := range []string{"signer_payload", "signature", "pad1"} {
		if _, ok := top[key]; !ok {
			return ia, sp, nil, fmt.Errorf("identity assertion lacks %q", key)
		}
	}
	for _, key := range []string{"signature", "pad1", "pad2"} {
		raw, ok := top[key]
		if !ok {
			continue
		}
		if !isCBORByteString(raw) {
			return ia, sp, nil, fmt.Errorf("identity assertion %q is not a byte string", key)
		}
	}
	if err := identityDecMode.Unmarshal(data, &ia); err != nil {
		return ia, sp, nil, fmt.Errorf("identity assertion did not decode: %w", err)
	}
	var payload map[string]cbor.RawMessage
	if err := identityDecMode.Unmarshal(ia.SignerPayload, &payload); err != nil {
		return ia, sp, nil, fmt.Errorf("signer_payload is not a CBOR map: %w", err)
	}
	for _, key := range []string{"referenced_assertions", "sig_type"} {
		if _, ok := payload[key]; !ok {
			return ia, sp, nil, fmt.Errorf("signer_payload lacks %q", key)
		}
	}
	if err := identityDecMode.Unmarshal(ia.SignerPayload, &sp); err != nil {
		return ia, sp, nil, fmt.Errorf("signer_payload did not decode: %w", err)
	}
	if len(sp.ReferencedAssertions) == 0 {
		return ia, sp, nil, errors.New("signer_payload.referenced_assertions is empty")
	}
	for i, ref := range sp.ReferencedAssertions {
		if ref.URL == "" || len(ref.Hash) == 0 {
			return ia, sp, nil, fmt.Errorf("referenced_assertions[%d] lacks url or hash", i)
		}
	}
	if sp.SigType == "" {
		return ia, sp, nil, errors.New("signer_payload.sig_type is empty")
	}
	for _, r := range sp.Roles {
		if r == "" {
			return ia, sp, nil, errors.New("signer_payload.role holds an empty label")
		}
	}
	for _, key := range identityUnevaluatedFields {
		if _, ok := payload[key]; ok {
			unevaluated = append(unevaluated, key)
		}
	}
	return ia, sp, unevaluated, nil
}

// allZero reports whether every byte is 0x00, in time independent of where a
// non-zero byte sits and without allocating.
func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// identityReferenceLabel resolves a referenced_assertions url to a label of the
// manifest's own assertion store. Two forms are accepted: the relative one
// c2pa-rs writes, "self#jumbf=c2pa.assertions/<label>", and the absolute one the
// spec's example uses, "self#jumbf=/c2pa/<manifest label>/c2pa.assertions/<label>",
// which must name THIS manifest — a reference into another manifest is not an
// assertion of this claim, whatever its hash.
func identityReferenceLabel(url, manifestLabel string) (string, bool) {
	const relative = "self#jumbf=c2pa.assertions/"
	if label, ok := strings.CutPrefix(url, relative); ok {
		return label, label != "" && !strings.Contains(label, "/")
	}
	absolute := "self#jumbf=/c2pa/" + manifestLabel + "/c2pa.assertions/"
	if label, ok := strings.CutPrefix(url, absolute); ok {
		return label, label != "" && !strings.Contains(label, "/")
	}
	return "", false
}

// Identity is one CAWG identity assertion (cawg.identity) of the active
// manifest: a named actor's signature, made with the actor's own credential,
// over some of the manifest's assertions — always including the hard binding,
// so the actor vouches for the content bytes as well. See ValidationResult.Identities.
//
// Valid is about the identity assertion alone: its CBOR, padding and
// references check and its signature verifies. A manifest whose own claim
// signature fails can still carry a Valid identity, and an asset with an
// invalid identity is itself invalid; ValidationResult.Valid is the verdict.
type Identity struct {
	// Label is the assertion label: "cawg.identity", or "cawg.identity__1", …
	// when a manifest carries several.
	Label string
	// URI is the URI this identity's statuses are recorded under:
	// "<manifest label>/<Label>".
	URI string
	// SigType is signer_payload.sig_type: "cawg.x509.cose" for an X.509
	// credential, "cawg.identity_claims_aggregation" for an aggregator's
	// verifiable credential.
	SigType string
	// Roles are the named actor's declared roles (e.g. "cawg.creator"), as
	// PRESENTED.
	Roles []string
	// Referenced lists the labels of the assertions the actor signed over, in
	// payload order.
	Referenced []string
	// Chain is the actor's certificate chain as PRESENTED (X.509 only), leaf
	// first, populated whether or not it verified — like SignerChain.
	Chain []*x509.Certificate
	// Issuer is the aggregator's DID (identity claims aggregation only), as
	// PRESENTED — e.g. "did:jwk:…". Only did:jwk is resolved and verified.
	Issuer string
	// VerifiedIdentities are the identity signals an aggregator vouched for
	// (identity claims aggregation only), as PRESENTED by the aggregator.
	VerifiedIdentities []VerifiedIdentity
	// SignedAt is the signing time from a TRUSTED timestamp on the identity
	// signature, or zero — like ValidationResult.SignedAt.
	SignedAt time.Time
	// Valid: the assertion is well-formed and its signature verifies
	// (cawg.identity.well-formed or cawg.identity.trusted was recorded). For an
	// aggregation credential: the credential is cawg.ica.credential_valid.
	Valid bool
	// Trusted: Valid, and the credential reaches a root of trust — an X.509
	// chain anchored by WithIdentityTrust. No issuer trust list exists for
	// aggregation credentials yet, so those are never Trusted. Only then is
	// the actor proven.
	Trusted bool
}

// Name returns the actor's name — the leaf certificate's Subject Common Name,
// falling back to its first Organization — ONLY when Trusted, exactly as
// ValidationResult.VerifiedSigner does for the claim signer. Otherwise "".
// The name as presented, proven or not, is Chain[0].Subject.
func (id Identity) Name() string {
	if !id.Trusted || len(id.Chain) == 0 || id.Chain[0] == nil {
		return ""
	}
	return certSubjectName(id.Chain[0])
}

// certSubjectName is the display name a certificate presents: Subject CN, or
// its first Organization.
func certSubjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return ""
}
