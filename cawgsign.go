package c2pa

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Writing the CAWG identity assertion. Sign's pipeline owns the ordering — the
// identity is signed between the digest and the claim, over the boxes the
// claim will list — and this file owns the pieces: the payload, the reserved
// size, the signature, and the padding that makes the final assertion exactly
// the placeholder's length.

// labelPattern is the CAWG spec's label ABNF (§5.3): dot-separated components,
// each an alphanumeric followed by alphanumerics, "-" or "_", at least a
// namespace and one component.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)+$`)

// validateIdentityInfo checks Manifest.Identity against the Signer and the
// manifest's fixed assertions: it needs an identity signer; every reference
// must name an assertion being written, once, and not the hard binding (always
// referenced); roles must be labels.
func validateIdentityInfo(info IdentityInfo, hasSigner bool, fixed []namedBox) error {
	if len(info.Roles) == 0 && len(info.References) == 0 {
		return nil
	}
	if !hasSigner {
		return fmt.Errorf("%w: Manifest.Identity is set but the Signer has no identity (WithIdentitySigner)", ErrManifestInvalid)
	}
	seen := make(map[string]bool, len(info.References))
	for _, label := range info.References {
		switch {
		case strings.HasPrefix(label, "c2pa.hash."):
			return fmt.Errorf("%w: identity reference %q: the hard binding is always referenced", ErrManifestInvalid, label)
		case seen[label]:
			return fmt.Errorf("%w: identity reference %q listed twice", ErrManifestInvalid, label)
		}
		seen[label] = true
		found := false
		for _, nb := range fixed {
			if nb.label == label {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: identity reference %q names no assertion of this manifest", ErrManifestInvalid, label)
		}
	}
	for _, r := range info.Roles {
		if !labelPattern.MatchString(r) {
			return fmt.Errorf("%w: identity role %q is not a label (e.g. %q)", ErrManifestInvalid, r, RoleCreator)
		}
	}
	return nil
}

// identityTemplate is the signer_payload with every hash zeroed: the same
// encoded length as the final one, so the reserve can be computed before the
// layout converges.
func identityTemplate(bindingLabel string, info IdentityInfo, hashLen int) identitySignerPayload {
	refs := make([]identityHashedURI, 0, 1+len(info.References))
	refs = append(refs, identityHashedURI{URL: assertionURL(bindingLabel), Hash: make([]byte, hashLen)})
	for _, label := range info.References {
		refs = append(refs, identityHashedURI{URL: assertionURL(label), Hash: make([]byte, hashLen)})
	}
	return identitySignerPayload{ReferencedAssertions: refs, SigType: identitySigTypeX509, Roles: info.Roles}
}

// identityPayload builds the signer_payload over the assembled boxes: the hard
// binding (boxes[0]) first, then each referenced label — the hashed_uri
// computed by the same function that computes the claim's entries, so the two
// agree by construction. No alg key: the claim's alg covers it, as c2pa-rs
// writes.
func identityPayload(alg string, boxes []namedBox, info IdentityInfo) (identitySignerPayload, error) {
	refs := make([]identityHashedURI, 0, 1+len(info.References))
	add := func(nb namedBox) error {
		ref, err := hashedURI(alg, assertionURL(nb.label), nb.box)
		if err != nil {
			return err
		}
		hash, _ := ref["hash"].([]byte)
		refs = append(refs, identityHashedURI{URL: assertionURL(nb.label), Hash: hash})
		return nil
	}
	if len(boxes) == 0 {
		return identitySignerPayload{}, errors.New("c2pa: internal: no hard binding to reference")
	}
	if err := add(boxes[0]); err != nil {
		return identitySignerPayload{}, err
	}
	for _, label := range info.References {
		for _, nb := range boxes[1:] {
			if nb.label == label {
				if err := add(nb); err != nil {
					return identitySignerPayload{}, err
				}
				break
			}
		}
	}
	if len(refs) != 1+len(info.References) {
		return identitySignerPayload{}, errors.New("c2pa: internal: identity reference not among the assembled boxes")
	}
	return identitySignerPayload{ReferencedAssertions: refs, SigType: identitySigTypeX509, Roles: info.Roles}, nil
}

// identityReserveSize is the encoded length of the identity assertion for this
// payload shape once its COSE envelope is padded to coseReserve and pad1 is
// empty — exactly the final length, since every field is fixed-width from here.
func identityReserveSize(template identitySignerPayload, coseReserve int) (int, error) {
	payload, err := identityEncMode.Marshal(template)
	if err != nil {
		return 0, err
	}
	b, err := identityEncMode.Marshal(identityAssertion{
		SignerPayload: payload, Signature: make([]byte, coseReserve), Pad1: []byte{},
	})
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// signIdentity signs the payload with the identity key — a detached COSE_Sign1
// like the claim's, timestamped like the claim's when a TSA is configured,
// padded to coseReserve — and assembles the assertion padded to reserve. It
// returns the assertion bytes and the timestamp token's certificates for the
// self-check pool.
func (s *Signer) signIdentity(ctx context.Context, sp identitySignerPayload, coseReserve, reserve int, timestamped bool) ([]byte, []*x509.Certificate, error) {
	payload, err := identityEncMode.Marshal(sp)
	if err != nil || len(payload) == 0 {
		return nil, nil, fmt.Errorf("c2pa: internal: encoding signer_payload: %v", err)
	}
	msg, err := newSign1(rand.Reader, s.identity.key, s.identity.alg, s.identity.chainDER, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: identity: %v", ErrSignerKey, err)
	}
	var tokenCerts []*x509.Certificate
	if timestamped {
		tbs, err := coseTimestampTBS(msg)
		if err != nil {
			return nil, nil, fmt.Errorf("c2pa: internal: %w", err)
		}
		token, err := s.fetchTimestamp(ctx, tbs)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: identity: %w", ErrTimestamp, err)
		}
		attachSigTst2(msg, token)
		if sd, ok := parseCMSSignedData(token); ok {
			tokenCerts = sd.certs
		}
	}
	envelope, err := marshalSign1Padded(msg, coseReserve)
	if err != nil {
		return nil, nil, fmt.Errorf("c2pa: internal: identity %w", err)
	}
	out, err := marshalIdentityPadded(identityAssertion{SignerPayload: payload, Signature: envelope}, reserve)
	if err != nil {
		return nil, nil, fmt.Errorf("c2pa: internal: %w", err)
	}
	return out, tokenCerts, nil
}

// marshalIdentityPadded encodes the assertion at exactly reserve bytes by
// sizing pad1 — always present, empty when nothing is needed — and, at the
// CBOR width steps a single byte string cannot hit (a 25-byte pad cannot be
// made from one bstr, §6.2), a pad2. It never truncates: an assertion already
// over the reserve is an error, which is how a size disagreement surfaces.
func marshalIdentityPadded(ia identityAssertion, reserve int) ([]byte, error) {
	ia.Pad1, ia.Pad2 = []byte{}, nil
	base, err := identityEncMode.Marshal(ia)
	if err != nil {
		return nil, err
	}
	if len(base) == reserve {
		return base, nil
	}
	if len(base) > reserve {
		return nil, fmt.Errorf("identity assertion is %d bytes, over the %d reserved", len(base), reserve)
	}
	need := reserve - len(base)
	// Growing pad1 from empty to n zeros costs header(n) + n - 1 (its 1-byte
	// empty header is already in base); pad2 with m zeros costs its 5-byte key,
	// a 1-byte header and m zeros while m < 24.
	for m := -1; m < 24; m++ {
		remaining := need
		if m >= 0 {
			remaining -= 5 + 1 + m
		}
		n, ok := padGrowthFor(remaining)
		if !ok {
			continue
		}
		ia.Pad1 = make([]byte, n)
		if m >= 0 {
			ia.Pad2 = make([]byte, m)
		} else {
			ia.Pad2 = nil
		}
		out, err := identityEncMode.Marshal(ia)
		if err != nil {
			return nil, err
		}
		if len(out) == reserve {
			return out, nil
		}
	}
	return nil, fmt.Errorf("could not pad a %d-byte identity assertion to %d bytes", len(base), reserve)
}

// padGrowthFor solves header(n) + n - 1 == need for a byte string growing from
// empty; ok is false at the widths no n satisfies.
func padGrowthFor(need int) (int, bool) {
	for _, hdr := range []int{1, 2, 3, 5} {
		n := need + 1 - hdr
		if n >= 0 && bstrHeaderLen(n) == hdr {
			return n, true
		}
	}
	return 0, false
}
