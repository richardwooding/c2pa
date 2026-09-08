package c2pa

import (
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// verifyIdentities validates every CAWG identity assertion of manifest m (CAWG
// Identity Assertion 1.1 §7) and, for the active manifest, lists them in the
// result. Statuses are recorded at "<manifest label>/<assertion label>" — the
// spec asks for the identity assertion's own URL, and keeping them off the
// manifest's URI is what leaves VerifiedSigner's reading of the claim signer
// untouched.
//
// manifestSignedAt is the manifest's OWN trusted time-stamp (zero when it has
// none): an aggregation credential's validity window is compared with it.
func (v *validator) verifyIdentities(m *parsedManifest, uri string, depth int, manifestSignedAt time.Time) {
	var entries []claimAssertionEntry
	for _, a := range m.assertions {
		if !isIdentityLabel(a.label) {
			continue
		}
		if v.cancelled(uri+"/"+a.label, "before verifying an identity assertion") {
			return
		}
		if entries == nil {
			entries = claimAssertionEntries(m.claim)
		}
		id := v.verifyIdentity(m, a, entries, uri+"/"+a.label, manifestSignedAt)
		if depth == 0 {
			v.res.Identities = append(v.res.Identities, id)
		}
	}
}

// verifyIdentity checks one identity assertion: its CBOR (§7.1 → cbor.invalid),
// its zero padding (pad.invalid), its references against the claim's own
// hashed-uri entries (assertion.mismatch / .duplicate / hard_binding_missing),
// then the credential named by sig_type. An X.509 credential gets the C2PA
// signature, time-stamp, chain and revocation checks at the identity's URI
// (§8.2.2); an aggregation credential gets the §8.1.5 checks (cawgica.go).
// Only an assertion with no failure of its own is well-formed, and trusted on
// top of that when its chain reaches an identity anchor (§7.2.1, §9.3).
func (v *validator) verifyIdentity(m *parsedManifest, a rawAssertion, entries []claimAssertionEntry, iuri string, manifestSignedAt time.Time) Identity {
	id := Identity{Label: a.label, URI: iuri}
	start := len(v.res.Statuses)
	if a.tbox != "cbor" {
		v.add(StatusIdentityCBORInvalid, iuri, "identity assertion is not a CBOR box", nil)
		return id
	}
	ia, sp, unevaluated, err := decodeIdentityAssertion(a.data)
	if err != nil {
		v.add(StatusIdentityCBORInvalid, iuri, "identity assertion CBOR is malformed", err)
		return id
	}
	id.SigType = sp.SigType
	id.Roles = sp.Roles
	if len(unevaluated) > 0 {
		v.add(StatusUnsupported, iuri, "signer_payload fields not evaluated: "+strings.Join(unevaluated, ", "), nil)
	}
	if !allZero(ia.Pad1) || !allZero(ia.Pad2) {
		v.add(StatusIdentityPadInvalid, iuri, "pad1 or pad2 holds non-zero bytes", nil)
	}
	id.Referenced = v.checkIdentityReferences(m.label, sp, entries, iuri)

	var trusted bool
	switch sp.SigType {
	case identitySigTypeX509:
		id.Chain, id.SignedAt, trusted = v.verifyIdentityX509(ia, iuri)
	case identitySigTypeICA:
		out := v.verifyIdentityICA(ia, sp, iuri, manifestSignedAt)
		id.Issuer, id.VerifiedIdentities, id.SignedAt = out.issuer, out.identities, out.signedAt
		if v.failedSince(start) {
			return id
		}
		v.add(StatusICACredentialValid, iuri, "identity claims aggregation credential is valid", nil)
		// The credential is genuine; whether its issuer is one to believe is a
		// separate question, and one only the caller can answer — CAWG
		// publishes no aggregator trust list. See WithIdentityIssuers.
		switch issuers := v.cfg.identityIssuers; {
		case issuers == nil:
			id.Valid = true
			v.add(StatusIdentityWellFormed, iuri, "aggregation credential valid; issuer trust is not evaluated", nil)
		case issuers[didIdentifier(out.issuer)]:
			id.Valid, id.Trusted = true, true
			v.add(StatusIdentityTrusted, iuri, "aggregation credential valid; its issuer is a trusted identity claims aggregator", nil)
		default:
			// §8.1.5.2.3: "a DID issued from an untrusted source". Valid stays
			// false, so Identity.Valid keeps meaning "well-formed or trusted
			// was recorded" for both sig types.
			v.add(StatusICAUntrustedIssuer, iuri, fmt.Sprintf("credential issuer %q is not a trusted identity claims aggregator", out.issuer), nil)
		}
		return id
	default:
		v.add(StatusIdentitySigTypeUnknown, iuri, fmt.Sprintf("unrecognised sig_type %q", sp.SigType), nil)
		return id
	}
	if v.failedSince(start) {
		return id
	}
	id.Valid = true
	if trusted {
		id.Trusted = true
		v.add(StatusIdentityTrusted, iuri, "identity signature valid; credential reaches an identity trust anchor", nil)
	} else if v.cfg.identityTrust == nil {
		v.add(StatusIdentityWellFormed, iuri, "identity signature valid; no identity trust anchors configured", nil)
	} else {
		v.add(StatusIdentityWellFormed, iuri, "identity signature valid; credential does not reach an identity trust anchor", nil)
	}
	return id
}

// failedSince reports whether a failure was recorded at or after index start.
func (v *validator) failedSince(start int) bool {
	for i := start; i < len(v.res.Statuses); i++ {
		if v.res.Statuses[i].Severity == SeverityFailure {
			return true
		}
	}
	return false
}

// checkIdentityReferences applies §5.1.1/§7.1 to signer_payload.referenced_assertions:
// every entry must name an assertion of THIS manifest that the claim lists with
// the same hash, no assertion may be referenced twice, and one of them must be
// a hard binding (a c2pa.hash.* label). It returns the referenced labels in
// payload order — an unresolvable url is kept verbatim so the reader sees what
// was claimed.
func (v *validator) checkIdentityReferences(manifestLabel string, sp identitySignerPayload, entries []claimAssertionEntry, iuri string) []string {
	labels := make([]string, 0, len(sp.ReferencedAssertions))
	seen := make(map[string]bool, len(sp.ReferencedAssertions))
	hardBinding := false
	for _, ref := range sp.ReferencedAssertions {
		label, ok := identityReferenceLabel(ref.URL, manifestLabel)
		key := label
		if !ok {
			key = ref.URL
			labels = append(labels, ref.URL)
		} else {
			labels = append(labels, label)
		}
		if seen[key] {
			v.add(StatusIdentityAssertionDuplicate, iuri, fmt.Sprintf("assertion %q is referenced more than once", ref.URL), nil)
			continue
		}
		seen[key] = true
		if !ok {
			v.add(StatusIdentityAssertionMismatch, iuri, fmt.Sprintf("referenced url %q is not an assertion of this manifest", ref.URL), nil)
			continue
		}
		e, found := claimEntryForLabel(entries, label)
		if !found {
			v.add(StatusIdentityAssertionMismatch, iuri, fmt.Sprintf("referenced assertion %q is not listed in the claim", label), nil)
			continue
		}
		if ref.Alg != "" && e.alg != "" && !strings.EqualFold(ref.Alg, e.alg) {
			v.add(StatusIdentityAssertionMismatch, iuri, fmt.Sprintf("referenced assertion %q names hash algorithm %q, the claim %q", label, ref.Alg, e.alg), nil)
			continue
		}
		if subtle.ConstantTimeCompare(ref.Hash, e.hash) != 1 {
			v.add(StatusIdentityAssertionMismatch, iuri, fmt.Sprintf("referenced assertion %q hash differs from the claim's", label), nil)
			continue
		}
		if strings.HasPrefix(label, "c2pa.hash.") {
			hardBinding = true
		}
	}
	if !hardBinding {
		v.add(StatusIdentityHardBindingMissing, iuri, "referenced_assertions names no hard binding (c2pa.hash.*) assertion", nil)
	}
	return labels
}

// claimEntryForLabel finds the claim's hashed-uri entry for an assertion label.
func claimEntryForLabel(entries []claimAssertionEntry, label string) (claimAssertionEntry, bool) {
	for _, e := range entries {
		if assertionLabelFromURL(e.url) == label {
			return e, true
		}
	}
	return claimAssertionEntry{}, false
}

// verifyIdentityX509 runs C2PA §15.5–15.7 over an identity's COSE_Sign1 with
// the signer_payload bytes as the payload (CAWG §8.2.2), recording at iuri:
// the signature, the time-stamp (a v1 token is invalid here), the certificate
// validity window, the chain against the identity anchors, and revocation. It
// returns the chain as presented, the signing time when the time-stamp is
// trusted, and whether the chain reached an anchor.
func (v *validator) verifyIdentityX509(ia identityAssertion, iuri string) (chain []*x509.Certificate, signedAt time.Time, trusted bool) {
	chain, _, _ = v.verifySign1(ia.Signature, ia.SignerPayload, "identity", iuri)

	verifyTime := v.cfg.clock()
	genTime, tsTrusted := v.verifyTimestampOf(ia.Signature, ia.SignerPayload, iuri, false)
	if tsTrusted {
		signedAt = genTime
	}
	if !genTime.IsZero() {
		// As for the claim: an attested genTime pins the validity window even
		// when its TSA is unanchored (timeStamp.untrusted already stands).
		verifyTime = genTime
	}
	if len(chain) == 0 {
		return nil, signedAt, false // verifySign1 reported why
	}
	if leaf := chain[0]; !genTime.IsZero() &&
		(genTime.Before(leaf.NotBefore) || genTime.After(leaf.NotAfter)) {
		v.add(StatusTimeStampOutsideValidity, iuri,
			"timestamp genTime is outside the identity certificate's validity period", nil)
	}
	trusted = v.verifyIdentityChain(chain, verifyTime, iuri)
	v.checkRevocation(chain, iuri, StatusIdentityCredentialRevoked)
	return chain, signedAt, trusted
}

// verifyIdentityChain is verifyChain for an identity credential, with one
// difference: a chain that reaches no anchor is not a failure. The CAWG spec
// makes that outcome a success — cawg.identity.well-formed, "no root of trust
// identified" (§7.2.1) — and with no anchors configured by default, a failure
// here would make every asset carrying an identity invalid. The C2PA
// certificate profile (§14.5.2) is enforced regardless, on the presented chain
// when no path could be built: a CA leaf or a SHA-1 chain is an invalid
// credential whoever vouches for it. Note only the leaf's validity window is
// visible without an anchor; x509 checks it before looking for one.
func (v *validator) verifyIdentityChain(certs []*x509.Certificate, verifyTime time.Time, uri string) bool {
	path, err := buildTrustedPath(certs, v.identityTrustPool(), verifyTime)
	if err != nil {
		var unknownAuth x509.UnknownAuthorityError
		if errors.As(err, &unknownAuth) {
			for _, msg := range certProfileViolations(certs, certs[0], signingEKUOK) {
				v.add(StatusSigningCredentialInvalid, uri, msg, nil)
			}
			return false
		}
		code, explanation := chainErrorStatus(err)
		v.add(code, uri, explanation, err)
		return false
	}
	if !v.checkCertProfile(path, certs[0], signingEKUOK, uri) {
		return false
	}
	v.add(StatusSigningCredentialTrusted, uri, "identity certificate chain validated", nil)
	return true
}
