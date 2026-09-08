package c2pa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// Identity claims aggregation (CAWG Identity Assertion 1.1 §8.1): the named
// actor's identity signals — a verified ID document, a social-media account, an
// organisational affiliation — were gathered by an aggregator, which issued a
// W3C Verifiable Credential binding them to this asset. The credential is the
// embedded payload of a tagged COSE_Sign1 signed by the aggregator's key, which
// the credential's issuer DID names. Only did:jwk — the key written into the
// identifier itself — is resolved here; it needs no network. did:web is what
// the aggregators in the field use and is reported as an unsupported method.
//
// Where c2pa-rs and the spec differ, the spec is followed: the context and type
// are checked, an unsupported DID method has its own code, every algorithm the
// spec allows is accepted (c2pa-rs takes Ed25519 only), and the credential's
// validity window is also compared with the manifest's time-stamp.

const (
	icaContentType   = "application/vc"
	icaContextVC     = "https://www.w3.org/ns/credentials/v2"
	icaContextCAWG   = "https://cawg.io/identity/1.1/ica/context/"
	icaTypeVC        = "VerifiableCredential"
	icaTypeCAWG      = "IdentityClaimsAggregationCredential"
	maxICACredential = 1 << 20 // a credential larger than this is not one
)

// VerifiedIdentity is one identity signal an aggregator vouched for in an
// identity claims aggregation credential, as PRESENTED by the aggregator.
type VerifiedIdentity struct {
	// Type is the kind of signal: "cawg.document_verification",
	// "cawg.affiliation", "cawg.social_media", "cawg.crypto_wallet", ….
	Type string
	// Name is the actor's display name for this signal, when given.
	Name string
	// Username and URI locate the account for a social-media or wallet signal.
	Username string
	URI      string
	// VerifiedAt is when the aggregator verified the signal.
	VerifiedAt time.Time
	// Provider is who the aggregator verified the signal with.
	Provider IdentityProvider
}

// IdentityProvider names the service that issued an identity signal.
type IdentityProvider struct {
	ID   string
	Name string
}

// icaOutcome is what verifying an aggregation credential establishes.
type icaOutcome struct {
	issuer     string
	identities []VerifiedIdentity
	signedAt   time.Time
}

// verifyIdentityICA runs CAWG §8.1.5 over an identity assertion whose
// credential is an identity claims aggregation. Every failure is recorded at
// iuri with its cawg.ica.* code; checks that cannot proceed without an earlier
// one (a signature without a key) stop, the rest accumulate. It returns what
// the credential presents, filled as far as parsing got.
func (v *validator) verifyIdentityICA(ia identityAssertion, sp identitySignerPayload, iuri string, manifestSignedAt time.Time) icaOutcome {
	var out icaOutcome

	// §8.1.4: the signature MUST begin with the tagged COSE_Sign1 structure.
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.Signature); err != nil {
		explanation := "credential is not a tagged COSE_Sign1"
		if len(ia.Signature) > 0 && ia.Signature[0] != 0xd2 {
			explanation = "credential is not a TAGGED COSE_Sign1 (tag 18 required)"
		}
		v.add(StatusICAInvalidCOSESign1, iuri, explanation, err)
		return out
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil || !allowedCOSEAlg(alg) {
		v.add(StatusICAInvalidAlg, iuri, "credential's COSE alg is missing or not one the spec allows", err)
		return out
	}
	if ct, ok := msg.Headers.Protected[cose.HeaderLabelContentType]; !ok {
		v.add(StatusICAInvalidContentType, iuri, "credential has no content type; application/vc is required", nil)
	} else if s, isText := ct.(string); !isText || s != icaContentType {
		v.add(StatusICAInvalidContentType, iuri, fmt.Sprintf("credential content type is %v, not application/vc", ct), nil)
	}
	if len(msg.Payload) == 0 {
		v.add(StatusICAInvalidVerifiableCredential, iuri, "credential payload is not embedded in the COSE_Sign1", nil)
		return out
	}
	if len(msg.Payload) > maxICACredential {
		v.add(StatusICAInvalidVerifiableCredential, iuri, "credential payload is implausibly large", nil)
		return out
	}

	cred, err := parseICACredential(msg.Payload)
	if err != nil {
		v.add(StatusICAInvalidVerifiableCredential, iuri, "credential is not a valid identity claims aggregation credential", err)
		return out
	}
	out.issuer = cred.issuer
	out.identities = cred.identities()

	// Issuer: a DID whose method this validator resolves.
	pub, method, err := icaIssuerKey(cred.issuer)
	switch {
	case errors.Is(err, errICANotDID):
		v.add(StatusICAInvalidIssuer, iuri, "credential issuer is not a DID", err)
		return out
	case errors.Is(err, errICADIDMethod):
		v.add(StatusICADIDUnsupportedMethod, iuri, fmt.Sprintf("issuer DID method %q is not resolved here (only did:jwk)", method), nil)
		return out
	case err != nil:
		v.add(StatusICAInvalidDIDDocument, iuri, "issuer DID carries no usable public key", err)
		return out
	}
	if !keyFitsAlg(alg, pub) {
		v.add(StatusICAInvalidAlg, iuri, "credential's COSE alg does not fit the issuer's key", nil)
		return out
	}
	if verifier, err := cose.NewVerifier(alg, pub); err != nil {
		v.add(StatusICASignatureMismatch, iuri, "cannot build a verifier for the issuer's key", err)
	} else if err := msg.Verify(nil, verifier); err != nil {
		v.add(StatusICASignatureMismatch, iuri, "credential signature does not verify with the issuer's key", err)
	}

	// Time-stamp (§8.1.5.2.5): sigTst2 only; a v1 sigTst is ignored, as the
	// spec says a validator SHOULD.
	var credTime time.Time
	if token, v2 := extractTSToken(msg.Headers.Unprotected); v2 && len(token) > 0 {
		credTime = v.verifyICATimestamp(ia.Signature, token, iuri)
	}
	if !credTime.IsZero() {
		out.signedAt = credTime
	}

	// Validity (§8.1.5.2.6): validFrom against now, the credential's own
	// time-stamp and the manifest's.
	now := v.cfg.clock()
	if cred.validFrom == "" {
		v.add(StatusICAValidFromMissing, iuri, "credential has no validFrom (or issuanceDate)", nil)
	} else {
		from, err := parseVCTime(cred.validFrom)
		switch {
		case err != nil:
			v.add(StatusICAValidFromInvalid, iuri, "credential validFrom does not parse", err)
		case from.After(now):
			v.add(StatusICAValidFromInvalid, iuri, "credential validFrom is after the current time", nil)
		case !credTime.IsZero() && from.After(credTime):
			v.add(StatusICAValidFromInvalid, iuri, "credential validFrom is after the credential's own time-stamp", nil)
		case !manifestSignedAt.IsZero() && from.After(manifestSignedAt):
			v.add(StatusICAValidFromInvalid, iuri, "credential validFrom is after the manifest's time-stamp", nil)
		}
	}
	if cred.validUntil != "" {
		until, err := parseVCTime(cred.validUntil)
		switch {
		case err != nil:
			v.add(StatusICAValidUntilInvalid, iuri, "credential validUntil does not parse", err)
		case until.Before(now):
			v.add(StatusICAValidUntilInvalid, iuri, "credential validUntil is before the current time", nil)
		case !credTime.IsZero() && until.Before(credTime):
			v.add(StatusICAValidUntilInvalid, iuri, "credential validUntil is before the credential's own time-stamp", nil)
		case !manifestSignedAt.IsZero() && until.Before(manifestSignedAt):
			v.add(StatusICAValidUntilInvalid, iuri, "credential validUntil is before the manifest's time-stamp", nil)
		}
	}

	// The identity signals themselves.
	switch {
	case len(cred.subject.VerifiedIdentities) == 0:
		v.add(StatusICAVerifiedIdentitiesMissing, iuri, "credential lists no verifiedIdentities", nil)
	default:
		for i, vi := range cred.subject.VerifiedIdentities {
			if bad := vi.problem(); bad != "" {
				v.add(StatusICAVerifiedIdentitiesInvalid, iuri, fmt.Sprintf("verifiedIdentities[%d]: %s", i, bad), nil)
				break
			}
		}
	}

	// The credential describes THIS assertion's signer_payload (§8.1.5.4).
	if reason := cred.subject.C2PAAsset.mismatch(sp); reason != "" {
		v.add(StatusICASignerPayloadMismatch, iuri, "credential's c2paAsset differs from the assertion's signer_payload: "+reason, nil)
	}
	return out
}

// verifyICATimestamp checks a credential's sigTst2 token — bound to the COSE
// signature the way every C2PA time-stamp is — and its authority against the
// timestamp trust pool, recording cawg.ica.time_stamp.validated or .invalid. It
// returns the attested time when the token is validated.
func (v *validator) verifyICATimestamp(envelope, token []byte, iuri string) time.Time {
	protected, signature, ok := coseParts(envelope)
	if !ok {
		v.add(StatusICATimeStampInvalid, iuri, "credential COSE structure could not be read for the time-stamp binding", nil)
		return time.Time{}
	}
	counter, _ := cbor.Marshal(signature)
	chk, err := checkTimestampToken(token, coseCountersignData(counter, protected))
	if err != nil {
		v.add(StatusICATimeStampInvalid, iuri, "credential time-stamp token does not verify: "+err.Error(), err)
		return time.Time{}
	}
	if err := v.tsaChainOK(chk.signer, chk.certs, chk.tstInfo.genTime); err != nil {
		v.add(StatusICATimeStampInvalid, iuri, "credential time-stamp authority is not trusted", err)
		return time.Time{}
	}
	v.add(StatusICATimeStampValidated, iuri, "credential time-stamp verified", nil)
	return chk.tstInfo.genTime
}

// icaCredential is the identity claims aggregation credential as parsed:
// the fields the checks read, in the shapes VC 2.0 allows.
type icaCredential struct {
	context    []string
	types      []string
	issuer     string
	validFrom  string
	validUntil string
	subject    icaSubject
}

type icaSubject struct {
	VerifiedIdentities []icaVerifiedIdentity `json:"verifiedIdentities"`
	C2PAAsset          icaAsset              `json:"c2paAsset"`
}

type icaVerifiedIdentity struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	URI        string `json:"uri"`
	VerifiedAt string `json:"verifiedAt"`
	Provider   struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"provider"`
}

// problem names the first thing wrong with a verified identity entry, or "".
func (vi icaVerifiedIdentity) problem() string {
	switch {
	case vi.Type == "":
		return "no type"
	case vi.Provider.ID == "" || vi.Provider.Name == "":
		return "provider lacks id or name"
	case vi.VerifiedAt == "":
		return "no verifiedAt"
	}
	if _, err := parseVCTime(vi.VerifiedAt); err != nil {
		return "verifiedAt does not parse"
	}
	return ""
}

// icaAsset is credentialSubject.c2paAsset: the signer_payload the aggregator
// saw, in JSON.
type icaAsset struct {
	ReferencedAssertions []icaReference `json:"referenced_assertions"`
	SigType              string         `json:"sig_type"`
	Role                 []string       `json:"role"`
}

type icaReference struct {
	URL  string  `json:"url"`
	Alg  string  `json:"alg"`
	Hash icaHash `json:"hash"`
}

// mismatch compares the credential's copy of the payload with the assertion's
// and names the first difference, or "".
func (a icaAsset) mismatch(sp identitySignerPayload) string {
	if a.SigType != sp.SigType {
		return "sig_type"
	}
	if len(a.ReferencedAssertions) != len(sp.ReferencedAssertions) {
		return "referenced_assertions count"
	}
	for i, r := range a.ReferencedAssertions {
		want := sp.ReferencedAssertions[i]
		if r.URL != want.URL {
			return fmt.Sprintf("referenced_assertions[%d].url", i)
		}
		if r.Alg != "" && want.Alg != "" && !strings.EqualFold(r.Alg, want.Alg) {
			return fmt.Sprintf("referenced_assertions[%d].alg", i)
		}
		if subtle.ConstantTimeCompare(r.Hash, want.Hash) != 1 {
			return fmt.Sprintf("referenced_assertions[%d].hash", i)
		}
	}
	if len(a.Role) != len(sp.Roles) {
		return "role count"
	}
	for i := range a.Role {
		if a.Role[i] != sp.Roles[i] {
			return fmt.Sprintf("role[%d]", i)
		}
	}
	return ""
}

// icaHash is a referenced assertion's hash as a credential carries it: a
// base64 string per the VC's JSON, or — as c2pa-rs writes it — a JSON array of
// the ASCII bytes of that base64 string, or an array of raw bytes.
type icaHash []byte

func (h *icaHash) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		raw, err := decodeBase64Any(s)
		if err != nil {
			return fmt.Errorf("hash is not base64: %w", err)
		}
		*h = raw
		return nil
	}
	var nums []int
	if err := json.Unmarshal(b, &nums); err != nil {
		return errors.New("hash is neither a string nor a byte array")
	}
	raw := make([]byte, len(nums))
	for i, n := range nums {
		if n < 0 || n > 255 {
			return errors.New("hash byte out of range")
		}
		raw[i] = byte(n)
	}
	// c2pa-rs: the bytes are the ASCII of a base64 string.
	if decoded, err := decodeBase64Any(string(raw)); err == nil && isBase64Text(raw) {
		raw = decoded
	}
	*h = raw
	return nil
}

func isBase64Text(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '-', c == '_', c == '=':
		default:
			return false
		}
	}
	return true
}

// decodeBase64Any accepts standard or URL-safe base64, padded or not.
func decodeBase64Any(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if raw, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// parseICACredential decodes the VC JSON and applies the shape rules: the two
// required @context IRIs and types (spec §8.1.3; c2pa-rs skips this), an issuer
// as a string or {id}, validFrom|issuanceDate and validUntil|expirationDate, a
// credentialSubject as an object or a one-element array.
func parseICACredential(payload []byte) (icaCredential, error) {
	var raw struct {
		Context    json.RawMessage `json:"@context"`
		Type       json.RawMessage `json:"type"`
		Issuer     json.RawMessage `json:"issuer"`
		ValidFrom  string          `json:"validFrom"`
		Issuance   string          `json:"issuanceDate"`
		ValidUntil string          `json:"validUntil"`
		Expiration string          `json:"expirationDate"`
		Subject    json.RawMessage `json:"credentialSubject"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return icaCredential{}, fmt.Errorf("credential JSON: %w", err)
	}
	var c icaCredential
	var err error
	if c.context, err = stringOrList(raw.Context); err != nil {
		return c, fmt.Errorf("@context: %w", err)
	}
	if c.types, err = stringOrList(raw.Type); err != nil {
		return c, fmt.Errorf("type: %w", err)
	}
	for _, want := range []string{icaContextVC, icaContextCAWG} {
		if !contains(c.context, want) {
			return c, fmt.Errorf("@context lacks %s", want)
		}
	}
	for _, want := range []string{icaTypeVC, icaTypeCAWG} {
		if !contains(c.types, want) {
			return c, fmt.Errorf("type lacks %s", want)
		}
	}
	if err := json.Unmarshal(raw.Issuer, &c.issuer); err != nil {
		var obj struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw.Issuer, &obj); err != nil || obj.ID == "" {
			return c, errors.New("issuer is neither a string nor an object with an id")
		}
		c.issuer = obj.ID
	}
	c.validFrom = raw.ValidFrom
	if c.validFrom == "" {
		c.validFrom = raw.Issuance
	}
	c.validUntil = raw.ValidUntil
	if c.validUntil == "" {
		c.validUntil = raw.Expiration
	}
	if len(raw.Subject) == 0 {
		return c, errors.New("no credentialSubject")
	}
	if err := json.Unmarshal(raw.Subject, &c.subject); err != nil {
		var list []icaSubject
		if err := json.Unmarshal(raw.Subject, &list); err != nil || len(list) == 0 {
			return c, errors.New("credentialSubject is neither an object nor a non-empty array")
		}
		c.subject = list[0]
	}
	return c, nil
}

// identities converts the presented signals.
func (c icaCredential) identities() []VerifiedIdentity {
	out := make([]VerifiedIdentity, 0, len(c.subject.VerifiedIdentities))
	for _, vi := range c.subject.VerifiedIdentities {
		at, _ := parseVCTime(vi.VerifiedAt)
		out = append(out, VerifiedIdentity{
			Type: vi.Type, Name: vi.Name, Username: vi.Username, URI: vi.URI, VerifiedAt: at,
			Provider: IdentityProvider{ID: vi.Provider.ID, Name: vi.Provider.Name},
		})
	}
	return out
}

func stringOrList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("neither a string nor a list of strings")
	}
	return list, nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// parseVCTime reads a VC date-time: RFC 3339, with or without fractional
// seconds.
func parseVCTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

var (
	errICANotDID    = errors.New("issuer is not a DID")
	errICADIDMethod = errors.New("unsupported DID method")
)

// icaIssuerKey resolves an issuer DID to its public key. Only did:jwk — the
// key itself, base64url-encoded as a JWK in the identifier — is resolved; it
// returns the method name alongside so an unsupported one can be named. A
// fragment (#0) is ignored.
func icaIssuerKey(did string) (crypto.PublicKey, string, error) {
	did, _, _ = strings.Cut(did, "#")
	rest, ok := strings.CutPrefix(did, "did:")
	if !ok {
		return nil, "", errICANotDID
	}
	method, msid, ok := strings.Cut(rest, ":")
	if !ok || method == "" || msid == "" {
		return nil, method, errICANotDID
	}
	if method != "jwk" {
		return nil, method, errICADIDMethod
	}
	raw, err := decodeBase64Any(msid)
	if err != nil {
		return nil, method, fmt.Errorf("did:jwk is not base64url: %w", err)
	}
	pub, err := jwkPublicKey(raw)
	if err != nil {
		return nil, method, err
	}
	return pub, method, nil
}

// jwkPublicKey reads a JSON Web Key's public half with the standard library:
// OKP/Ed25519, EC P-256/384/521, RSA.
func jwkPublicKey(raw []byte) (crypto.PublicKey, error) {
	var k struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("JWK: %w", err)
	}
	field := func(s string) ([]byte, error) {
		if s == "" {
			return nil, errors.New("JWK field missing")
		}
		return decodeBase64Any(s)
	}
	switch k.Kty {
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("JWK OKP curve %q is not Ed25519", k.Crv)
		}
		x, err := field(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("JWK Ed25519 x is not 32 bytes")
		}
		return ed25519.PublicKey(x), nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("JWK EC curve %q is not supported", k.Crv)
		}
		x, err := field(k.X)
		if err != nil {
			return nil, err
		}
		y, err := field(k.Y)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) > size || len(y) > size {
			return nil, errors.New("JWK EC coordinate too long for its curve")
		}
		point := make([]byte, 1+2*size)
		point[0] = 4
		copy(point[1+size-len(x):], x)
		copy(point[1+2*size-len(y):], y)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("JWK EC point: %w", err)
		}
		return pub, nil
	case "RSA":
		n, err := field(k.N)
		if err != nil {
			return nil, err
		}
		e, err := field(k.E)
		if err != nil {
			return nil, err
		}
		if len(e) == 0 || len(e) > 4 {
			return nil, errors.New("JWK RSA exponent out of range")
		}
		ev := new(big.Int).SetBytes(e)
		if !ev.IsInt64() || ev.Int64() < 3 || ev.Int64() > 1<<31-1 {
			return nil, errors.New("JWK RSA exponent out of range")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev.Int64())}, nil
	}
	return nil, fmt.Errorf("JWK kty %q is not supported", k.Kty)
}

// keyFitsAlg reports whether a COSE algorithm can be verified with a key: the
// curve must match for ECDSA, RSA-PSS wants an RSA key, EdDSA an Ed25519 one.
func keyFitsAlg(alg cose.Algorithm, pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return alg == cose.AlgorithmEdDSA
	case *ecdsa.PublicKey:
		switch alg {
		case cose.AlgorithmES256:
			return k.Curve == elliptic.P256()
		case cose.AlgorithmES384:
			return k.Curve == elliptic.P384()
		case cose.AlgorithmES512:
			return k.Curve == elliptic.P521()
		}
		return false
	case *rsa.PublicKey:
		return alg == cose.AlgorithmPS256 || alg == cose.AlgorithmPS384 || alg == cose.AlgorithmPS512
	}
	return false
}

// didIdentifier is a DID with any DID URL fragment removed and surrounding
// space trimmed — the form WithIdentityIssuers compares. A credential names its
// issuer as a bare DID, while a verification method carries a fragment
// ("…#0"), and an operator should not have to know which they were handed.
func didIdentifier(did string) string {
	did, _, _ = strings.Cut(strings.TrimSpace(did), "#")
	return did
}
