package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/veraison/go-cose"
)

// Sign is the writer: it embeds a signed Content Credentials manifest into an
// asset. The pipeline is the validator's steps run backwards — assertions, the
// claim that hashes them, the COSE signature over the claim, the container
// framing — and every output is run through Validate before it is written, so
// this package can never emit a file its own verifier rejects. The interop
// oracle is c2pa-rs's c2patool, which CI runs over every container's output.

// Errors Sign and NewSigner return. Every error is wrapped with detail; test
// with errors.Is.
var (
	// ErrNoInput is returned when the reader or writer is nil.
	ErrNoInput = errors.New("c2pa: nil reader or writer")
	// ErrUnsupportedContainer is returned for a container Sign cannot write
	// into, or an asset with a feature this release does not write into.
	ErrUnsupportedContainer = errors.New("c2pa: container cannot be signed")
	// ErrFragmentedBMFF is returned for a fragmented MP4 (a 'moof', 'sidx' or
	// 'styp' box, or merkle boxes): its binding is a Merkle tree per fragment,
	// which this release does not author.
	ErrFragmentedBMFF = errors.New("c2pa: fragmented BMFF is not signable in this release")
	// ErrMalformedAsset is returned when the input does not parse as the named
	// container, or carries a manifest store that cannot be chained.
	ErrMalformedAsset = errors.New("c2pa: asset could not be parsed for embedding")
	// ErrAssetTooLarge is returned when the input reaches ValidateMaxScan.
	ErrAssetTooLarge = errors.New("c2pa: asset exceeds the signing size cap")
	// ErrStoreTooLarge is returned when the manifest store would exceed 64 MiB.
	ErrStoreTooLarge = errors.New("c2pa: manifest store exceeds the size cap")
	// ErrManifestInvalid is returned for a Manifest Sign will not write: no
	// leading c2pa.created/c2pa.opened action, a reserved or duplicate
	// assertion label, an unencodable value, or c2pa.created on an asset that
	// already carries a manifest.
	ErrManifestInvalid = errors.New("c2pa: manifest is invalid")
	// ErrSignerKey is returned for a key whose type or size no COSE algorithm
	// the C2PA profile allows can use.
	ErrSignerKey = errors.New("c2pa: signing key unusable")
	// ErrSignerChain is returned for a certificate chain that does not match
	// the key, does not link, is not currently valid, or fails the C2PA
	// certificate profile Validate enforces.
	ErrSignerChain = errors.New("c2pa: certificate chain rejected")
	// ErrSignerOption is returned for an option value that cannot be used.
	ErrSignerOption = errors.New("c2pa: signer option invalid")
	// ErrTimestamp is returned when the timestamp authority named by
	// WithTimestampAuthority could not be reached, rejected the request, or
	// returned a token that does not verify over this signature or does not
	// echo the request's nonce. Nothing is written.
	ErrTimestamp = errors.New("c2pa: timestamp authority")
	// ErrSelfCheckFailed is returned when the signed output fails this
	// package's own Validate; nothing is written when it does.
	ErrSelfCheckFailed = errors.New("c2pa: signed output did not validate")
)

// Actions a Manifest's first action may be (spec §10.2: a standard manifest's
// actions assertion opens with the action that brought the asset into being or
// into this workflow).
const (
	// ActionCreated says the asset was created here. It cannot be used on an
	// asset that already carries a manifest — a prior manifest proves that
	// something preceded this one.
	ActionCreated = "c2pa.created"
	// ActionOpened says an existing asset was opened; Sign records what was
	// opened as a parentOf ingredient, chaining any prior manifest.
	ActionOpened = "c2pa.opened"
)

// Digital source types for Action.DigitalSourceType (IPTC NewsCodes; the
// "empty" value is C2PA's own).
const (
	DigitalSourceTypeEmpty                   = "http://c2pa.org/digitalsourcetype/empty"
	DigitalSourceTypeDigitalCapture          = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
	DigitalSourceTypeTrainedAlgorithmicMedia = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
)

// Manifest is what a Sign call says about one asset. Actions is required and
// its first entry must be ActionCreated or ActionOpened; Sign refuses a
// manifest without one rather than defaulting to "created", which would be a
// provenance claim the caller did not make. Assertions are written after the
// ones Sign generates (the hard binding, the ingredient, the actions); their
// labels may not be ones Sign writes itself.
type Manifest struct {
	Title      string
	Actions    []Action
	Assertions []Assertion
}

// Action is one entry of the c2pa.actions.v2 assertion. DigitalSourceType is
// recommended for ActionCreated. Parameters are copied as given; for the
// first action of an ActionOpened manifest Sign adds parameters.ingredients
// itself, pointing at the parentOf ingredient.
type Action struct {
	Action            string
	DigitalSourceType string
	SoftwareAgent     GeneratorInfo
	Parameters        map[string]any
}

// GeneratorInfo names a piece of software: claim_generator_info and an
// action's softwareAgent. Version is optional.
type GeneratorInfo struct {
	Name    string
	Version string
}

// Assertion is a caller-supplied assertion. Exactly one of Value (encoded as
// deterministic CBOR — a cbor.RawMessage passes through verbatim) or JSON
// (written as a JSON content box) must be set.
type Assertion struct {
	Label string
	Value any
	JSON  []byte
}

// SignerOption configures a Signer. See the With* constructors.
type SignerOption func(*signerConfig)

type signerConfig struct {
	generator GeneratorInfo
	vendor    string
	hashAlg   string
	tsaURL    string
	tsaClient *http.Client
}

// WithClaimGenerator sets claim_generator_info, the software that produced the
// manifest (default: this module's path and version).
func WithClaimGenerator(name, version string) SignerOption {
	return func(c *signerConfig) { c.generator = GeneratorInfo{Name: name, Version: version} }
}

// WithVendor appends ":<vendor>" (lowercased; 1–32 visible characters, no
// space or colon) to every manifest label: urn:c2pa:<uuid>:<vendor>.
func WithVendor(vendor string) SignerOption {
	return func(c *signerConfig) { c.vendor = vendor }
}

// WithHashAlgorithm sets the hash used for the claim's hashed URIs and the hard
// binding: "sha256" (default), "sha384" or "sha512".
func WithHashAlgorithm(alg string) SignerOption {
	return func(c *signerConfig) { c.hashAlg = alg }
}

// WithTimestampAuthority enables RFC 3161 timestamping (§13.2): every Sign
// POSTs a TimeStampReq to url and stores the verified TimeStampToken in the
// signature's sigTst2 header, so validators can pin the signing time without
// trusting the clock. The reply is checked with the validator's own code
// before it is embedded; a reply that fails the check, or an authority that
// cannot be reached, fails the sign with ErrTimestamp. Without this option Sign
// makes no network requests.
func WithTimestampAuthority(url string) SignerOption {
	return func(c *signerConfig) { c.tsaURL = url }
}

// WithTimestampHTTPClient sets the client used to reach the timestamp
// authority (default: a client with a 30-second timeout). WithHTTPClient is
// Validate's option for revocation fetches, hence the distinct name.
func WithTimestampHTTPClient(client *http.Client) SignerOption {
	return func(c *signerConfig) { c.tsaClient = client }
}

func defaultSignerConfig() signerConfig {
	return signerConfig{
		generator: GeneratorInfo{Name: "github.com/richardwooding/c2pa", Version: moduleVersion()},
		hashAlg:   "sha256",
	}
}

// moduleVersion is this module's version as the consuming binary recorded it,
// or "dev" when it is the main module or the build carries no info.
func moduleVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/richardwooding/c2pa" && d.Version != "" {
				return d.Version
			}
		}
	}
	return "dev"
}

// Signer signs assets with Content Credentials. It is configured once with
// what is per-signer — the key, its certificate chain, the claim generator —
// and Sign takes what is per-asset. A Signer keeps no per-call state, so it is
// safe for concurrent use to the extent its key is.
//
// The COSE algorithm is inferred from the key's public half (§14.5.1): P-256 →
// ES256, P-384 → ES384, P-521 → ES512, RSA of at least 2048 bits → PS256,
// Ed25519 → EdDSA. Any crypto.Signer works — an in-memory key, an HSM or KMS
// wrapper, or a WebCrypto-backed key in a browser. Counterpart: c2pa-rs's
// Signer trait.
type Signer struct {
	key      crypto.Signer
	alg      cose.Algorithm
	sigLen   int
	chain    []*x509.Certificate
	chainDER [][]byte
	cfg      signerConfig
}

// NewSigner validates the key and chain up front so that Sign can only fail on
// the asset. chain is leaf first, then intermediates; the trust anchor may be
// omitted — validators build the path to their own anchors, so a root in the
// file is dead weight — and a single self-signed certificate is accepted. The
// leaf must match the key, each certificate must be issued by the next, the
// leaf must be valid now, and the chain must satisfy the C2PA certificate
// profile (§14.5.2) exactly as Validate enforces it: digitalSignature key
// usage, a constrained signing EKU, a non-CA leaf, no SHA-1/MD5, RSA of at
// least 2048 bits. Never panics.
//
// A key that can only sign whole messages — WebCrypto's SubtleCrypto.sign,
// some HSM and KMS APIs — implements the standard crypto.MessageSigner as
// well. Sign then hands it the COSE Sig_structure instead of a digest, with
// the opts and signature encoding x509.CreateCertificate uses (the hash for
// ECDSA, PSS options for RSA, crypto.Hash(0) for Ed25519; DER for ECDSA, raw
// for the others), and never calls its Sign method.
func NewSigner(key crypto.Signer, chain []*x509.Certificate, opts ...SignerOption) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil key", ErrSignerKey)
	}
	cfg := defaultSignerConfig()
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.generator.Name == "" {
		return nil, fmt.Errorf("%w: claim generator name is empty", ErrSignerOption)
	}
	if _, ok := hashByName(cfg.hashAlg); !ok {
		return nil, fmt.Errorf("%w: unsupported hash algorithm %q", ErrSignerOption, cfg.hashAlg)
	}
	if cfg.vendor != "" {
		cfg.vendor = strings.ToLower(cfg.vendor)
		if !validVendor(cfg.vendor) {
			return nil, fmt.Errorf("%w: vendor %q must be 1-32 visible characters without space or colon", ErrSignerOption, cfg.vendor)
		}
	}
	if cfg.tsaURL != "" {
		u, err := url.Parse(cfg.tsaURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%w: timestamp authority %q is not an http(s) URL", ErrSignerOption, cfg.tsaURL)
		}
	}
	alg, sigLen, err := coseAlgorithmFor(key.Public())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignerKey, err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: no certificates", ErrSignerChain)
	}
	certs := make([]*x509.Certificate, len(chain))
	der := make([][]byte, len(chain))
	for i, c := range chain {
		if c == nil {
			return nil, fmt.Errorf("%w: certificate %d is nil", ErrSignerChain, i)
		}
		// parseCert repairs an id-RSASSA-PSS SPKI that x509 leaves without a
		// public key, the same way the validator does.
		p, err := parseCert(c.Raw)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %v", ErrSignerChain, i, err)
		}
		certs[i], der[i] = p, p.Raw
	}
	leafPub, ok := certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !leafPub.Equal(key.Public()) {
		return nil, fmt.Errorf("%w: leaf certificate does not match the key", ErrSignerChain)
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("%w: certificate %d is not issued by certificate %d: %v", ErrSignerChain, i, i+1, err)
		}
	}
	if now := time.Now(); now.Before(certs[0].NotBefore) || now.After(certs[0].NotAfter) {
		return nil, fmt.Errorf("%w: leaf certificate is not valid now (%s to %s)", ErrSignerChain,
			certs[0].NotBefore.Format(time.RFC3339), certs[0].NotAfter.Format(time.RFC3339))
	}
	if violations := certProfileViolations(certs, certs[0], signingEKUOK); len(violations) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrSignerChain, strings.Join(violations, "; "))
	}
	return &Signer{key: key, alg: alg, sigLen: sigLen, chain: certs, chainDER: der, cfg: cfg}, nil
}

// Sign reads the whole asset from in (up to ValidateMaxScan), builds a
// c2pa.claim.v2 manifest carrying the container's hard binding, signs it once
// with COSE_Sign1 into an envelope of reserved size, embeds the manifest store
// where the C2PA specification puts it for that container (Annex A), validates
// the result with this package's own Validate, and only then writes it to out.
// On any error nothing is written.
//
// An asset that already carries a manifest store keeps every prior manifest:
// they are carried into the new store verbatim and the new manifest names the
// previous active one as its parentOf ingredient, so provenance chains rather
// than being replaced. The manifest's first action must then be ActionOpened.
//
// BMFF assets (MP4, MOV, HEIC, AVIF) are bound with c2pa.hash.bmff.v3 and the
// C2PA box is inserted after 'ftyp', with every 'stco', 'co64', 'saio' and
// 'iloc' offset rewritten to follow. Fragmented files are refused with
// ErrFragmentedBMFF: their binding is a Merkle tree per fragment, which this
// release does not author.
//
// Like Validate, Sign never panics; malformed or oversized input, a manifest it
// will not write, or a failed self-check is an error. Counterpart: c2pa-rs's
// Builder::sign.
func (s *Signer) Sign(ctx context.Context, container Container, in io.Reader, out io.Writer, m Manifest) error {
	if in == nil || out == nil {
		return ErrNoInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := embedderFor(container); !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedContainer, string(container))
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	asset, err := io.ReadAll(io.LimitReader(in, int64(ValidateMaxScan)))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedAsset, err)
	}
	if len(asset) >= ValidateMaxScan {
		return ErrAssetTooLarge
	}
	if len(asset) == 0 {
		return fmt.Errorf("%w: empty input", ErrMalformedAsset)
	}
	var hb hardBinding = dataHashBinding{container: container, alg: s.cfg.hashAlg}
	if container == BMFF {
		hb = bmffFlatBinding{alg: s.cfg.hashAlg}
	}
	final, err := s.sign(ctx, container, asset, m, hb)
	if err != nil {
		return err
	}
	if _, err := out.Write(final); err != nil {
		return fmt.Errorf("c2pa: writing signed asset: %w", err)
	}
	return nil
}

// hardBinding is what differs between hard bindings inside the one signing
// pipeline: the assertion written into the store, the digest over the
// converged layout, the ranges the drift check ignores, and how the asset as
// found (for the parentOf ingredient) and the output (the self-check) are
// validated. Everything else in sign — labels, the layout fixpoint, the single
// signature, the padded envelope, prior-manifest chaining — is the same for
// every binding, which is why it is one function.
type hardBinding interface {
	label() string
	matchCode() StatusCode
	payload(excl []byteRange, digest []byte) ([]byte, error)
	digest(ctx context.Context, layout []byte, excl []byteRange) ([]byte, error)
	compareRanges(ctx context.Context, layout []byte, excl []byteRange) ([]byteRange, error)
	validatePrior(ctx context.Context, asset []byte) ValidationResult
	validateOutput(ctx context.Context, final []byte, opts []ValidateOption) ValidationResult
}

// dataHashBinding is c2pa.hash.data: the file minus the store's byte ranges.
type dataHashBinding struct {
	container Container
	alg       string
}

func (dataHashBinding) label() string         { return "c2pa.hash.data" }
func (dataHashBinding) matchCode() StatusCode { return StatusAssertionDataHashMatch }
func (b dataHashBinding) payload(excl []byteRange, digest []byte) ([]byte, error) {
	return dataHashAssertion(b.alg, excl, digest)
}
func (b dataHashBinding) digest(_ context.Context, layout []byte, excl []byteRange) ([]byte, error) {
	h, ok := hashByName(b.alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %q", b.alg)
	}
	hashWithExclusions(layout, h, excl)
	return h.Sum(nil), nil
}
func (dataHashBinding) compareRanges(_ context.Context, _ []byte, excl []byteRange) ([]byteRange, error) {
	return excl, nil
}
func (b dataHashBinding) validatePrior(ctx context.Context, asset []byte) ValidationResult {
	return Validate(ctx, b.container, bytes.NewReader(asset), WithOnlineRevocation(false))
}
func (b dataHashBinding) validateOutput(ctx context.Context, final []byte, opts []ValidateOption) ValidationResult {
	return Validate(ctx, b.container, bytes.NewReader(final), opts...)
}

// bmffFlatBinding is c2pa.hash.bmff.v3 over one whole file: the offset-marker
// walk with the standard exclusions. It has no byte ranges, so the layout
// converges on the output's length, and the store's own box is excluded by the
// walk rather than by a range — which is what the drift check must ignore too.
type bmffFlatBinding struct{ alg string }

func (bmffFlatBinding) label() string         { return "c2pa.hash.bmff.v3" }
func (bmffFlatBinding) matchCode() StatusCode { return StatusAssertionBMFFHashMatch }
func (b bmffFlatBinding) payload(_ []byteRange, digest []byte) ([]byte, error) {
	return bmffHashAssertion(b.alg, digest)
}
func (b bmffFlatBinding) digest(ctx context.Context, layout []byte, _ []byteRange) ([]byte, error) {
	return bmffHashDigest(ctx, b.alg, layout)
}
func (bmffFlatBinding) compareRanges(ctx context.Context, layout []byte, _ []byteRange) ([]byteRange, error) {
	seg, err := bmffStandardSegment(ctx, layout)
	if err != nil {
		return nil, err
	}
	return seg.ranges, nil
}
func (bmffFlatBinding) validatePrior(ctx context.Context, asset []byte) ValidationResult {
	return Validate(ctx, BMFF, bytes.NewReader(asset), WithOnlineRevocation(false))
}
func (bmffFlatBinding) validateOutput(ctx context.Context, final []byte, opts []ValidateOption) ValidationResult {
	return Validate(ctx, BMFF, bytes.NewReader(final), opts...)
}

// validateManifest is what Sign refuses before it reads a byte of the asset.
func validateManifest(m Manifest) error {
	if len(m.Actions) == 0 {
		return fmt.Errorf("%w: no actions; the first action must be %s or %s", ErrManifestInvalid, ActionCreated, ActionOpened)
	}
	for i, a := range m.Actions {
		inception := a.Action == ActionCreated || a.Action == ActionOpened
		switch {
		case a.Action == "":
			return fmt.Errorf("%w: action %d has no action", ErrManifestInvalid, i)
		case i == 0 && !inception:
			return fmt.Errorf("%w: the first action is %q; it must be %s or %s", ErrManifestInvalid, a.Action, ActionCreated, ActionOpened)
		case i > 0 && inception:
			return fmt.Errorf("%w: action %d is %q; only the first action may be", ErrManifestInvalid, i, a.Action)
		}
	}
	seen := make(map[string]bool, len(m.Assertions))
	for _, a := range m.Assertions {
		switch {
		case reservedAssertionLabel(a.Label):
			return fmt.Errorf("%w: assertion label %q is reserved", ErrManifestInvalid, a.Label)
		case seen[a.Label]:
			return fmt.Errorf("%w: duplicate assertion label %q", ErrManifestInvalid, a.Label)
		case (a.Value == nil) == (a.JSON == nil):
			return fmt.Errorf("%w: assertion %q must set exactly one of Value or JSON", ErrManifestInvalid, a.Label)
		case a.JSON != nil && !json.Valid(a.JSON):
			return fmt.Errorf("%w: assertion %q is not valid JSON", ErrManifestInvalid, a.Label)
		}
		seen[a.Label] = true
	}
	return nil
}

// priorManifest is one manifest already in the asset, kept as the exact bytes
// it was signed as.
type priorManifest struct {
	label     string
	full      []byte // the whole superbox — carried into the new store verbatim
	content   []byte // the superbox payload — what the parentOf hash covers
	signature *box   // the c2pa.signature superbox, for the claimSignature hashed_uri
	title     string
}

// priorStore is what an already-signed asset contributes to a re-sign.
type priorStore struct {
	manifests []*priorManifest
	active    *priorManifest
	result    ValidationResult // the verdict on the asset as found, set by sign through the binding
}

func (p *priorStore) has(label string) bool {
	for _, m := range p.manifests {
		if m.label == label {
			return true
		}
	}
	return false
}

// priorManifests finds the manifests an asset already carries. nil when it
// carries no store. A store that parses but holds no manifest, or two
// manifests sharing a label, is refused rather than carried forward: keeping
// provenance means keeping something a validator can resolve.
func (s *Signer) priorManifests(ctx context.Context, container Container, asset []byte) (*priorStore, error) {
	store := extractJUMBF(ctx, container, asset)
	if len(store) == 0 {
		return nil, nil
	}
	var found []*priorManifest
	var walk func(b *box)
	walk = func(b *box) {
		if b.tbox != "jumb" {
			return
		}
		if m := asManifest(b); m != nil {
			pm := &priorManifest{label: b.label, full: b.full, content: b.content}
			for _, c := range b.children {
				if strings.HasSuffix(c.label, "c2pa.signature") {
					pm.signature = c
				}
			}
			if m.claim != nil {
				pm.title, _ = m.claim["dc:title"].(string)
			}
			found = append(found, pm)
			return
		}
		for _, c := range b.children {
			walk(c)
		}
	}
	for _, b := range parseBoxTree(ctx, store) {
		walk(b)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%w: the asset's manifest store holds no manifest", ErrMalformedAsset)
	}
	labels := make(map[string]bool, len(found))
	for _, m := range found {
		if m.label == "" || labels[m.label] {
			return nil, fmt.Errorf("%w: the asset's manifest store has an unlabelled or duplicate manifest %q", ErrMalformedAsset, m.label)
		}
		labels[m.label] = true
	}
	return &priorStore{manifests: found, active: found[len(found)-1]}, nil
}

// namedBox is an assertion superbox and the label its claim entry uses.
type namedBox struct {
	label string
	box   []byte
}

// builtStore is one assembly of the manifest store.
type builtStore struct {
	store []byte
	claim []byte
}

// sign is the pipeline. The only layout-dependent bytes are the hard binding's
// exclusion offsets (variable-width CBOR integers) and its digest; the COSE
// envelope has a reserved, fixed length; so the store's length is fixed before
// anything is signed. Three phases: (a) converge the layout with a placeholder
// digest and envelope, (b) hash the converged layout — the excluded bytes make
// the placeholder store's content irrelevant, and everything outside them is a
// function of the asset and the store's length alone — then (c) sign once, pad
// the envelope to the reserved size, embed, and check byte-for-byte that
// nothing outside the exclusions moved before validating the result.
func (s *Signer) sign(ctx context.Context, container Container, asset []byte, m Manifest, hb hardBinding) ([]byte, error) {
	prior, err := s.priorManifests(ctx, container, asset)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		// The ingredient's validationResults are the verdict on the asset as
		// found — through the binding, since a fragmented initialization
		// segment is judged by ValidateFragmented, not Validate.
		prior.result = hb.validatePrior(ctx, asset)
	}
	if prior != nil && m.Actions[0].Action == ActionCreated {
		return nil, fmt.Errorf("%w: asset already carries a manifest store; the first action must be %s", ErrManifestInvalid, ActionOpened)
	}
	alg := s.cfg.hashAlg
	label, err := s.uniqueLabel(prior)
	if err != nil {
		return nil, err
	}
	instanceID, err := newInstanceID()
	if err != nil {
		return nil, err
	}

	// Layout-independent assertions, in the order they follow the hard binding.
	var fixed []namedBox
	var ingredientRefs []any
	if m.Actions[0].Action == ActionOpened {
		var pm *priorManifest
		var res *ValidationResult
		if prior != nil {
			pm, res = prior.active, &prior.result
		}
		iid, err := newInstanceID()
		if err != nil {
			return nil, err
		}
		payload, err := parentIngredientAssertion(alg, pm, res, iid)
		if err != nil {
			return nil, fmt.Errorf("c2pa: encoding ingredient: %w", err)
		}
		bx := assertionBox("c2pa.ingredient.v3", payload)
		ref, err := hashedURI(alg, assertionURL("c2pa.ingredient.v3"), bx)
		if err != nil {
			return nil, err
		}
		ingredientRefs = []any{ref}
		fixed = append(fixed, namedBox{"c2pa.ingredient.v3", bx})
	}
	actions, err := actionsAssertion(m.Actions, ingredientRefs)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding actions: %v", ErrManifestInvalid, err)
	}
	fixed = append(fixed, namedBox{"c2pa.actions.v2", assertionBox("c2pa.actions.v2", actions)})
	for _, a := range m.Assertions {
		if a.JSON != nil {
			fixed = append(fixed, namedBox{a.Label, jsonAssertionBox(a.Label, a.JSON)})
			continue
		}
		payload, err := encMode.Marshal(a.Value)
		if err != nil {
			return nil, fmt.Errorf("%w: encoding assertion %q: %v", ErrManifestInvalid, a.Label, err)
		}
		fixed = append(fixed, namedBox{a.Label, assertionBox(a.Label, payload)})
	}

	var priorBoxes [][]byte
	if prior != nil {
		for _, pm := range prior.manifests {
			priorBoxes = append(priorBoxes, pm.full)
		}
	}
	// The binding decides the assertion; a BMFF binding has no byte ranges, so
	// its layout converges on the output's length rather than on offsets.
	bindingLabel := hb.label()
	build := func(excl []byteRange, digest, envelope []byte) (builtStore, error) {
		payload, err := hb.payload(excl, digest)
		if err != nil {
			return builtStore{}, err
		}
		boxes := append([]namedBox{{bindingLabel, assertionBox(bindingLabel, payload)}}, fixed...)
		created := make([]any, 0, len(boxes))
		children := make([][]byte, 0, len(boxes))
		for _, nb := range boxes {
			ref, err := hashedURI(alg, assertionURL(nb.label), nb.box)
			if err != nil {
				return builtStore{}, err
			}
			created = append(created, ref)
			children = append(children, nb.box)
		}
		claim, err := buildClaimV2(claimParams{
			title: m.Title, instanceID: instanceID, alg: alg, generator: s.cfg.generator, created: created,
		})
		if err != nil {
			return builtStore{}, err
		}
		manifest := superBox(uuidC2MA, label,
			superBox(uuidC2AS, "c2pa.assertions", children...),
			superBox(uuidC2CL, "c2pa.claim.v2", leafBox("cbor", claim)),
			superBox(uuidC2CS, "c2pa.signature", leafBox("cbor", envelope)),
		)
		store := storeBox(append(append([][]byte{}, priorBoxes...), manifest)...)
		if len(store) > maxEmbedStore {
			return builtStore{}, fmt.Errorf("%w: %d bytes", ErrStoreTooLarge, len(store))
		}
		return builtStore{store: store, claim: claim}, nil
	}

	// (a) converge the layout.
	h, _ := hashByName(alg)
	zeroDigest := make([]byte, h.Size())
	timestamped := s.cfg.tsaURL != ""
	reserve := coseReserveSize(s.sigLen, s.chainDER, timestamped)
	zeroEnvelope := make([]byte, reserve)
	excl := []byteRange{{start: 0, length: 0}}
	var layout []byte
	var placeholder builtStore
	converged := false
	for pass, prevLen := 0, -1; pass < 8 && !converged; pass++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		placeholder, err = build(excl, zeroDigest, zeroEnvelope)
		if err != nil {
			return nil, err
		}
		out, next, err := embedStore(ctx, container, asset, placeholder.store)
		if err != nil {
			return nil, embedError(err)
		}
		if sameRanges(next, excl) && len(out) == prevLen {
			layout, converged = out, true
			break
		}
		excl, prevLen = next, len(out)
	}
	if !converged {
		return nil, fmt.Errorf("%w: exclusion offsets did not converge", ErrMalformedAsset)
	}

	// (b) the digest over the converged layout.
	digest, err := hb.digest(ctx, layout, excl)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedAsset, err)
	}

	// (c) sign once, pad to the reserve, embed, and prove nothing else moved.
	unsigned, err := build(excl, digest, zeroEnvelope)
	if err != nil {
		return nil, err
	}
	msg, err := newSign1(rand.Reader, s.key, s.alg, s.chainDER, unsigned.claim)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignerKey, err)
	}
	var tokenCerts []*x509.Certificate
	if timestamped {
		// Sign first, then timestamp the signature (sigTst2, §13.2): the token
		// goes in the unprotected header, so the signature stays valid.
		tbs, err := coseTimestampTBS(msg)
		if err != nil {
			return nil, fmt.Errorf("c2pa: internal: %w", err)
		}
		token, err := s.fetchTimestamp(ctx, tbs)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTimestamp, err)
		}
		attachSigTst2(msg, token)
		if sd, ok := parseCMSSignedData(token); ok {
			tokenCerts = sd.certs
		}
	}
	envelope, err := marshalSign1Padded(msg, reserve)
	if err != nil {
		return nil, fmt.Errorf("c2pa: internal: %w", err)
	}
	signed, err := build(excl, digest, envelope)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signed.claim, unsigned.claim) || len(signed.store) != len(placeholder.store) {
		return nil, errors.New("c2pa: internal: store changed size after signing")
	}
	final, finalExcl, err := embedStore(ctx, container, asset, signed.store)
	if err != nil {
		return nil, embedError(err)
	}
	// Outside the store, the signed file must be the placeholder layout to the
	// byte; the binding says which ranges the comparison ignores.
	compare, err := hb.compareRanges(ctx, layout, excl)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedAsset, err)
	}
	if !sameRanges(finalExcl, excl) || !sameOutsideExclusions(final, layout, compare) {
		return nil, errors.New("c2pa: internal: layout drifted between the placeholder and the signed store")
	}

	pool := x509.NewCertPool()
	pool.AddCert(s.chain[len(s.chain)-1])
	checkOpts := []ValidateOption{WithSigningTrust(pool), WithMaxIngredientDepth(0), WithOnlineRevocation(false)}
	if len(tokenCerts) > 0 {
		// The self-check is about the binding, not about whether the caller's
		// TSA is anchored: the token's own certificates are the pool.
		tsaPool := x509.NewCertPool()
		for _, c := range tokenCerts {
			tsaPool.AddCert(c)
		}
		checkOpts = append(checkOpts, WithTimestampTrust(tsaPool))
	}
	res := hb.validateOutput(ctx, final, checkOpts)
	match := hb.matchCode()
	if !res.Valid || !res.Has(match) || (timestamped && !res.Has(StatusTimeStampValidated)) {
		reason := "hard binding did not verify"
		if f := res.FirstFailure(); f != nil {
			reason = string(f.Code) + ": " + f.Explanation
		}
		return nil, fmt.Errorf("%w: %s", ErrSelfCheckFailed, reason)
	}
	return final, nil
}

// uniqueLabel returns a fresh manifest label that no prior manifest uses.
func (s *Signer) uniqueLabel(prior *priorStore) (string, error) {
	for try := 0; try < 3; try++ {
		l, err := newManifestLabel(s.cfg.vendor)
		if err != nil {
			return "", err
		}
		if prior == nil || !prior.has(l) {
			return l, nil
		}
	}
	return "", fmt.Errorf("%w: could not find an unused manifest label", ErrMalformedAsset)
}

// embedError maps an embedder's sentinel onto the public error it means.
func embedError(err error) error {
	switch {
	case errors.Is(err, errFragmented):
		return fmt.Errorf("%w: %v", ErrFragmentedBMFF, err)
	case errors.Is(err, errCarrierMalformed):
		return fmt.Errorf("%w: %v", ErrMalformedAsset, err)
	case errors.Is(err, errCarrierUnsupported):
		return fmt.Errorf("%w: %v", ErrUnsupportedContainer, err)
	case errors.Is(err, errStoreInvalid):
		return fmt.Errorf("c2pa: internal: %w", err)
	}
	return err
}

func sameRanges(a, b []byteRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameOutsideExclusions reports whether a and b are the same length and
// byte-equal everywhere except inside the (sorted, merged) ranges.
func sameOutsideExclusions(a, b []byte, ranges []byteRange) bool {
	if len(a) != len(b) {
		return false
	}
	cur := 0
	for _, r := range ranges {
		if r.start > cur && !bytes.Equal(a[cur:r.start], b[cur:r.start]) {
			return false
		}
		if end := r.start + r.length; end > cur {
			cur = end
		}
	}
	return cur >= len(a) || bytes.Equal(a[cur:], b[cur:])
}
