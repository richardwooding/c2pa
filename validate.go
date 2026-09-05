package c2pa

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"slices"
	"time"
)

// ValidateMaxScan caps how many leading bytes Validate consumes. Unlike Read's
// MaxScan (tuned for fast manifest discovery), validation must hash the whole
// asset for hard-binding checks, so the cap is larger. Assets beyond it cannot
// have their data hash verified — that is reported as an informational status,
// never a false mismatch.
const ValidateMaxScan = 256 << 20

// Severity threshold for the Valid roll-up lives in finish(); see ValidationResult.

// StatusEntry is one outcome from the validation pipeline: a C2PA status code,
// its severity, the JUMBF URI of the subject it concerns (best-effort), a
// human-readable explanation, and the underlying error for failures.
type StatusEntry struct {
	Code        StatusCode
	Severity    Severity
	URI         string
	Explanation string
	Err         error
}

// ValidationResult is the outcome of Validate. Valid is true exactly when no
// SeverityFailure status was recorded (see the package docs on the roll-up
// rule). Statuses is the ordered accumulation of every success, informational,
// and failure status produced along the way.
type ValidationResult struct {
	// Valid is true iff Statuses contains no SeverityFailure entry.
	Valid bool
	// Info mirrors the surfaced fields Read would return for the same input.
	Info Info
	// Statuses is the ordered list of every validation outcome.
	Statuses []StatusEntry
	// ActiveManifestLabel is the active (last) manifest's JUMBF label.
	ActiveManifestLabel string
	// SignerChain is the COSE signer's certificate chain (leaf first) as
	// presented in the manifest, populated once the chain is parsed.
	SignerChain []*x509.Certificate
	// SignedAt is the signing time from a verified RFC 3161 timestamp, or zero
	// when no trusted timestamp was found.
	SignedAt time.Time
}

// VerifiedSigner returns the signer's identity — the leaf certificate's Subject
// Common Name, falling back to its first Organization — but ONLY when that
// identity was actually proven: the active manifest's claim signature verified,
// and its certificate chain reached a trust anchor. Otherwise it returns "".
//
// Use this rather than reading SignerChain directly. SignerChain is the chain
// as PRESENTED, populated whether or not it verified, so a name taken straight
// from it is a claim rather than a fact — the same trap Info.SignedBy carries.
//
// A hard-binding failure does not clear it: if the content was edited after
// signing, who signed the original is still proven, and Valid reports the edit.
func (r ValidationResult) VerifiedSigner() string {
	if !r.hasForActive(StatusClaimSignatureValidated) || !r.hasForActive(StatusSigningCredentialTrusted) {
		return ""
	}
	if len(r.SignerChain) == 0 || r.SignerChain[0] == nil {
		return ""
	}
	leaf := r.SignerChain[0]
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	if len(leaf.Subject.Organization) > 0 {
		return leaf.Subject.Organization[0]
	}
	return ""
}

// hasForActive reports whether code was recorded against the active manifest
// specifically. Plain Has would also match an ingredient's status, so a file
// carrying a trusted ingredient could make an untrusted asset look verified.
func (r ValidationResult) hasForActive(code StatusCode) bool {
	for i := range r.Statuses {
		if r.Statuses[i].Code == code && r.Statuses[i].URI == r.ActiveManifestLabel {
			return true
		}
	}
	return false
}

// Has reports whether any recorded status has the given code.
func (r ValidationResult) Has(code StatusCode) bool {
	for i := range r.Statuses {
		if r.Statuses[i].Code == code {
			return true
		}
	}
	return false
}

// FirstFailure returns the first SeverityFailure status, or nil if none.
func (r ValidationResult) FirstFailure() *StatusEntry {
	for i := range r.Statuses {
		if r.Statuses[i].Severity == SeverityFailure {
			return &r.Statuses[i]
		}
	}
	return nil
}

// validateConfig holds the resolved options for one Validate call.
type validateConfig struct {
	signingTrust       *x509.CertPool
	timestampTrust     *x509.CertPool
	onlineRevocation   bool
	clock              func() time.Time
	maxIngredientDepth int
	maxScan            int
	httpClient         *http.Client
}

// ValidateOption configures a Validate call. See the With* constructors.
type ValidateOption func(*validateConfig)

// WithSigningTrust overrides the embedded C2PA signing-anchor trust pool used
// to validate the claim signer's certificate chain.
func WithSigningTrust(pool *x509.CertPool) ValidateOption {
	return func(c *validateConfig) { c.signingTrust = pool }
}

// WithTimestampTrust overrides the embedded C2PA timestamp-authority trust pool
// used to validate RFC 3161 timestamp tokens.
func WithTimestampTrust(pool *x509.CertPool) ValidateOption {
	return func(c *validateConfig) { c.timestampTrust = pool }
}

// WithOnlineRevocation enables OCSP/CRL revocation checking, which makes
// network calls. It is off by default; when off, revocation is reported as an
// informational "unknown" status. Revocation is always soft-fail: a network or
// parse error is informational, never a validation failure.
func WithOnlineRevocation(enabled bool) ValidateOption {
	return func(c *validateConfig) { c.onlineRevocation = enabled }
}

// WithClock overrides the time source used when no trusted timestamp pins the
// signing time (defaults to time.Now). Useful for deterministic tests.
func WithClock(now func() time.Time) ValidateOption {
	return func(c *validateConfig) { c.clock = now }
}

// WithMaxIngredientDepth caps recursive ingredient/nested-manifest validation
// depth (default 16).
func WithMaxIngredientDepth(n int) ValidateOption {
	return func(c *validateConfig) { c.maxIngredientDepth = n }
}

// WithMaxScan overrides how many leading bytes Validate reads (default
// ValidateMaxScan).
func WithMaxScan(n int) ValidateOption {
	return func(c *validateConfig) { c.maxScan = n }
}

// WithHTTPClient sets the HTTP client used for OCSP/CRL fetches when online
// revocation is enabled (defaults to a client with a short timeout).
func WithHTTPClient(client *http.Client) ValidateOption {
	return func(c *validateConfig) { c.httpClient = client }
}

func defaultConfig() validateConfig {
	return validateConfig{
		clock:              time.Now,
		maxIngredientDepth: 16,
		maxScan:            ValidateMaxScan,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}
}

// validator carries the per-call state through the pipeline.
type validator struct {
	ctx       context.Context
	cfg       validateConfig
	container Container // the carrier format Validate was called with
	data      []byte    // the full asset bytes read (up to cfg.maxScan)
	res       ValidationResult
	visited   map[string]bool // manifest labels already validated (ingredient cycle guard)
	// hardBound records manifests whose hard binding was already verified
	// against THIS asset — an update manifest's parent, whose binding covers
	// these bytes even though the ingredient walk reaches it at depth > 0.
	hardBound map[string]bool
	// attribution is what the container said the store is a claim about, kept
	// until parseManifest has built the Info it belongs on.
	attribution Attribution
	// priorStores are the carrier's other manifest stores, which §A.4.2.1 asks a
	// consumer to process together with the active one ("all C2PA Manifests in
	// all C2PA Manifest Stores as if they were contained in a single C2PA
	// Manifest Store"). PDF's update sections and object-level stores, and
	// BMFF's "original" store beneath an update manifest.
	priorStores [][]byte
}

func (v *validator) add(code StatusCode, uri, explain string, err error) {
	v.res.Statuses = append(v.res.Statuses, StatusEntry{
		Code:        code,
		Severity:    code.Severity(),
		URI:         uri,
		Explanation: explain,
		Err:         err,
	})
}

func (v *validator) finish() ValidationResult {
	v.res.Valid = true
	for i := range v.res.Statuses {
		if v.res.Statuses[i].Severity == SeverityFailure {
			v.res.Valid = false
			break
		}
	}
	return v.res
}

// Validate reads up to ValidateMaxScan bytes from r and performs full C2PA
// validation of the embedded manifest: COSE signature verification, certificate
// chain + C2PA cert-profile validation against the (embedded or overridden)
// trust list, assertion and hard-binding hash verification, RFC 3161 timestamp
// verification, optional revocation checking, and recursive ingredient
// validation. It reports every outcome as a StatusEntry; ValidationResult.Valid
// is true exactly when no failure status was recorded.
//
// Like Read, Validate never returns an error and never panics: malformed,
// truncated, or cancelled input is reported via failure statuses with
// Valid=false. It is the verified counterpart to Read's fast, unverified scan.
func Validate(ctx context.Context, container Container, r io.Reader, opts ...ValidateOption) ValidationResult {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	v := &validator{
		ctx: ctx, cfg: cfg, container: container,
		visited: map[string]bool{}, attribution: AttributionAsset,
	}

	if ctx.Err() != nil {
		v.add(StatusGeneralError, "", "context cancelled before validation", ctx.Err())
		return v.finish()
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(cfg.maxScan)))
	if err != nil || len(data) == 0 {
		v.add(StatusGeneralError, "", "no readable input", err)
		return v.finish()
	}
	v.data = data

	jumbf := extractJUMBF(ctx, container, data)
	if len(jumbf) == 0 {
		v.add(StatusClaimMissing, "", "no C2PA manifest found", nil)
		return v.finish()
	}
	if container == BMFF {
		// §A.5.3: when the active manifest is an update manifest, the store it
		// updates is still in the file under purpose "original". Both are read
		// as one so the update's parentOf reference resolves to it.
		if original := bmffStores(ctx, data)["original"]; len(original) > 0 &&
			!bytes.Equal(original, jumbf) {
			v.priorStores = append(v.priorStores, original)
		}
	}
	if container == PDF && !v.checkPDFStores(ctx, data) {
		return v.finish()
	}
	// Reuse the read path to surface the convenience Info fields.
	v.res.Info = parseManifest(ctx, jumbf)
	if v.res.Info.Present {
		v.res.Info.Attribution = v.attribution
	}

	store := v.storeWithPriorSections(ctx, parseStore(ctx, jumbf))
	m := store.active()
	if m == nil {
		v.add(StatusClaimMissing, "", "no parseable manifest in store", nil)
		return v.finish()
	}
	v.res.ActiveManifestLabel = m.label

	v.validateManifest(m, store, 0)
	return v.finish()
}

// checkPDFStores records what the PDF container cannot settle by itself: a store
// that only the §A.4.1 markers identified, which §A.4.3 allows to be an embedded
// file's manifest rather than the document's, and further stores this extractor
// does not evaluate — earlier update sections', which §A.4.2.1 asks a consumer
// to process together with the active one.
// It reports whether validation should go on: §15.5.2.2 makes multiple stores in
// one update section invalid and asks a consumer to treat that as if no
// manifests were located, which is a failure, not an advisory.
func (v *validator) checkPDFStores(ctx context.Context, data []byte) bool {
	objs, active, src := pdfScan(ctx, data)
	v.attribution = pdfAttribution(src)
	tally := pdfTallyStores(ctx, data, objs)
	if tally.attributed && tally.perSection > 1 {
		v.add(StatusClaimMissing, "", "§15.5.2.2: one update section associates "+
			"multiple C2PA manifest stores, so none is located", nil)
		return false
	}
	switch src {
	case pdfStoreObject:
		v.add(StatusUnsupported, "", "PDF manifest store is an object-level manifest (§A.4.3), "+
			"associated from the object whose provenance it records rather than from the "+
			"document catalog: it is a claim about an embedded resource, and its signer is "+
			"not the document's", nil)
	case pdfStoreMarker:
		v.add(StatusUnsupported, "", "PDF manifest store identified by its C2PA markers alone, "+
			"nothing in the document associating it: it may record an embedded resource's "+
			"provenance rather than the document's, and its signer may not be the document's", nil)
	}
	v.priorStores = pdfOtherStores(ctx, data, objs, active)
	return true
}

// pdfOtherStores collects every manifest store the document carries apart from
// the active one: the earlier update sections' (§A.4.2.1), the object-level
// ones an object associates with itself (§A.4.3), and any the markers alone
// found. §A.4.2.1 is categorical about what to do with them —
//
//	A C2PA Manifest Consumer shall process all C2PA Manifests in all C2PA
//	Manifest Stores as if they were contained in a single C2PA Manifest Store.
//
// — and §A.4.3 recommends an object-level manifest be referenced from the
// active manifest as a componentOf ingredient, which is precisely a reference
// that has to resolve across stores.
//
// Folding a store in only puts its manifests within reach of a reference. It
// grants them nothing: a manifest resolved this way is validated like any
// other, and the active store's manifests stay last so none of these can become
// the active manifest.
func pdfOtherStores(ctx context.Context, data []byte, objs *pdfObjects, active []byte) [][]byte {
	prior := pdfCatalogStores(ctx, data, objs, active)
	for _, os := range pdfObjectStores(ctx, objs) {
		prior = append(prior, os.store)
	}
	prior = append(prior, pdfMarkedStores(ctx, objs)...)
	out := prior[:0]
	for _, store := range prior {
		if bytes.Equal(store, active) || slices.ContainsFunc(out,
			func(have []byte) bool { return bytes.Equal(have, store) }) {
			continue
		}
		out = append(out, store)
	}
	return out
}

// extractJUMBF dispatches to the container-specific JUMBF extractor.
func extractJUMBF(ctx context.Context, container Container, data []byte) []byte {
	switch container {
	case JPEG:
		return jpegJUMBF(ctx, data)
	case PNG:
		return pngJUMBF(ctx, data)
	case BMFF:
		return bmffJUMBF(ctx, data)
	case RIFF:
		return riffJUMBF(ctx, data)
	case TIFF:
		return tiffJUMBF(ctx, data)
	case GIF:
		return gifJUMBF(ctx, data)
	case MP3:
		return mp3JUMBF(ctx, data)
	case SVG:
		return svgJUMBF(ctx, data)
	case PDF:
		return pdfJUMBF(ctx, data)
	default:
		return nil
	}
}

// validateManifest runs every validation step against one manifest, recording
// status entries. depth bounds ingredient recursion. Steps accumulate a
// complete report rather than short-circuiting, except where a later step is
// meaningless without an earlier one.
func (v *validator) validateManifest(m *parsedManifest, store *parsedStore, depth int) {
	uri := m.label
	v.visited[m.label] = true
	if m.claimBytes == nil {
		v.add(StatusClaimRequiredMissing, uri, "manifest has no claim", nil)
	}
	if m.multipleClaims {
		v.add(StatusClaimMultiple, uri, "manifest holds more than one claim box", nil)
	}
	if m.signature == nil {
		v.add(StatusClaimSignatureMissing, uri, "manifest has no signature", nil)
	}

	// Signature: verify the COSE_Sign1 over the claim.
	chain, _, _ := v.verifyCOSE(m, uri)

	// Timestamp: verify the RFC 3161 token. A trusted genTime pins the signing
	// certificate's validity window (so a cert valid at signing but now expired
	// still passes); otherwise fall back to the configured clock.
	verifyTime := v.cfg.clock()
	genTime, trusted := v.verifyTimestamp(m, uri)
	if trusted && depth == 0 {
		// Only the active manifest's timestamp describes THIS asset. An
		// ingredient's is about the bytes that went into it, so letting the
		// recursion below overwrite this would report an earlier work's
		// signing time as the asset's. SignedAt stays trusted-only.
		v.res.SignedAt = genTime
	}
	if !genTime.IsZero() {
		// The validity-window clock uses an attested genTime even when the TSA
		// is unanchored: the token is cryptographically bound to this signature,
		// so "the certificate was valid when this was signed" is established
		// even though timeStamp.untrusted stands (and keeps Valid false). The
		// alternative manufactures signingCredential.expired out of our refusal
		// to trust the clock — a worse diagnosis than the trust failure itself,
		// and one that misfiles legitimately old files as structurally broken.
		// No verdict weakens: an untrusted timestamp can never make Valid true.
		verifyTime = genTime
	}

	if len(chain) > 0 {
		// A bound genTime outside the signing certificate's own validity window
		// is its own defined failure, distinct from an expiry measured at the
		// wall clock.
		if leaf := chain[0]; !genTime.IsZero() &&
			(genTime.Before(leaf.NotBefore) || genTime.After(leaf.NotAfter)) {
			v.add(StatusTimeStampOutsideValidity, uri,
				"timestamp genTime is outside the signing certificate's validity period", nil)
		}
		// Likewise the signer: an ingredient is signed by whoever made the
		// material, not by whoever signed this asset.
		if depth == 0 {
			v.res.SignerChain = chain
		}
		v.verifyChain(chain, v.signingTrustPool(), verifyTime, signingEKUOK, uri)
		v.checkRevocation(chain, uri)
	}

	// Assertion integrity: each claimed assertion hash must match its box.
	v.verifyAssertionHashes(m, uri)
	// Hard binding: the asset content hash must match. Only the active
	// manifest's binding covers the asset being validated — an ingredient
	// manifest's hard binding refers to the ingredient's ORIGINAL bytes, which
	// are not available here, so it is reported informationally rather than
	// half-checked against the wrong asset.
	switch {
	case depth == 0 && m.update:
		// An update manifest changes no content, so it carries no hard binding
		// and demanding one would fail every correctly formed asset. What binds
		// the content is the manifest it updates, reached through its single
		// parentOf ingredient — and that manifest describes THESE bytes, unlike
		// an ordinary ingredient's.
		v.verifyUpdateManifest(m, store, uri)
	case depth == 0:
		v.verifyHardBinding(m, uri)
	case !v.hardBound[m.label]:
		v.add(StatusUnsupported, uri,
			"ingredient manifest hard binding not evaluated (original asset bytes unavailable)", nil)
	}
	// Ingredients: recursively validate referenced nested manifests.
	v.validateIngredients(m, store, depth)
}

// storeWithPriorSections folds the earlier update sections' manifests into the
// active store, oldest first, so the whole document reads as one manifest store
// — which is what §A.4.2.1 asks a consumer to do.
//
// The active store's manifests stay last, so active() still resolves to the
// current section's active manifest: an earlier section is extra provenance to
// resolve references against, never a claim about the document as it stands.
// A label the active store also defines is dropped from the earlier ones, since
// a superseded definition of the same manifest is what an incremental update
// leaves behind.
func (v *validator) storeWithPriorSections(ctx context.Context, active *parsedStore) *parsedStore {
	if len(v.priorStores) == 0 {
		return active
	}
	have := make(map[string]bool, len(active.manifests))
	for _, m := range active.manifests {
		have[m.label] = true
	}
	merged := &parsedStore{}
	for _, jumbf := range v.priorStores {
		for _, m := range parseStore(ctx, jumbf).manifests {
			if have[m.label] {
				continue
			}
			have[m.label] = true
			merged.manifests = append(merged.manifests, m)
		}
	}
	merged.manifests = append(merged.manifests, active.manifests...)
	return merged
}
