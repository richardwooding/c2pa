package c2pa

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
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
	container Container       // the carrier format Validate was called with
	data      []byte          // the full asset bytes read (up to cfg.maxScan)
	res       ValidationResult
	visited   map[string]bool // manifest labels already validated (ingredient cycle guard)
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
	v := &validator{ctx: ctx, cfg: cfg, container: container, visited: map[string]bool{}}

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
	if container == BMFF && bmffHasUpdateManifest(ctx, data) {
		v.add(StatusUnsupported, "", "BMFF update manifest present but not evaluated", nil)
	}
	// Reuse the read path to surface the convenience Info fields.
	v.res.Info = parseManifest(ctx, jumbf)

	store := parseStore(ctx, jumbf)
	m := store.active()
	if m == nil {
		v.add(StatusClaimMissing, "", "no parseable manifest in store", nil)
		return v.finish()
	}
	v.res.ActiveManifestLabel = m.label

	v.validateManifest(m, store, 0)
	return v.finish()
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
	if m.signature == nil {
		v.add(StatusClaimSignatureMissing, uri, "manifest has no signature", nil)
	}

	// Signature: verify the COSE_Sign1 over the claim.
	chain, _, _ := v.verifyCOSE(m, uri)

	// Timestamp: verify the RFC 3161 token. A trusted genTime pins the signing
	// certificate's validity window (so a cert valid at signing but now expired
	// still passes); otherwise fall back to the configured clock.
	verifyTime := v.cfg.clock()
	if genTime, trusted := v.verifyTimestamp(m, uri); trusted {
		v.res.SignedAt = genTime
		verifyTime = genTime
	}

	if len(chain) > 0 {
		v.res.SignerChain = chain
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
	if depth == 0 {
		v.verifyHardBinding(m, uri)
	} else {
		v.add(StatusUnsupported, uri,
			"ingredient manifest hard binding not evaluated (original asset bytes unavailable)", nil)
	}
	// Ingredients: recursively validate referenced nested manifests.
	v.validateIngredients(m, store, depth)
}
