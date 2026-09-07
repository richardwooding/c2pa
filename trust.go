package c2pa

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

// embeddedSigningPEM and embeddedTSAPEM are the official C2PA conformance trust
// lists (signing anchors and timestamp-authority anchors), bundled as defaults.
// They go stale — refresh from github.com/c2pa-org/conformance-public. Callers
// override them with WithSigningTrust / WithTimestampTrust.
//
//go:embed trustlists/C2PA-TRUST-LIST.pem
var embeddedSigningPEM []byte

//go:embed trustlists/C2PA-TSA-TRUST-LIST.pem
var embeddedTSAPEM []byte

var (
	signingPoolOnce sync.Once
	signingPool     *x509.CertPool
	tsaPoolOnce     sync.Once
	tsaPool         *x509.CertPool
	// noIdentityAnchors is the identity pool when WithIdentityTrust is not
	// given: empty but NON-NIL, because x509.Verify reads a nil Roots as "use
	// the system roots", and no CAWG trust decision may consult those.
	noIdentityAnchors = x509.NewCertPool()
)

// defaultSigningPool returns the embedded C2PA signing-anchor pool, parsed once.
func defaultSigningPool() *x509.CertPool {
	signingPoolOnce.Do(func() {
		signingPool = x509.NewCertPool()
		signingPool.AppendCertsFromPEM(embeddedSigningPEM)
	})
	return signingPool
}

// defaultTSAPool returns the embedded C2PA timestamp-authority pool, parsed once.
func defaultTSAPool() *x509.CertPool {
	tsaPoolOnce.Do(func() {
		tsaPool = x509.NewCertPool()
		tsaPool.AppendCertsFromPEM(embeddedTSAPEM)
	})
	return tsaPool
}

// signingTrustPool returns the configured signing pool, falling back to the
// embedded default.
func (v *validator) signingTrustPool() *x509.CertPool {
	if v.cfg.signingTrust != nil {
		return v.cfg.signingTrust
	}
	return defaultSigningPool()
}

// timestampTrustPool returns the configured TSA pool, falling back to the
// embedded default.
func (v *validator) timestampTrustPool() *x509.CertPool {
	if v.cfg.timestampTrust != nil {
		return v.cfg.timestampTrust
	}
	return defaultTSAPool()
}

// identityTrustPool returns the configured CAWG identity anchors, or an empty
// pool — there is no embedded default (see WithIdentityTrust).
func (v *validator) identityTrustPool() *x509.CertPool {
	if v.cfg.identityTrust != nil {
		return v.cfg.identityTrust
	}
	return noIdentityAnchors
}
