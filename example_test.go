package c2pa_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/richardwooding/c2pa"
)

// Example reads the Content Credentials a JPEG claims, and surfaces the
// (unverified) creating tool, AI-generated flag, and signer identity.
func Example() {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	info := c2pa.Read(context.Background(), c2pa.JPEG, f)
	if !info.Present {
		fmt.Println("no Content Credentials")
		return
	}
	fmt.Println("title:", info.Title)
	fmt.Println("ai-generated:", info.AIGenerated)
	// SignedBy is the CLAIMED signer — not cryptographically verified.
	fmt.Println("signed by:", info.SignedBy)
	// Output:
	// title: CA.jpg
	// ai-generated: false
	// signed by: C2PA Signer
}

// ExampleValidate verifies a JPEG's Content Credentials against the embedded
// C2PA trust list. The test fixture is signed by the c2pa-rs *test* PKI, so its
// signature verifies cryptographically but its signer does not chain to a
// production trust anchor — an honest "valid signature, untrusted signer"
// verdict. Pass WithSigningTrust / WithTimestampTrust to supply your own anchors.
func ExampleValidate() {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	r := c2pa.Validate(context.Background(), c2pa.JPEG, f)
	fmt.Println("valid:", r.Valid)
	fmt.Println("signature verified:", r.Has(c2pa.StatusClaimSignatureValidated))
	fmt.Println("signer trusted:", r.Has(c2pa.StatusSigningCredentialTrusted))
	// Output:
	// valid: false
	// signature verified: true
	// signer trusted: false
}

// ExampleRead_pdf reads the Content Credentials a PDF claims. The fixture is a
// real document from ChatGPT's image pipeline, so unlike the JPEG above its
// signer chains to a production trust anchor.
//
// Attribution is checked BEFORE the signer is reported. A PDF can carry a
// manifest describing an image or font inside it rather than the document
// (spec §A.4.3), and that manifest's signer is not the document's — reading
// SignedBy without this check is how a file gets credited to whoever signed a
// picture inside it.
func ExampleRead_pdf() {
	f, err := os.Open("testdata/c2pa_chatgpt.pdf")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	info := c2pa.Read(context.Background(), c2pa.PDF, f)
	if !info.Present {
		fmt.Println("no Content Credentials")
		return
	}
	fmt.Println("generator:", info.ClaimGenerator)
	fmt.Println("title:", info.Title)
	fmt.Println("ai-generated:", info.AIGenerated)

	switch info.Attribution {
	case c2pa.AttributionAsset:
		// The document's own structure associates this manifest.
		fmt.Println("signed by (claimed):", info.SignedBy)
	default:
		// A claim about something the document carries, or one nothing places.
		fmt.Println("manifest describes:", info.Attribution)
	}
	// Output:
	// generator: ChatGPT
	// title: image.pdf
	// ai-generated: true
	// signed by (claimed): OpenAI Media Service
}

// ExampleValidate_pdf verifies a PDF against the embedded C2PA trust list.
// VerifiedSigner is the proven identity — empty unless the claim signature
// verified AND the chain reached a trust anchor — where Info.SignedBy is only
// what the file claims.
func ExampleValidate_pdf() {
	f, err := os.Open("testdata/c2pa_chatgpt.pdf")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	r := c2pa.Validate(context.Background(), c2pa.PDF, f)
	fmt.Println("valid:", r.Valid)
	fmt.Println("verified signer:", r.VerifiedSigner())
	fmt.Println("content hash bound:", r.Has(c2pa.StatusAssertionDataHashMatch))
	// This document carries no RFC 3161 timestamp, so the signing time is
	// unproven and SignedAt stays zero.
	fmt.Println("trusted timestamp:", !r.Has(c2pa.StatusTimeStampMissing))
	// Output:
	// valid: true
	// verified signer: OpenAI Media Service
	// content hash bound: true
	// trusted timestamp: false
}

// ExampleReadAll_pdf enumerates every manifest store a PDF carries. Only PDF
// returns more than one today: §A.4.1 embeds the document's own store as an
// associated file, and §A.4.3 lets an object carry a manifest of its own, so a
// document and the image inside it can both bear provenance. The first entry is
// exactly what Read returns.
func ExampleReadAll_pdf() {
	f, err := os.Open("testdata/c2pa_chatgpt.pdf")
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()

	for i, info := range c2pa.ReadAll(context.Background(), c2pa.PDF, f) {
		fmt.Printf("%d: %s signed by %q (%s)\n",
			i, info.Attribution, info.SignedBy, info.ClaimGenerator)
	}
	// Output:
	// 0: asset signed by "OpenAI Media Service" (ChatGPT)
}

// ExampleValidateFragmented verifies a DASH/CMAF asset whose initialization
// segment and media fragments are separate files. The initialization segment
// carries the manifest; each fragment carries the Merkle proof that binds it.
// The binding is a match only when every fragment the manifest binds was
// supplied and verified; a partial set — here one fragment of eleven — is an
// informational status naming what was not covered, never a false match.
//
// The fixture is a third-party signed set from c2pa-rs's test assets; its
// signer is not on the embedded trust list, so the chain it presents is
// anchored explicitly (a claim about identity, not proof of it).
func ExampleValidateFragmented() {
	init, err := os.Open("testdata/dash/dashinit.mp4")
	if err != nil {
		panic(err)
	}
	defer func() { _ = init.Close() }()
	frag, err := os.Open("testdata/dash/dash1.m4s")
	if err != nil {
		panic(err)
	}
	defer func() { _ = frag.Close() }()

	ctx := context.Background()
	presented := c2pa.Validate(ctx, c2pa.BMFF, init)
	pool := x509.NewCertPool()
	pool.AddCert(presented.SignerChain[len(presented.SignerChain)-1])
	if _, err := init.Seek(0, io.SeekStart); err != nil {
		panic(err)
	}

	r := c2pa.ValidateFragmented(ctx, init, []io.Reader{frag}, c2pa.WithSigningTrust(pool))
	fmt.Println("valid:", r.Valid)
	// Bound only if every fragment was supplied and verified.
	fmt.Println("bound:", r.Has(c2pa.StatusAssertionBMFFHashMatch))
	fmt.Println("signer:", r.VerifiedSigner())
	for _, s := range r.Statuses {
		if s.Code == c2pa.StatusUnsupported {
			fmt.Println(s.Explanation)
		}
	}
	// Output:
	// valid: true
	// bound: false
	// signer: Alice
	// fragmented BMFF hash only partly verified: initialization segment and 1 of 11 fragments verified; not verified: locations 1..10
}

// exampleSigner mints a self-signed P-256 certificate that satisfies the C2PA
// certificate profile (digitalSignature key usage, an emailProtection EKU, not
// a CA) and returns a Signer for it plus a pool that trusts it. A deployment
// loads a key and a CA-issued chain from PEM instead; the README shows how.
func exampleSigner() (*c2pa.Signer, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Signer", Organization: []string{"Example Org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	signer, err := c2pa.NewSigner(key, []*x509.Certificate{cert}, c2pa.WithClaimGenerator("example", "1.0"))
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return signer, pool
}

// ExampleSigner_Sign signs an MP4 that carries no Content Credentials with a
// c2pa.created manifest, then verifies the result with the signer's own root
// as the trust anchor. Nothing is written unless the output already validates,
// so the verdict here is the same one Sign checked before returning.
func ExampleSigner_Sign() {
	signer, pool := exampleSigner()
	ctx := context.Background()

	in, err := os.Open("testdata/video_no_manifest.mp4")
	if err != nil {
		panic(err)
	}
	defer func() { _ = in.Close() }()

	var signed bytes.Buffer
	m := c2pa.Manifest{
		Title: "clip.mp4",
		Actions: []c2pa.Action{{
			Action:            c2pa.ActionCreated,
			DigitalSourceType: c2pa.DigitalSourceTypeDigitalCapture,
		}},
	}
	if err := signer.Sign(ctx, c2pa.BMFF, in, &signed, m); err != nil {
		panic(err)
	}

	r := c2pa.Validate(ctx, c2pa.BMFF, bytes.NewReader(signed.Bytes()), c2pa.WithSigningTrust(pool))
	fmt.Println("valid:", r.Valid)
	fmt.Println("content bound:", r.Has(c2pa.StatusAssertionBMFFHashMatch))
	fmt.Println("verified signer:", r.VerifiedSigner())
	fmt.Println("title:", r.Info.Title)
	// Output:
	// valid: true
	// content bound: true
	// verified signer: Example Signer
	// title: clip.mp4
}

// ExampleSigner_Sign_resign signs an asset that already carries Content
// Credentials — the ChatGPT PDF, signed by OpenAI. The existing manifest is
// kept and becomes the new manifest's parentOf ingredient — provenance is
// chained, never replaced — which is why the manifest must open with
// c2pa.opened rather than c2pa.created. For PDF the new store arrives as an
// incremental update; nothing before the previous %%EOF changes.
//
// WithSigningTrust REPLACES the embedded trust list, so the prior signer's
// chain (as the file presents it) is added to the pool to let the ingredient
// validate too. With only the new signer trusted the new manifest still
// verifies, and the ingredient's untrusted signer is reported, not hidden.
func ExampleSigner_Sign_resign() {
	signer, pool := exampleSigner()
	ctx := context.Background()

	fixture, err := os.ReadFile("testdata/c2pa_chatgpt.pdf")
	if err != nil {
		panic(err)
	}
	prior := c2pa.Validate(ctx, c2pa.PDF, bytes.NewReader(fixture))
	pool.AddCert(prior.SignerChain[len(prior.SignerChain)-1])

	var signed bytes.Buffer
	m := c2pa.Manifest{
		Title:   "image-edited.pdf",
		Actions: []c2pa.Action{{Action: c2pa.ActionOpened}},
	}
	if err := signer.Sign(ctx, c2pa.PDF, bytes.NewReader(fixture), &signed, m); err != nil {
		panic(err)
	}

	r := c2pa.Validate(ctx, c2pa.PDF, bytes.NewReader(signed.Bytes()), c2pa.WithSigningTrust(pool))
	fmt.Println("valid:", r.Valid)
	fmt.Println("title:", r.Info.Title)
	fmt.Println("verified signer:", r.VerifiedSigner())
	fmt.Println("ingredient validated:", r.Has(c2pa.StatusIngredientManifestValidated))
	fmt.Println("prior signer:", prior.VerifiedSigner())
	// Output:
	// valid: true
	// title: image-edited.pdf
	// verified signer: Example Signer
	// ingredient validated: true
	// prior signer: OpenAI Media Service
}
