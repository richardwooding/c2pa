package c2pa_test

import (
	"context"
	"fmt"
	"os"

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
