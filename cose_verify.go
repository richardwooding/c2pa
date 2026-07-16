package c2pa

import (
	// Registers SHA-256/384/512 so cose.Verifier.Verify can call crypto.Hash.New
	// for ES*/PS* algorithms. Without these go-cose panics at verify time on an
	// adversarially-selected algorithm, breaking the never-panic contract.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"

	cose "github.com/veraison/go-cose"
)

// verifyCOSE verifies a manifest's claim signature (COSE_Sign1). C2PA uses a
// detached payload (msg.Payload == nil), so the claim box bytes are injected as
// the payload before verification; external_aad is empty. The signing algorithm
// is read from the protected header only (an unprotected-header value would be a
// downgrade vector).
//
// It returns the parsed signer chain (leaf first) and the raw COSE signature
// bytes (which the RFC 3161 timestamp's messageImprint covers). chain is
// returned even when verification fails, so the caller can still surface the
// claimed signer; ok reports whether the cryptographic signature verified.
func (v *validator) verifyCOSE(m *parsedManifest, uri string) (chain []*x509.Certificate, coseSig []byte, ok bool) {
	if len(m.signature) == 0 {
		return nil, nil, false // absence already reported by the caller
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(m.signature); err != nil {
		v.add(StatusClaimSignatureMismatch, uri, "COSE_Sign1 envelope did not decode", err)
		return nil, nil, false
	}
	if msg.Payload == nil {
		msg.Payload = m.claimBytes // detached payload: the signed bytes are the claim
	}
	if len(msg.Payload) == 0 {
		v.add(StatusClaimSignatureMismatch, uri, "no payload to verify", nil)
		return nil, msg.Signature, false
	}

	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		v.add(StatusAlgorithmUnsupported, uri, "no algorithm in protected header", err)
		return nil, msg.Signature, false
	}
	if !allowedCOSEAlg(alg) {
		v.add(StatusAlgorithmUnsupported, uri, "disallowed COSE signature algorithm", nil)
		return nil, msg.Signature, false
	}

	// The chain lives under the COSE x5chain label (RFC 9360, int 33) in the
	// protected or unprotected header; pre-1.3 c2pa-rs signers (e.g. c2patool
	// 0.6-era assets) used the text key "x5chain" instead. Accept all four —
	// the chain is transport, not a signed claim; trust comes from chain
	// validation against the anchor pool either way.
	for _, hdr := range []map[any]any{map[any]any(msg.Headers.Protected), map[any]any(msg.Headers.Unprotected)} {
		for _, key := range []any{cose.HeaderLabelX5Chain, "x5chain"} {
			if len(chain) == 0 {
				chain = parseChain(hdr[key])
			}
		}
	}
	if len(chain) == 0 {
		v.add(StatusSigningCredentialInvalid, uri, "no x5chain certificate in signature", nil)
		return nil, msg.Signature, false
	}

	verifier, err := cose.NewVerifier(alg, chain[0].PublicKey)
	if err != nil {
		v.add(StatusClaimSignatureMismatch, uri, "cannot build verifier for signer key/algorithm", err)
		return chain, msg.Signature, false
	}
	if err := msg.Verify(nil, verifier); err != nil {
		v.add(StatusClaimSignatureMismatch, uri, "claim signature did not verify", err)
		return chain, msg.Signature, false
	}
	v.add(StatusClaimSignatureValidated, uri, "claim signature verified", nil)
	return chain, msg.Signature, true
}

// allowedCOSEAlg reports whether a COSE algorithm is permitted by the C2PA
// signature profile (ECDSA, RSA-PSS, EdDSA — never RSA PKCS#1v1.5 or SHA-1).
func allowedCOSEAlg(alg cose.Algorithm) bool {
	switch alg {
	case cose.AlgorithmES256, cose.AlgorithmES384, cose.AlgorithmES512,
		cose.AlgorithmPS256, cose.AlgorithmPS384, cose.AlgorithmPS512,
		cose.AlgorithmEdDSA:
		return true
	}
	return false
}
