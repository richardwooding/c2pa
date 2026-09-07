package c2pa

import (
	"bytes"

	// Registers SHA-256/384/512 so cose.Verifier.Verify can call crypto.Hash.New
	// for ES*/PS* algorithms. Without these go-cose panics at verify time on an
	// adversarially-selected algorithm, breaking the never-panic contract.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"

	cose "github.com/veraison/go-cose"
)

// verifyCOSE verifies the manifest's COSE_Sign1 signature over the claim. It
// returns the parsed signer chain (leaf first) and the raw COSE signature bytes
// (which the RFC 3161 timestamp's messageImprint covers). chain is returned
// even when verification fails, so the caller can still surface the claimed
// signer; ok reports whether the cryptographic signature verified.
func (v *validator) verifyCOSE(m *parsedManifest, uri string) (chain []*x509.Certificate, coseSig []byte, ok bool) {
	if len(m.signature) == 0 {
		return nil, nil, false // absence already reported by the caller
	}
	return v.verifySign1(m.signature, m.claimBytes, "claim", uri)
}

// verifySign1 verifies a detached-payload COSE_Sign1 envelope over payload and
// records the outcome at uri — the claim signature over the claim, or a CAWG
// identity signature over its signer_payload (CAWG §8.2.2 applies the same
// rules and codes). subject words the explanations ("claim", "identity").
//
// The algorithm is read from the PROTECTED header only, so an attacker cannot
// downgrade it through the unprotected one; an attached payload is honoured
// only when it IS the expected payload, since verifying a signature over
// attacker-chosen bytes while reporting different ones would make the success
// code meaningless. chain is returned even when verification fails.
func (v *validator) verifySign1(envelope, payload []byte, subject, uri string) (chain []*x509.Certificate, coseSig []byte, ok bool) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelope); err != nil {
		v.add(StatusClaimSignatureMismatch, uri, "COSE_Sign1 envelope did not decode", err)
		return nil, nil, false
	}
	if msg.Payload == nil {
		msg.Payload = payload // detached payload: the signed bytes are the claim
	} else if !bytes.Equal(msg.Payload, payload) {
		v.add(StatusClaimSignatureMismatch, uri, "attached COSE payload is not the "+subject, nil)
		return nil, msg.Signature, false
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
	for _, v := range x5chainCandidates(msg.Headers) {
		if len(chain) == 0 {
			chain = parseChain(v)
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
		v.add(StatusClaimSignatureMismatch, uri, subject+" signature did not verify", err)
		return chain, msg.Signature, false
	}
	v.add(StatusClaimSignatureValidated, uri, subject+" signature verified", nil)
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
