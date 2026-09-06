package c2pa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// COSE_Sign1 construction for Sign (spec §14). go-cose does the signing; this
// file decides what goes in the headers and how the envelope is brought to an
// exact, pre-reserved size so that signing happens once.

// coseAlgorithmFor infers the COSE algorithm from a public key, the way
// c2pa-rs's SigningAlg maps onto keys (§14.5.1): P-256 → ES256, P-384 →
// ES384, P-521 → ES512, RSA of at least 2048 bits → PS256, Ed25519 → EdDSA.
// It also returns the signature's fixed width in the envelope — ECDSA is raw
// r‖s (P1363), RSA-PSS is the modulus width, Ed25519 is 64 — which is what
// makes a reserved envelope size possible.
func coseAlgorithmFor(pub crypto.PublicKey) (cose.Algorithm, int, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return cose.AlgorithmES256, 64, nil
		case elliptic.P384():
			return cose.AlgorithmES384, 96, nil
		case elliptic.P521():
			return cose.AlgorithmES512, 132, nil
		}
		return 0, 0, fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return 0, 0, fmt.Errorf("RSA key is %d bits; the C2PA profile needs 2048", k.N.BitLen())
		}
		return cose.AlgorithmPS256, (k.N.BitLen() + 7) / 8, nil
	case ed25519.PublicKey:
		return cose.AlgorithmEdDSA, ed25519.SignatureSize, nil
	}
	return 0, 0, fmt.Errorf("unsupported key type %T", pub)
}

// newSign1 signs payload as a detached COSE_Sign1 (§14.1): the protected header
// carries alg and x5chain under integer label 33 — the protected bucket, as
// §14.5 requires and c2pa-rs writes; a single certificate is a bare byte
// string, several are an array — nothing is placed in the unprotected header,
// and external_aad is empty. go-cose refuses to sign a nil payload, so the
// payload is attached for the signature and detached afterwards; the caller
// re-supplies it as the claim bytes when verifying.
func newSign1(rnd io.Reader, key crypto.Signer, alg cose.Algorithm, chainDER [][]byte, payload []byte) (*cose.Sign1Message, error) {
	var signer cose.Signer
	if ms, ok := key.(crypto.MessageSigner); ok {
		_, sigLen, err := coseAlgorithmFor(key.Public())
		if err != nil {
			return nil, err
		}
		signer = &messageSigner{alg: alg, key: ms, pub: key.Public(), sigLen: sigLen}
	} else {
		var err error
		if signer, err = cose.NewSigner(alg, key); err != nil {
			return nil, err
		}
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = alg
	switch len(chainDER) {
	case 0:
	case 1:
		msg.Headers.Protected[cose.HeaderLabelX5Chain] = chainDER[0]
	default:
		msg.Headers.Protected[cose.HeaderLabelX5Chain] = chainDER
	}
	msg.Payload = payload
	if err := msg.Sign(rnd, nil, signer); err != nil {
		return nil, err
	}
	msg.Payload = nil
	return msg, nil
}

// messageSigner adapts a key implementing the standard crypto.MessageSigner —
// one that signs whole messages rather than a digest handed to it, which is
// all WebCrypto's SubtleCrypto.sign and some HSM/KMS APIs offer — to go-cose's
// Signer. go-cose only knows crypto.Signer: for ECDSA it hashes the
// Sig_structure itself and calls Sign(rand, digest, nil), which such a key
// cannot serve. Here the key receives the Sig_structure, with the opts and the
// encoding contract x509.CreateCertificate uses (it goes through
// crypto.SignMessage): the hash for ECDSA, PSS options for RSA, crypto.Hash(0)
// for Ed25519; DER back for ECDSA — converted to COSE's raw r‖s here — raw for
// RSA-PSS and Ed25519. One key type therefore serves both the certificate and
// the COSE signature.
type messageSigner struct {
	alg    cose.Algorithm
	key    crypto.MessageSigner
	pub    crypto.PublicKey
	sigLen int
}

func (m *messageSigner) Algorithm() cose.Algorithm { return m.alg }

func (m *messageSigner) Sign(rnd io.Reader, content []byte) ([]byte, error) {
	var opts crypto.SignerOpts
	switch m.alg {
	case cose.AlgorithmES256:
		opts = crypto.SHA256
	case cose.AlgorithmES384:
		opts = crypto.SHA384
	case cose.AlgorithmES512:
		opts = crypto.SHA512
	case cose.AlgorithmPS256:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	case cose.AlgorithmEdDSA:
		opts = crypto.Hash(0)
	default:
		return nil, fmt.Errorf("unsupported algorithm %v for a message signer", m.alg)
	}
	sig, err := m.key.SignMessage(rnd, content, opts)
	if err != nil {
		return nil, err
	}
	if pub, ok := m.pub.(*ecdsa.PublicKey); ok {
		if sig, err = ecdsaRawFromDER(sig, pub.Curve); err != nil {
			return nil, err
		}
	}
	if len(sig) != m.sigLen {
		return nil, fmt.Errorf("message signer returned a %d-byte signature; %v needs %d", len(sig), m.alg, m.sigLen)
	}
	return sig, nil
}

// ecdsaRawFromDER converts an ASN.1 SEQUENCE{r, s} ECDSA signature — what
// crypto.Signer and crypto.MessageSigner return for ECDSA keys — to the fixed
// width r‖s COSE carries (RFC 9053 §2.1), each integer left-padded to the
// curve's byte size. A malformed or oversized integer is an error, never a
// short signature.
func ecdsaRawFromDER(der []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("ECDSA signature is not a DER SEQUENCE of two positive integers")
	}
	n := (curve.Params().BitSize + 7) / 8
	if sig.R.BitLen() > n*8 || sig.S.BitLen() > n*8 {
		return nil, errors.New("ECDSA signature integer exceeds the curve size")
	}
	out := make([]byte, 2*n)
	sig.R.FillBytes(out[:n])
	sig.S.FillBytes(out[n:])
	return out, nil
}

// coseTimestampTBS is what a sigTst2 timestamp covers (§13.2): the COSE
// Sig_structure with the CounterSignature context over the CBOR-byte-string-
// encoded signature — the same bytes verifyTimestamp recomputes.
func coseTimestampTBS(msg *cose.Sign1Message) ([]byte, error) {
	raw, err := msg.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	protected, signature, ok := coseParts(raw)
	if !ok {
		return nil, fmt.Errorf("could not decode the envelope just marshalled")
	}
	sig, err := cbor.Marshal(signature)
	if err != nil {
		return nil, err
	}
	return coseCountersignData(sig, protected), nil
}

// sigTstHeader is the unprotected-header value both sigTst and sigTst2 carry:
// {tstTokens: [{val: <DER token>}]}, the container extractTSToken walks.
func sigTstHeader(der []byte) map[any]any {
	return map[any]any{"tstTokens": []any{map[any]any{"val": der}}}
}

// attachSigTst2 stores a TimeStampToken in the unprotected header. Unprotected
// headers may be added after signing (the protected bytes and signature are
// untouched); RawUnprotected must be dropped or go-cose re-emits the stale
// bytes it cached at signing time.
func attachSigTst2(msg *cose.Sign1Message, tokenDER []byte) {
	msg.Headers.Unprotected["sigTst2"] = sigTstHeader(tokenDER)
	msg.Headers.RawUnprotected = nil
}

// coseReserveSize is how many bytes the signature box's content is reserved
// for before anything is signed: the signature's fixed width, the certificate
// chain, and c2pa-rs's allowances — 1024 for the CBOR framing and 10000 for a
// timestamp token, whose size is the one thing not known in advance.
func coseReserveSize(sigLen int, chainDER [][]byte, timestamped bool) int {
	n := sigLen + 1024
	for _, c := range chainDER {
		n += len(c)
	}
	if timestamped {
		n += 10000
	}
	return n
}

// marshalSign1Padded encodes msg as a tagged COSE_Sign1 of exactly reserve
// bytes by adding an unprotected "pad" byte string of zeros — and, at the CBOR
// width boundaries a single pad cannot hit, a second "pad2" — the technique
// c2pa-rs's pad_cose_sig uses (§10.4.2 recommends it). It never truncates: an
// envelope that already exceeds reserve is an error, which is how a timestamp
// token larger than its allowance surfaces.
func marshalSign1Padded(msg *cose.Sign1Message, reserve int) ([]byte, error) {
	delete(msg.Headers.Unprotected, "pad")
	delete(msg.Headers.Unprotected, "pad2")
	msg.Headers.RawUnprotected = nil
	base, err := msg.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	if len(base) == reserve {
		return base, nil
	}
	if len(base) > reserve {
		return nil, fmt.Errorf("envelope is %d bytes, over the %d reserved", len(base), reserve)
	}
	need := reserve - len(base)
	// pad2 costs 5 (its key) + a 1-byte header + m zeros while m < 24; it only
	// exists to step past the sizes a lone pad cannot produce.
	for m := -1; m < 24; m++ {
		remaining := need
		if m >= 0 {
			remaining -= 5 + 1 + m
		}
		n, ok := padSizeFor(remaining)
		if !ok {
			continue
		}
		msg.Headers.Unprotected["pad"] = make([]byte, n)
		if m >= 0 {
			msg.Headers.Unprotected["pad2"] = make([]byte, m)
		} else {
			delete(msg.Headers.Unprotected, "pad2")
		}
		msg.Headers.RawUnprotected = nil
		out, err := msg.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		if len(out) == reserve {
			return out, nil
		}
	}
	return nil, fmt.Errorf("could not pad a %d-byte envelope to %d bytes", len(base), reserve)
}

// padSizeFor solves 4 + header(n) + n == need for the "pad" entry: a 4-byte
// text key plus a byte string whose header is 1, 2, 3 or 5 bytes depending on
// n. ok is false at the widths no n satisfies.
func padSizeFor(need int) (int, bool) {
	for _, hdr := range []int{1, 2, 3, 5} {
		n := need - 4 - hdr
		if n >= 0 && bstrHeaderLen(n) == hdr {
			return n, true
		}
	}
	return 0, false
}

// bstrHeaderLen is the length of a CBOR byte-string header for n bytes.
func bstrHeaderLen(n int) int {
	switch {
	case n < 24:
		return 1
	case n < 256:
		return 2
	case n < 65536:
		return 3
	default:
		return 5
	}
}
