package c2pa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"time"
)

// RFC 3161 client for Sign's opt-in timestamping (spec §13.2). One request
// per sign: the CounterSignature data over the COSE signature is hashed, sent
// as a TimeStampReq with a fresh nonce, and the TimeStampToken in the reply is
// verified with the validator's own code — imprint, signed attributes, CMS
// signature, id-kp-timeStamping, nonce echo — before it goes anywhere near
// the file. A reply that fails any of that fails the sign. Trust in the TSA is
// not judged here: the caller chose it, and validators decide for themselves.

// maxTSAResponse caps a TSA reply; a real TimeStampResp is a few kilobytes.
const maxTSAResponse = 1 << 20

// defaultTSATimeout bounds the HTTP round trip when the caller supplies no client.
const defaultTSATimeout = 30 * time.Second

// tsaAlgID is an AlgorithmIdentifier.
type tsaAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// tsaImprint is a MessageImprint.
type tsaImprint struct {
	Alg    tsaAlgID
	Hashed []byte
}

// tsaRequest is a TimeStampReq (RFC 3161 §2.4.1) without reqPolicy or
// extensions; the optional fields are omitted when zero.
type tsaRequest struct {
	Version        int
	MessageImprint tsaImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// tsaStatusInfo is a PKIStatusInfo.
type tsaStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// tsaResponse is a TimeStampResp.
type tsaResponse struct {
	Status tsaStatusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

// timestampRequest encodes the request for tbs and returns it with the nonce
// the reply must echo. The imprint is SHA-256 whatever the signing algorithm,
// as c2pa-rs's default_rfc3161_message does; certReq asks the TSA to include
// its certificates, which the token needs to be verifiable on its own.
func timestampRequest(tbs []byte) ([]byte, *big.Int, error) {
	var nb [8]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, nil, err
	}
	nonce := new(big.Int).SetBytes(nb[:])
	digest := sha256.Sum256(tbs)
	der, err := asn1.Marshal(tsaRequest{
		Version:        1,
		MessageImprint: tsaImprint{Alg: tsaAlgID{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, Hashed: digest[:]},
		Nonce:          nonce,
		CertReq:        true,
	})
	if err != nil {
		return nil, nil, err
	}
	return der, nonce, nil
}

// fetchTimestamp obtains a verified TimeStampToken for tbs from the configured
// authority. It returns the DER ContentInfo — the timeStampToken field of the
// response, which is what sigTst2 carries — never the whole TimeStampResp.
func (s *Signer) fetchTimestamp(ctx context.Context, tbs []byte) ([]byte, error) {
	req, nonce, err := timestampRequest(tbs)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.tsaURL, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	client := s.cfg.tsaClient
	if client == nil {
		client = &http.Client{Timeout: defaultTSATimeout}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from the timestamp authority", resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/timestamp-reply" {
		return nil, fmt.Errorf("timestamp authority replied with content type %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTSAResponse {
		return nil, fmt.Errorf("timestamp reply exceeds %d bytes", maxTSAResponse)
	}
	return parseTimestampResponse(body, nonce, tbs)
}

// parseTimestampResponse checks a TimeStampResp: granted, carrying a token
// that verifies over tbs (checkTimestampToken — the validator's own checks),
// signed by a certificate with id-kp-timeStamping, and echoing the nonce we
// sent, which is what ties this reply to this request. It never panics; it is
// fuzzed with arbitrary bodies.
func parseTimestampResponse(body []byte, nonce *big.Int, tbs []byte) ([]byte, error) {
	var resp tsaResponse
	rest, err := asn1.Unmarshal(body, &resp)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("reply is not a TimeStampResp")
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("timestamp authority rejected the request (status %d)", resp.Status.Status)
	}
	token := resp.Token.FullBytes
	if len(token) == 0 {
		return nil, errors.New("timestamp authority granted the request but sent no token")
	}
	chk, err := checkTimestampToken(token, tbs)
	if err != nil {
		return nil, err
	}
	if !timestampEKUOK(chk.signer) {
		return nil, errors.New("timestamp signer lacks id-kp-timeStamping")
	}
	if chk.tstInfo.nonce == nil || chk.tstInfo.nonce.Cmp(nonce) != 0 {
		return nil, errors.New("timestamp token does not echo the request nonce")
	}
	return token, nil
}
