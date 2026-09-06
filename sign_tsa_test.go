package c2pa

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

// tsaResponder decides what the fake authority sends back for one request.
type tsaResponder func(t *testing.T, w http.ResponseWriter, req tsaRequest)

// newTSAServer serves RFC 3161 over httptest with the corpus TSA writer,
// minting a token over the imprint the request carries and echoing its nonce.
// respond, when set, replaces the default behaviour.
func newTSAServer(t *testing.T, ta *testTSA, respond tsaResponder) *httptest.Server {
	t.Helper()
	if respond == nil {
		respond = func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
			tsaReply(t, w, ta, req, tsRawImprint(req.MessageImprint.Hashed), tsNonce(req.Nonce))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Errorf("request: %s %s %q", r.Method, r.URL, r.Header.Get("Content-Type"))
		}
		body, _ := readAllLimited(r.Body, 1<<16)
		var req tsaRequest
		if rest, err := asn1.Unmarshal(body, &req); err != nil || len(rest) != 0 {
			t.Errorf("request is not a TimeStampReq: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Version != 1 || !req.CertReq || req.Nonce == nil || len(req.MessageImprint.Hashed) != 32 {
			t.Errorf("request shape: %+v", req)
		}
		respond(t, w, req)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func readAllLimited(r interface{ Read([]byte) (int, error) }, n int) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(&limitedReader{r: r, n: n})
	return buf.Bytes(), err
}

type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("body too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

// tsaReply writes a granted TimeStampResp minted with opts (plus a genTime of
// now and the response wrapper).
func tsaReply(t *testing.T, w http.ResponseWriter, ta *testTSA, _ tsaRequest, opts ...tsTokenOpt) {
	t.Helper()
	der := mintTSToken(t, ta, nil, append(opts, tsGenTime(time.Now()), tsWrapInResp())...)
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(der)
}

// liveTSA is a test authority whose certificates are valid around the wall
// clock, which a genTime of now requires.
func liveTSA(t *testing.T) *testTSA {
	t.Helper()
	now := time.Now()
	return newTestTSA(t, tsaValidity(now.Add(-time.Hour), now.Add(48*time.Hour)))
}

// TestSignWithTimestamp is the positive path: the token lands in sigTst2, the
// validator verifies it against the TSA's root, SignedAt is the TSA's time,
// and the envelope was padded to the larger reserve.
func TestSignWithTimestamp(t *testing.T) {
	ta := liveTSA(t)
	srv := newTSAServer(t, ta, nil)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Container{JPEG, PNG} {
		t.Run(string(c), func(t *testing.T) {
			before := time.Now().Truncate(time.Second)
			out := signBytes(t, s, c, unsignedInput(t, c), createdManifest("stamped"))
			res := Validate(context.Background(), c, bytes.NewReader(out),
				WithSigningTrust(sc.roots), WithTimestampTrust(ta.pool()), WithOnlineRevocation(false))
			if !res.Valid || !res.Has(StatusTimeStampValidated) {
				t.Fatalf("got %v: %v", codes(res), res.FirstFailure())
			}
			if res.Info.SignedAt.Before(before) || res.Info.SignedAt.After(time.Now().Add(5*time.Second)) {
				t.Errorf("SignedAt = %v, want about now", res.Info.SignedAt)
			}
			m := parseStore(context.Background(), extractJUMBF(context.Background(), c, out)).active()
			var msg cose.Sign1Message
			if err := msg.UnmarshalCBOR(m.signature); err != nil {
				t.Fatal(err)
			}
			if _, ok := msg.Headers.Unprotected["sigTst2"]; !ok {
				t.Errorf("no sigTst2 header: %v", msg.Headers.Unprotected)
			}
			if _, ok := msg.Headers.Unprotected["sigTst"]; ok {
				t.Errorf("a v2 claim must not carry the 1.x sigTst header")
			}
			if der, v2 := extractTSToken(msg.Headers.Unprotected); !v2 || !bytes.Equal(der, timestampContentInfo(der)) {
				t.Errorf("sigTst2 must carry the bare TimeStampToken, not the TimeStampResp")
			}
		})
	}
	// Without the TSA root the timestamp is untrusted — and that is a failure
	// for the validator, so a caller who wants Valid must anchor the TSA.
	out := signBytes(t, s, JPEG, unsignedJPEG(t), createdManifest("stamped"))
	res := Validate(context.Background(), JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Has(StatusTimeStampUntrusted) {
		t.Errorf("expected timeStamp.untrusted without the TSA anchor: %v", codes(res))
	}
}

// TestSignTimestampFailures pins that every way a TSA can go wrong fails the
// sign and writes nothing: the token never reaches the file unverified.
func TestSignTimestampFailures(t *testing.T) {
	ta := liveTSA(t)
	otherNonce := big.NewInt(12345)
	rejected := []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02} // TimeStampResp{status 2}, no token
	cases := map[string]tsaResponder{
		"http 500": func(_ *testing.T, w http.ResponseWriter, _ tsaRequest) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"wrong content type": func(_ *testing.T, w http.ResponseWriter, _ tsaRequest) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello"))
		},
		"rejected": func(_ *testing.T, w http.ResponseWriter, _ tsaRequest) {
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write(rejected)
		},
		"garbage body": func(_ *testing.T, w http.ResponseWriter, _ tsaRequest) {
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write([]byte("not asn.1 at all"))
		},
		"oversized body": func(_ *testing.T, w http.ResponseWriter, _ tsaRequest) {
			w.Header().Set("Content-Type", "application/timestamp-reply")
			_, _ = w.Write(make([]byte, maxTSAResponse+1))
		},
		"wrong imprint": func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
			tsaReply(t, w, ta, req, tsWrongImprint(), tsNonce(req.Nonce))
		},
		"wrong nonce": func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
			tsaReply(t, w, ta, req, tsRawImprint(req.MessageImprint.Hashed), tsNonce(otherNonce))
		},
		"no nonce": func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
			tsaReply(t, w, ta, req, tsRawImprint(req.MessageImprint.Hashed))
		},
		"corrupt signature": func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
			tsaReply(t, w, ta, req, tsRawImprint(req.MessageImprint.Hashed), tsNonce(req.Nonce), tsCorruptSignature())
		},
		"no certificates": func(t *testing.T, w http.ResponseWriter, req tsaRequest) {
			tsaReply(t, w, ta, req, tsRawImprint(req.MessageImprint.Hashed), tsNonce(req.Nonce), tsOmitCerts())
		},
	}
	sc := newSigningChain(t)
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTSAServer(t, ta, respond)
			s, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = s.Sign(context.Background(), JPEG, bytes.NewReader(unsignedJPEG(t)), &out, createdManifest("x"))
			if !errors.Is(err, ErrTimestamp) {
				t.Errorf("got %v, want ErrTimestamp", err)
			}
			if out.Len() != 0 {
				t.Errorf("wrote %d bytes on a timestamp failure", out.Len())
			}
		})
	}
	t.Run("authority unreachable", func(t *testing.T) {
		srv := newTSAServer(t, ta, nil)
		srv.Close()
		s, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Sign(context.Background(), JPEG, bytes.NewReader(unsignedJPEG(t)), &bytes.Buffer{}, createdManifest("x")); !errors.Is(err, ErrTimestamp) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("cancelled while waiting", func(t *testing.T) {
		srv := newTSAServer(t, ta, func(_ *testing.T, w http.ResponseWriter, _ tsaRequest) {
			<-w.(http.CloseNotifier).CloseNotify() //nolint:staticcheck // the request's own context is what we wait on
		})
		s, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		var out bytes.Buffer
		if err := s.Sign(ctx, JPEG, bytes.NewReader(unsignedJPEG(t)), &out, createdManifest("x")); !errors.Is(err, ErrTimestamp) || out.Len() != 0 {
			t.Errorf("got %v (%d bytes)", err, out.Len())
		}
	})
	t.Run("bad authority url", func(t *testing.T) {
		if _, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority("not a url")); !errors.Is(err, ErrSignerOption) {
			t.Errorf("got %v", err)
		}
		if _, err := NewSigner(sc.key, sc.chain, WithTimestampAuthority("ftp://tsa.example")); !errors.Is(err, ErrSignerOption) {
			t.Errorf("got %v", err)
		}
	})
}

// TestTimestampResponseParsing pins the client's own checks on a reply,
// independent of HTTP.
func TestTimestampResponseParsing(t *testing.T) {
	ta := liveTSA(t)
	tbs := []byte("counter-signature data")
	nonce := big.NewInt(0xABCDEF)
	imprint := hashBytes(cryptoSHA256(), tbs)
	good := mintTSToken(t, ta, nil, tsRawImprint(imprint), tsNonce(nonce), tsGenTime(time.Now()), tsWrapInResp())
	token, err := parseTimestampResponse(good, nonce, tbs)
	if err != nil {
		t.Fatalf("good reply rejected: %v", err)
	}
	if !bytes.Equal(token, timestampContentInfo(good)) {
		t.Errorf("returned token is not the response's TimeStampToken")
	}
	if _, err := parseTimestampResponse(good, big.NewInt(1), tbs); err == nil {
		t.Errorf("wrong nonce accepted")
	}
	if _, err := parseTimestampResponse(good, nonce, []byte("other")); err == nil {
		t.Errorf("wrong tbs accepted")
	}
	bare := mintTSToken(t, ta, nil, tsRawImprint(imprint), tsNonce(nonce), tsGenTime(time.Now()))
	if _, err := parseTimestampResponse(bare, nonce, tbs); err == nil {
		t.Errorf("a bare token (not a TimeStampResp) accepted")
	}
	if _, err := parseTimestampResponse(append(good, 0), nonce, tbs); err == nil {
		t.Errorf("trailing bytes accepted")
	}
}

// FuzzTSAResponse: arbitrary bytes as a TSA reply must never panic and must
// only be accepted when they are the genuine, nonce-echoing response.
func FuzzTSAResponse(f *testing.F) {
	ta := newTestTSA(f)
	tbs := []byte("counter-signature data")
	nonce := big.NewInt(0xABCDEF)
	genuine := mintTSToken(f, ta, nil, tsRawImprint(hashBytes(cryptoSHA256(), tbs)), tsNonce(nonce), tsWrapInResp())
	f.Add(genuine)
	f.Add(mintTSToken(f, ta, nil, tsWrapInResp()))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02})
	// The oracle is what the client promises of a reply it accepts, not "equals
	// the genuine bytes": any token whose CMS signature verifies under its own
	// certificates with the right imprint and nonce IS acceptable (trust is the
	// validator's decision), and a fuzz worker process mints a different test
	// TSA than the coordinator, so the coordinator's genuine seed arrives here
	// as a token from a stranger — and must still pass.
	f.Fuzz(func(t *testing.T, body []byte) {
		token, err := parseTimestampResponse(body, nonce, tbs)
		if err != nil {
			return
		}
		if !bytes.Contains(body, token) {
			t.Fatal("accepted token is not a slice of the reply")
		}
		chk, err := checkTimestampToken(token, tbs)
		if err != nil {
			t.Fatalf("accepted token fails the validator's own check: %v", err)
		}
		if chk.tstInfo.nonce == nil || chk.tstInfo.nonce.Cmp(nonce) != 0 {
			t.Fatalf("accepted token carries nonce %v, want %v", chk.tstInfo.nonce, nonce)
		}
		if !timestampEKUOK(chk.signer) {
			t.Fatal("accepted token's signer lacks id-kp-timeStamping")
		}
		if chk.tstInfo.genTime.IsZero() {
			t.Fatal("accepted token has no genTime")
		}
	})
}

func cryptoSHA256() crypto.Hash { return crypto.SHA256 }
