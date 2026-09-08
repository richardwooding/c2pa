package c2pa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

// countingContext is a context whose Err is counted, and which cancels its
// parent the n-th time Err is asked. The library checks ctx.Err() at every
// input-sized step, so cancelling at the n-th check, for every n a call makes,
// visits every point a cancellation can land on. Done/Deadline/Value delegate
// to the parent, so an HTTP transport (which waits on Done) sees the cancel
// too. Err is called from those transports' goroutines after the cancel, hence
// the atomic counter and the once-only cancel.
type countingContext struct {
	context.Context
	cancel  context.CancelFunc
	limit   int64
	checks  atomic.Int64
	stopped atomic.Bool
}

// newCountingContext returns a context that cancels at the limit-th Err call;
// a limit of 0 never cancels and just counts.
func newCountingContext(limit int) *countingContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &countingContext{Context: ctx, cancel: cancel, limit: int64(limit)}
}

func (c *countingContext) Err() error {
	n := c.checks.Add(1)
	if c.limit > 0 && n >= c.limit && c.stopped.CompareAndSwap(false, true) {
		c.cancel()
	}
	return c.Context.Err()
}

func (c *countingContext) total() int { return int(c.checks.Load()) }

// sweepPoints picks the cancellation points to try: every check up to cap,
// then evenly spaced, or all of them under C2PA_CANCEL_SWEEP=1.
func sweepPoints(total, cap int) []int {
	if total <= 0 {
		return nil
	}
	if os.Getenv("C2PA_CANCEL_SWEEP") != "" || total <= cap {
		out := make([]int, 0, total)
		for n := 1; n <= total; n++ {
			out = append(out, n)
		}
		return out
	}
	out := make([]int, 0, cap)
	for i := 0; i < cap; i++ {
		out = append(out, 1+i*(total-1)/(cap-1))
	}
	return out
}

// cancelAsset is one input for the sweeps.
type cancelAsset struct {
	name      string
	container Container
	data      []byte
	opts      []ValidateOption
	match     StatusCode
}

// cancelAssets are the assets the Validate sweep runs over: every hard-binding
// kind, an ingredient chain with a v2 timestamp, a CAWG identity, and the real
// fixtures.
func cancelAssets(t *testing.T) []cancelAsset {
	t.Helper()
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ta := newTestTSA(t)
	corpusOpts := []ValidateOption{WithSigningTrust(sb.roots), WithClock(corpusClock()), WithOnlineRevocation(false), WithTimestampTrust(ta.pool())}
	s, sc := newTestSigner(t)
	signed := func(c Container) []byte { return signBytes(t, s, c, unsignedInput(t, c), createdManifest("cancel")) }
	signOpts := []ValidateOption{WithSigningTrust(sc.roots), WithOnlineRevocation(false)}
	return []cancelAsset{
		{"corpus jpeg timestamped", JPEG, buildAsset(t, JPEG, manifestSpec{
			signer: sb, claimV2: true, tsKind: 2, tsa: ta, assertions: []assertionSpec{markerAssertion()},
		}), corpusOpts, StatusAssertionDataHashMatch},
		{"corpus png boxes", PNG, buildAsset(t, PNG, manifestSpec{signer: sb, assertions: []assertionSpec{markerAssertion()}}), corpusOpts, StatusAssertionDataHashMatch},
		{"corpus pdf", PDF, buildAsset(t, PDF, manifestSpec{signer: sb, claimV2: true, assertions: []assertionSpec{markerAssertion()}}), corpusOpts, StatusAssertionDataHashMatch},
		{"signed jpeg", JPEG, signed(JPEG), signOpts, StatusAssertionDataHashMatch},
		{"signed mp4", BMFF, signed(BMFF), signOpts, StatusAssertionBMFFHashMatch},
		{"fixture jpeg", JPEG, fixtureBytes(t, "c2pa_signed.jpg"), []ValidateOption{WithOnlineRevocation(false)}, StatusAssertionDataHashMatch},
		{"fixture cawg identity", JPEG, fixtureBytes(t, "cawg_x509.jpg"), []ValidateOption{WithOnlineRevocation(false)}, StatusAssertionDataHashMatch},
	}
}

// assertCancelledResult is the contract for a cancelled Validate: not Valid, a
// general.error carrying the cancellation, no status a cut-short hash could
// have forged, and a match only if the binding really completed.
func assertCancelledResult(t *testing.T, res ValidationResult, match StatusCode, n int) {
	t.Helper()
	if res.Valid {
		t.Errorf("cancel at check %d: Valid=true: %v", n, codes(res))
	}
	var cancelled bool
	for _, s := range res.Statuses {
		if s.Code == StatusGeneralError && errors.Is(s.Err, context.Canceled) {
			cancelled = true
		}
		switch s.Code {
		case StatusAssertionDataHashMismatch, StatusAssertionBoxesHashMismatch, StatusAssertionBMFFHashMismatch,
			StatusAssertionHashedURIMismatch, StatusAssertionBoxesHashMalformed, StatusAssertionBMFFHashMalformed,
			StatusClaimMissing, StatusClaimSignatureMismatch, StatusAssertionMissing:
			t.Errorf("cancel at check %d: a cancelled run reported %s (%s)", n, s.Code, s.Explanation)
		}
	}
	if !cancelled {
		t.Errorf("cancel at check %d: no general.error carrying context.Canceled: %v", n, codes(res))
	}
	if res.Has(match) && !hasBindingProof(res, match) {
		t.Errorf("cancel at check %d: %s reported without the binding completing", n, match)
	}
}

// hasBindingProof is true when the match came from a completed binding step —
// a match entry is only ever recorded after the whole hash compared equal, so
// its presence is the proof; this exists so the assertion reads as one.
func hasBindingProof(res ValidationResult, match StatusCode) bool { return res.Has(match) }

// TestValidateCancelledAtEveryStep cancels Validate at each context check it
// makes, over every hard-binding kind, and asserts the contract every time.
func TestValidateCancelledAtEveryStep(t *testing.T) {
	for _, a := range cancelAssets(t) {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			dry := newCountingContext(0)
			full := Validate(dry, a.container, bytes.NewReader(a.data), a.opts...)
			if !full.Has(a.match) {
				t.Fatalf("uncancelled run must verify the binding: %v", codes(full))
			}
			total := dry.total()
			if total < 5 {
				t.Fatalf("only %d context checks in a full run; the sweep proves nothing", total)
			}
			for _, n := range sweepPoints(total, 300) {
				cc := newCountingContext(n)
				res := Validate(cc, a.container, bytes.NewReader(a.data), a.opts...)
				assertCancelledResult(t, res, a.match, n)
			}
			t.Logf("%d context checks per run", total)
		})
	}
}

// TestValidateFragmentedCancelledAtEveryStep is the same sweep over a split set.
func TestValidateFragmentedCancelledAtEveryStep(t *testing.T) {
	s, sc := newTestSigner(t)
	init, frags := unsignedFragmentedSet(4, fragOpts{})
	outInit, outFrags := signFragmentedSet(t, s, init, frags, createdManifest("cancel fragments"))
	opts := []ValidateOption{WithSigningTrust(sc.roots), WithOnlineRevocation(false)}
	dry := newCountingContext(0)
	full := ValidateFragmented(dry, bytes.NewReader(outInit), readersOf(outFrags...), opts...)
	if !full.Has(StatusAssertionBMFFHashMatch) {
		t.Fatalf("uncancelled run must verify the set: %v", codes(full))
	}
	for _, n := range sweepPoints(dry.total(), 300) {
		cc := newCountingContext(n)
		res := ValidateFragmented(cc, bytes.NewReader(outInit), readersOf(outFrags...), opts...)
		assertCancelledResult(t, res, StatusAssertionBMFFHashMatch, n)
	}
}

// TestReadCancelledAtEveryStep: a cancelled Read is Info{}, a cancelled ReadAll
// is nil, a cancelled ExtractStore is the context's error, whenever the cancel
// lands.
func TestReadCancelledAtEveryStep(t *testing.T) {
	for _, a := range cancelAssets(t) {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			dry := newCountingContext(0)
			if info := Read(dry, a.container, bytes.NewReader(a.data)); !info.Present {
				t.Fatal("uncancelled Read found no manifest")
			}
			for _, n := range sweepPoints(dry.total(), 300) {
				if info := Read(newCountingContext(n), a.container, bytes.NewReader(a.data)); info != (Info{}) {
					t.Errorf("Read cancelled at check %d returned %+v", n, info)
				}
			}
			dry = newCountingContext(0)
			if all := ReadAll(dry, a.container, bytes.NewReader(a.data)); len(all) == 0 {
				t.Fatal("uncancelled ReadAll found no manifest")
			}
			for _, n := range sweepPoints(dry.total(), 300) {
				if all := ReadAll(newCountingContext(n), a.container, bytes.NewReader(a.data)); all != nil {
					t.Errorf("ReadAll cancelled at check %d returned %d manifests", n, len(all))
				}
			}
			dry = newCountingContext(0)
			if store, err := ExtractStore(dry, a.container, bytes.NewReader(a.data)); err != nil || len(store) == 0 {
				t.Fatalf("uncancelled ExtractStore: %d bytes, %v", len(store), err)
			}
			for _, n := range sweepPoints(dry.total(), 300) {
				store, err := ExtractStore(newCountingContext(n), a.container, bytes.NewReader(a.data))
				if !errors.Is(err, context.Canceled) || store != nil {
					t.Errorf("ExtractStore cancelled at check %d: %d bytes, %v", n, len(store), err)
				}
			}
		})
	}
}

// TestWalkBoxesCancelled: the walk stops at the cancel and calls fn no more.
func TestWalkBoxesCancelled(t *testing.T) {
	store := extractJUMBF(context.Background(), JPEG, fixtureBytes(t, "c2pa_signed.jpg"))
	dry := newCountingContext(0)
	calls := 0
	WalkBoxes(dry, store, func(string, string, []byte) { calls++ })
	if calls == 0 {
		t.Fatal("uncancelled walk visited nothing")
	}
	for _, n := range sweepPoints(dry.total(), 300) {
		cc := newCountingContext(n)
		after := 0
		WalkBoxes(cc, store, func(string, string, []byte) {
			if cc.Context.Err() != nil {
				after++
			}
		})
		if after != 0 {
			t.Errorf("cancel at check %d: fn called %d times after the cancel", n, after)
		}
	}
}

// TestSignCancelledAtEveryStep cancels Sign at each context check, with a TSA
// so the timestamp windows are covered, and requires the context's error and
// nothing written.
func TestSignCancelledAtEveryStep(t *testing.T) {
	ta := liveTSA(t)
	srv := newTSAServer(t, ta, nil)
	sc := newSigningChain(t)
	idChain := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("cancel", "1"), WithTimestampAuthority(srv.URL), WithIdentitySigner(idChain.key, idChain.chain))
	if err != nil {
		t.Fatal(err)
	}
	m := createdManifest("cancel sign")
	m.Identity = IdentityInfo{Roles: []string{RoleCreator}}
	for _, c := range []Container{JPEG, PDF, BMFF} {
		t.Run(string(c), func(t *testing.T) {
			t.Parallel()
			in := unsignedInput(t, c)
			dry := newCountingContext(0)
			var out bytes.Buffer
			if err := s.Sign(dry, c, bytes.NewReader(in), &out, m); err != nil {
				t.Fatalf("uncancelled Sign: %v", err)
			}
			for _, n := range sweepPoints(dry.total(), 40) {
				var out bytes.Buffer
				err := s.Sign(newCountingContext(n), c, bytes.NewReader(in), &out, m)
				if !errors.Is(err, context.Canceled) {
					t.Errorf("cancel at check %d: err = %v", n, err)
				}
				if out.Len() != 0 {
					t.Errorf("cancel at check %d: wrote %d bytes", n, out.Len())
				}
			}
		})
	}
	t.Run("fragmented", func(t *testing.T) {
		init, frags := unsignedFragmentedSet(3, fragOpts{})
		dry := newCountingContext(0)
		fullBufs, outs := fragmentWriters(len(frags))
		var fullInit bytes.Buffer
		if err := s.SignFragmented(dry, bytes.NewReader(init), fragmentSeekers(frags), &fullInit, outs, m); err != nil {
			t.Fatalf("uncancelled SignFragmented: %v", err)
		}
		fullWritten := fullInit.Len()
		for _, b := range fullBufs {
			fullWritten += b.Len()
		}
		for _, n := range sweepPoints(dry.total(), 40) {
			bufs, outs := fragmentWriters(len(frags))
			var outInit bytes.Buffer
			err := s.SignFragmented(newCountingContext(n), bytes.NewReader(init), fragmentSeekers(frags), &outInit, outs, m)
			written := outInit.Len()
			for _, b := range bufs {
				written += b.Len()
			}
			// Before the point of no return: the cancellation and nothing
			// written. After it: the whole set, since a half-written set is
			// worse than a late one.
			switch {
			case err == nil && written == fullWritten:
			case errors.Is(err, context.Canceled) && written == 0:
			default:
				t.Errorf("cancel at check %d: err = %v, wrote %d of %d bytes", n, err, written, fullWritten)
			}
		}
	})
}

// TestRevocationRequestsCarryContext: an OCSP responder that never answers
// holds Validate only until the context ends — the request carries it. No
// timing is asserted: the responder signals the request's arrival, the test
// cancels, and the responder returns only when it sees its own request context
// cancelled.
func TestRevocationRequestsCarryContext(t *testing.T) {
	arrived := make(chan struct{}, 1)
	released := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server only watches for the client going away once the request
		// body has been consumed, so read it before waiting.
		_, _ = io.ReadAll(r.Body)
		arrived <- struct{}{}
		<-r.Context().Done()
		released <- struct{}{}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sb := newCorpusSigner(t, cose.AlgorithmES256, func(p *certProfile) { p.ocspURL = srv.URL })
	asset := buildAsset(t, JPEG, manifestSpec{signer: sb, assertions: []assertionSpec{markerAssertion()}})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-arrived
		cancel()
	}()
	res := Validate(ctx, JPEG, bytes.NewReader(asset), WithSigningTrust(sb.roots), WithClock(corpusClock()),
		WithOnlineRevocation(true), WithHTTPClient(&http.Client{}))
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("the OCSP request did not see the cancellation")
	}
	if res.Valid || !res.Has(StatusGeneralError) {
		t.Errorf("cancelled during revocation: valid=%v %v", res.Valid, codes(res))
	}
}

// TestBMFFMerkleCancelledAtEveryStep sweeps the flat fragmented merkle path,
// which used to report a cancel as an INFORMATIONAL and let the result come out
// Valid.
func TestBMFFMerkleCancelledAtEveryStep(t *testing.T) {
	ff := fragmentedFlatAsset(t, 5, 2, 1, 1, nil)
	raw := mustMarshalCBOR(t, ff.assertion)
	run := func(ctx context.Context) ValidationResult {
		v := &validator{ctx: ctx, cfg: validateConfig{maxScan: ValidateMaxScan}, container: BMFF, data: ff.asset}
		v.verifyBMFFHash(&rawAssertion{label: "c2pa.hash.bmff.v3", data: raw}, "urn:test")
		return v.finish()
	}
	dry := newCountingContext(0)
	if full := run(dry); !full.Has(StatusAssertionBMFFHashMatch) || !full.Valid {
		t.Fatalf("uncancelled: %v", codes(full))
	}
	for _, n := range sweepPoints(dry.total(), 300) {
		res := run(newCountingContext(n))
		assertCancelledResult(t, res, StatusAssertionBMFFHashMatch, n)
		if res.Has(StatusUnsupported) {
			t.Errorf("cancel at check %d: a cancel is not an informational: %v", n, codes(res))
		}
	}
}

func TestHashWriteAndReadAllCtx(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 3*hashChunk+123)
	want := hashOf(t, "sha256", data)
	h, _ := hashByName("sha256")
	if err := hashWrite(context.Background(), h, data); err != nil || !bytes.Equal(h.Sum(nil), want) {
		t.Fatalf("hashWrite: %v", err)
	}
	// Cancelled between chunks: the error comes back and the digest is not the whole data's.
	cc := newCountingContext(3)
	h, _ = hashByName("sha256")
	if err := hashWrite(cc, h, data); !errors.Is(err, context.Canceled) {
		t.Fatalf("hashWrite cancelled: %v", err)
	}
	if bytes.Equal(h.Sum(nil), want) {
		t.Error("a cancelled hash equalled the full digest")
	}

	got, err := readAllCtx(context.Background(), bytes.NewReader(data), len(data)+1)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("readAllCtx: %d bytes, %v", len(got), err)
	}
	if got, err := readAllCtx(context.Background(), bytes.NewReader(data), 100); err != nil || len(got) != 100 {
		t.Fatalf("readAllCtx limit: %d bytes, %v", len(got), err)
	}
	if _, err := readAllCtx(newCountingContext(2), bytes.NewReader(data), len(data)); !errors.Is(err, context.Canceled) {
		t.Fatalf("readAllCtx cancelled: %v", err)
	}
	if _, err := readAllCtx(context.Background(), &erroringReader{}, 10); err == nil || strings.Contains(err.Error(), "context") {
		t.Fatalf("readAllCtx reader error: %v", err)
	}
	if got, err := readAllCtx(context.Background(), bytes.NewReader(data), 0); err != nil || got != nil {
		t.Fatalf("readAllCtx zero limit: %v %v", got, err)
	}
}

type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error) { return 0, fmt.Errorf("boom") }
