package c2pa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// readersOf wraps each fragment in a reader.
func readersOf(frags ...[]byte) []io.Reader {
	out := make([]io.Reader, len(frags))
	for i, f := range frags {
		out[i] = bytes.NewReader(f)
	}
	return out
}

// runFragmented checks a merkle assertion against an initialization segment
// and fragment readers directly, without the signing machinery: the hard
// binding is what is under test. ctx is the validator's, so a reader can
// cancel it mid-way.
func runFragmented(ctx context.Context, t testing.TB, init []byte, frags []io.Reader, assertion map[string]any, opts ...ValidateOption) ValidationResult {
	t.Helper()
	raw, err := cbor.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	v := newValidator(ctx, BMFF, opts)
	v.data = init
	v.fragments = &fragmentSet{readers: frags}
	v.verifyBMFFHash(&rawAssertion{label: "c2pa.hash.bmff.v3", data: raw}, "urn:test")
	return v.finish()
}

// rollupExplanation returns the fragmented advisory on the assertion itself —
// the general.unsupported whose URI names no fragment.
func rollupExplanation(res ValidationResult) string {
	for _, s := range res.Statuses {
		if s.Code == StatusUnsupported && !strings.Contains(s.URI, "#fragment=") {
			return s.Explanation
		}
	}
	return ""
}

// fragmentFailures returns the failure statuses whose URI names a fragment,
// keyed by the index after "#fragment=".
func fragmentFailures(res ValidationResult) map[string]StatusEntry {
	out := map[string]StatusEntry{}
	for _, s := range res.Statuses {
		if _, index, ok := strings.Cut(s.URI, "#fragment="); ok && s.Severity == SeverityFailure {
			out[index] = s
		}
	}
	return out
}

// signedFragmentedAsset builds the signed initialization segment of a
// fragmented asset split across files. The manifest store goes into a C2PA
// uuid box placed LAST, so initHash — 'moov' alone, with /ftyp and /uuid
// excluded — does not depend on the store's size and no fixpoint is needed:
// the same reasoning buildBoxHashAsset documents. spec's signer, label and
// overlay are honoured; its bindings are replaced by the merkle assertion.
func signedFragmentedAsset(t testing.TB, sf splitFragmented, spec manifestSpec) []byte {
	t.Helper()
	spec.noHardBinding = true
	spec.extraBinding = &assertionSpec{label: "c2pa.hash.bmff.v3", value: sf.assertion}
	if len(spec.assertions) == 0 {
		spec.assertions = []assertionSpec{markerAssertion()}
	}
	return buildFramedAsset(t, func(store []byte) ([]byte, []byteRange) {
		return append(append([]byte(nil), sf.init...), synthC2PABox("manifest", store, 0)...), nil
	}, spec)
}

// validateFragmentedCorpus runs ValidateFragmented with the corpus signer's
// anchors and clock, as runCorpus does for Validate.
func validateFragmentedCorpus(t testing.TB, init []byte, frags []io.Reader, sb *signerBundle, extra ...ValidateOption) ValidationResult {
	t.Helper()
	opts := []ValidateOption{
		WithSigningTrust(sb.roots),
		WithClock(corpusClock()),
		WithOnlineRevocation(false),
	}
	return ValidateFragmented(context.Background(), bytes.NewReader(init), frags, append(opts, extra...)...)
}

// expectFragmentedMatch asserts the full-coverage verdict: valid, bound, no
// per-fragment entries, no fragmented advisory.
func expectFragmentedMatch(t testing.TB, res ValidationResult, n int) {
	t.Helper()
	if !res.Valid {
		t.Fatalf("expected valid, got %v: %s", codes(res), firstFailureText(res))
	}
	if !res.Has(StatusAssertionBMFFHashMatch) {
		t.Fatalf("expected %s, got %v (%q)", StatusAssertionBMFFHashMatch, codes(res), merkleExplanation(res))
	}
	want := fmt.Sprintf("all %d fragments", n)
	if got := statusExplanation(res, StatusAssertionBMFFHashMatch); !strings.Contains(got, want) {
		t.Errorf("match does not say %q: %q", want, got)
	}
	for _, s := range res.Statuses {
		if strings.Contains(s.URI, "#fragment=") {
			t.Errorf("a fully verified asset has no per-fragment entries: %+v", s)
		}
		if s.Code == StatusUnsupported && strings.Contains(s.Explanation, "fragmented") {
			t.Errorf("a fully verified asset raises no fragmented advisory: %q", s.Explanation)
		}
	}
}

func firstFailureText(res ValidationResult) string {
	if f := res.FirstFailure(); f != nil {
		return f.Explanation
	}
	return ""
}

// --- the signed, end-to-end cases ----------------------------------------------

// TestValidateFragmentedAllFragments is the whole point: an initialization
// segment plus every fragment comes out valid and bound, with the same
// signature, chain and timestamp checks Validate gives a single file.
func TestValidateFragmentedAllFragments(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 4, 1, 1, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{signer: sb})
	res := validateFragmentedCorpus(t, init, readersOf(sf.frags...), sb)
	expectFragmentedMatch(t, res, 4)
	if !res.Has(StatusClaimSignatureValidated) {
		t.Errorf("the initialization segment's signature should have been verified: %v", codes(res))
	}
}

// TestValidateFragmentedSubset pins the roll-up rule: a legitimate partial
// check verifies what was supplied, names what was not, and neither fails nor
// claims a match.
func TestValidateFragmentedSubset(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 4, 1, 1, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{signer: sb})
	res := validateFragmentedCorpus(t, init, readersOf(sf.frags[1:3]...), sb)
	if !res.Valid {
		t.Fatalf("a partial set is not a failure: %v: %s", codes(res), firstFailureText(res))
	}
	if res.Has(StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match with two of four fragments")
	}
	got := merkleExplanation(res)
	for _, want := range []string{"2 of 4 fragments", "locations 0, 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("advisory does not say %q: %q", want, got)
		}
	}
}

// TestValidateFragmentedOrderAndDuplicates pins that a fragment's place comes
// from its merkle box, not from where the caller put it, and that seeing one
// twice changes nothing.
func TestValidateFragmentedOrderAndDuplicates(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{signer: sb})
	reversed := readersOf(sf.frags[2], sf.frags[1], sf.frags[0])
	expectFragmentedMatch(t, validateFragmentedCorpus(t, init, reversed, sb), 3)
	duplicated := readersOf(sf.frags[0], sf.frags[0], sf.frags[1], sf.frags[2])
	expectFragmentedMatch(t, validateFragmentedCorpus(t, init, duplicated, sb), 3)
}

// TestValidateFragmentedTamper is the binding at work: an edited fragment
// fails at ITS index and no other; an edited initialization segment fails the
// init hash, and the fragments are still reported.
func TestValidateFragmentedTamper(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 4, 1, 1, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{signer: sb})

	frags := readersOf(sf.frags...)
	bad := append([]byte(nil), sf.frags[2]...)
	bad[len(bad)-4] ^= 0xFF // inside the 'mdat'
	frags[2] = bytes.NewReader(bad)
	res := validateFragmentedCorpus(t, init, frags, sb)
	if res.Valid {
		t.Errorf("an edited fragment should fail: %v", codes(res))
	}
	failures := fragmentFailures(res)
	if f, ok := failures["2"]; !ok || f.Code != StatusAssertionBMFFHashMismatch || !strings.Contains(f.Explanation, "location 2") {
		t.Errorf("expected a mismatch at #fragment=2 naming location 2, got %+v", failures)
	}
	if len(failures) != 1 {
		t.Errorf("only the edited fragment should fail: %+v", failures)
	}
	if res.Has(StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match alongside a fragment mismatch")
	}

	badInit := append([]byte(nil), init...)
	badInit[len(sf.init)-4] ^= 0xFF // inside 'moov'
	frags = readersOf(sf.frags...)
	frags[1] = bytes.NewReader(bad)
	res = validateFragmentedCorpus(t, badInit, frags, sb)
	if res.Valid {
		t.Errorf("an edited initialization segment should fail: %v", codes(res))
	}
	if got := statusExplanation(res, StatusAssertionBMFFHashMismatch); !strings.Contains(got, "initialization segment") {
		t.Errorf("expected the init hash to fail first: %q", got)
	}
	if _, ok := fragmentFailures(res)["1"]; !ok {
		t.Errorf("fragments should still be verified after an init mismatch: %v", codes(res))
	}
}

// TestValidateFragmentedForeignFragment pins pairing by uniqueId/localId: a
// fragment of another asset — or another track the manifest does not bind —
// is not this asset's, and saying so is a failure.
func TestValidateFragmentedForeignFragment(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{})
	other := fragmentedFiles(t, 2, 1, 2, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{signer: sb})
	res := validateFragmentedCorpus(t, init, readersOf(sf.frags[0], other.frags[1]), sb)
	if res.Valid {
		t.Errorf("a foreign fragment should fail: %v", codes(res))
	}
	f, ok := fragmentFailures(res)["1"]
	if !ok || f.Code != StatusAssertionBMFFHashMismatch || !strings.Contains(f.Explanation, "uniqueId 2/localId 1") {
		t.Errorf("expected a mismatch at #fragment=1 naming the foreign tree, got %+v", f)
	}
}

// TestValidateFragmentedNoFragments pins the empty set: the initialization
// segment is verified, nothing is disproved, and nothing is matched.
func TestValidateFragmentedNoFragments(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{signer: sb})
	for name, frags := range map[string][]io.Reader{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			res := validateFragmentedCorpus(t, init, frags, sb)
			if !res.Valid {
				t.Errorf("no fragments is not a failure: %v: %s", codes(res), firstFailureText(res))
			}
			if res.Has(StatusAssertionBMFFHashMatch) {
				t.Errorf("reported a match with no fragments")
			}
			got := merkleExplanation(res)
			for _, want := range []string{"0 of 3 fragments", "locations 0..2", "no fragments supplied"} {
				if !strings.Contains(got, want) {
					t.Errorf("advisory does not say %q: %q", want, got)
				}
			}
		})
	}
}

// TestValidateFragmentedPlainMP4 pins that a flat, non-fragmented MP4 handed in
// as an initialization segment is malformed for the purpose: its binding is a
// flat hash, which says nothing about fragments.
func TestValidateFragmentedPlainMP4(t *testing.T) {
	video, err := os.ReadFile("testdata/c2pa_signed_video.mp4")
	if err != nil {
		t.Fatal(err)
	}
	sf := fragmentedFiles(t, 1, 1, 1, 1, splitOpts{})
	res := ValidateFragmented(context.Background(), bytes.NewReader(video), readersOf(sf.frags...))
	if res.Valid {
		t.Errorf("a flat-hash binding cannot bind fragments: %v", codes(res))
	}
	if got := statusExplanation(res, StatusAssertionBMFFHashMalformed); !strings.Contains(got, "flat hash") {
		t.Errorf("expected the flat hash to be called out, got %v (%q)", codes(res), got)
	}
	if res.Has(StatusAssertionBMFFHashMatch) {
		t.Errorf("reported a match")
	}
}

// mustNotRead fails the test if anything reads it.
type mustNotRead struct{ t testing.TB }

func (m *mustNotRead) Read([]byte) (int, error) {
	m.t.Errorf("a fragment was read though nothing could bind it")
	return 0, io.EOF
}

// TestValidateFragmentedNeedsBMFFBinding pins that a c2pa.hash.data over the
// initialization segment does not bind the fragments — and that fragments are
// never read when nothing could bind them.
func TestValidateFragmentedNeedsBMFFBinding(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{})
	init := buildFramedAsset(t, func(store []byte) ([]byte, []byteRange) {
		box := synthC2PABox("manifest", store, 0)
		return append(append([]byte(nil), sf.init...), box...), []byteRange{{start: len(sf.init), length: len(box)}}
	}, manifestSpec{signer: sb, assertions: []assertionSpec{markerAssertion()}})
	res := validateFragmentedCorpus(t, init, []io.Reader{&mustNotRead{t}}, sb)
	if !res.Has(StatusHardBindingMissing) {
		t.Errorf("expected %s, got %v", StatusHardBindingMissing, codes(res))
	}
	if res.Valid {
		t.Errorf("fragments left unbound is a failure")
	}
}

// TestValidateFragmentedUpdateManifest pins that the fragmented branch is
// reached through an update manifest's parent too: it is keyed off the entry
// point, not the call site.
func TestValidateFragmentedUpdateManifest(t *testing.T) {
	const parentLabel = "urn:uuid:00000000-0000-4000-8000-0000000000aa"
	const updateLabel = "urn:uuid:00000000-0000-4000-8000-0000000000bb"
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{})
	init := signedFragmentedAsset(t, sf, manifestSpec{
		signer: sb, label: parentLabel,
		updateOverlay: &manifestSpec{
			signer: sb, label: updateLabel, updateManifest: true, noHardBinding: true,
			assertions: []assertionSpec{parentOfAssertion(t, parentLabel)},
		},
	})
	res := validateFragmentedCorpus(t, init, readersOf(sf.frags...), sb)
	expectFragmentedMatch(t, res, 2)
	if res.ActiveManifestLabel != updateLabel {
		t.Errorf("active manifest should be the update, got %q", res.ActiveManifestLabel)
	}
}

// TestValidateFragmentedMultiTrack covers two trees — video and audio
// representations sharing one initialization segment — where a match needs
// every location of BOTH covered, and the advisory names the tree left short.
func TestValidateFragmentedMultiTrack(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	video := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	audio := fragmentedFiles(t, 2, 1, 1, 2, splitOpts{})
	both := video
	both.assertion = map[string]any{
		"alg":        "sha256",
		"exclusions": video.assertion["exclusions"],
		"merkle":     []any{firstMerkleMap(video.assertion), firstMerkleMap(audio.assertion)},
	}
	init := signedFragmentedAsset(t, both, manifestSpec{signer: sb})

	all := append(readersOf(video.frags...), readersOf(audio.frags...)...)
	expectFragmentedMatch(t, validateFragmentedCorpus(t, init, all, sb), 5)

	res := validateFragmentedCorpus(t, init, readersOf(video.frags...), sb)
	if !res.Valid || res.Has(StatusAssertionBMFFHashMatch) {
		t.Errorf("one tree covered should be a valid partial, got %v", codes(res))
	}
	if got := merkleExplanation(res); !strings.Contains(got, "tree uniqueId 1/localId 2 locations 0..1") {
		t.Errorf("advisory does not name the audio tree: %q", got)
	}
}

// TestValidateFragmentedMultiRendition: c2pa-rs signs several renditions into
// ONE manifest — one merkle map per initialization segment, the identical store
// in each. Given one init, the maps whose initHash is another init's are named
// as not evaluated, not failed; a fragment that claims such a map IS a failure,
// since the caller asserted these are this asset's fragments; and an init that
// matches no map at all is still tampered.
func TestValidateFragmentedMultiRendition(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	a := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	b := fragmentedFiles(t, 2, 1, 2, 2, splitOpts{moovFill: 0x66})
	if bytes.Equal(a.init, b.init) {
		t.Fatal("the two renditions need different initialization segments")
	}
	both := a
	both.assertion = map[string]any{
		"alg":        "sha256",
		"exclusions": a.assertion["exclusions"],
		"merkle":     []any{firstMerkleMap(a.assertion), firstMerkleMap(b.assertion)},
	}
	init := signedFragmentedAsset(t, both, manifestSpec{signer: sb})

	t.Run("own fragments", func(t *testing.T) {
		res := validateFragmentedCorpus(t, init, readersOf(a.frags...), sb)
		if !res.Valid || !res.Has(StatusAssertionBMFFHashMatch) {
			t.Fatalf("got %v: %s", codes(res), firstFailureText(res))
		}
		if got := statusExplanation(res, StatusUnsupported); !strings.Contains(got, "uniqueId 2/localId 2") || !strings.Contains(got, "other initialization segments") {
			t.Errorf("the other rendition's map should be named as not evaluated: %q", got)
		}
	})
	t.Run("other rendition's fragments", func(t *testing.T) {
		res := validateFragmentedCorpus(t, init, readersOf(b.frags...), sb)
		if res.Valid || res.Has(StatusAssertionBMFFHashMatch) {
			t.Fatalf("fragments of another rendition should fail: %v", codes(res))
		}
		fails := fragmentFailures(res)
		if len(fails) != 2 {
			t.Fatalf("want a failure per fragment, got %v", fails)
		}
		for uri, st := range fails {
			if !strings.Contains(st.Explanation, "does not match this initialization segment") {
				t.Errorf("%s: %q", uri, st.Explanation)
			}
		}
	})
	t.Run("subset of own fragments", func(t *testing.T) {
		res := validateFragmentedCorpus(t, init, readersOf(a.frags[0]), sb)
		if !res.Valid || res.Has(StatusAssertionBMFFHashMatch) {
			t.Fatalf("a partial set is a valid partial: %v", codes(res))
		}
		if got := merkleExplanation(res); !strings.Contains(got, "1 of 3 fragments") {
			t.Errorf("coverage should count only this init's tree: %q", got)
		}
	})
	t.Run("tampered init", func(t *testing.T) {
		bad := append([]byte(nil), init...)
		moov := bytes.Index(bad, []byte("moov"))
		bad[moov+8] ^= 0xFF
		res := validateFragmentedCorpus(t, bad, readersOf(a.frags...), sb)
		if res.Valid || res.Has(StatusAssertionBMFFHashMatch) {
			t.Fatalf("a tampered init should fail: %v", codes(res))
		}
		n := 0
		for _, st := range res.Statuses {
			if st.Code == StatusAssertionBMFFHashMismatch && strings.Contains(st.Explanation, "initialization segment hash does not match merkle map") {
				n++
			}
		}
		if n != 2 {
			t.Errorf("both maps should report the init mismatch, got %d", n)
		}
	})
}

// --- the binding-only edge cases ----------------------------------------------

// TestValidateFragmentedMalformedAssertion covers what a split-file assertion
// must carry: an initHash on every map, a location inside the tree, and a
// count under the leaf cap.
func TestValidateFragmentedMalformedAssertion(t *testing.T) {
	ctx := context.Background()
	t.Run("no initHash", func(t *testing.T) {
		sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{})
		delete(firstMerkleMap(sf.assertion), "initHash")
		res := runFragmented(ctx, t, sf.init, readersOf(sf.frags...), sf.assertion)
		if got := statusExplanation(res, StatusAssertionBMFFHashMalformed); !strings.Contains(got, "no initHash") {
			t.Errorf("expected malformed naming the missing initHash, got %v (%q)", codes(res), got)
		}
	})
	t.Run("location outside the tree", func(t *testing.T) {
		sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{mutate: func(k int, spec *merkleBoxSpec) {
			if k == 1 {
				spec.location = 2
			}
		}})
		res := runFragmented(ctx, t, sf.init, readersOf(sf.frags...), sf.assertion)
		f, ok := fragmentFailures(res)["1"]
		if !ok || f.Code != StatusAssertionBMFFHashMalformed || !strings.Contains(f.Explanation, "outside the tree") {
			t.Errorf("expected malformed at #fragment=1, got %+v", f)
		}
	})
	t.Run("count over the leaf cap", func(t *testing.T) {
		sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{})
		firstMerkleMap(sf.assertion)["count"] = maxMerkleLeaves + 1
		res := runFragmented(ctx, t, sf.init, readersOf(sf.frags...), sf.assertion)
		if got := statusExplanation(res, StatusAssertionBMFFHashMalformed); !strings.Contains(got, "leaf cap") {
			t.Errorf("expected malformed naming the cap, got %v (%q)", codes(res), got)
		}
	})
	t.Run("fragment with no merkle box", func(t *testing.T) {
		sf := fragmentedFiles(t, 2, 1, 1, 1, splitOpts{})
		res := runFragmented(ctx, t, sf.init, readersOf(sf.frags[0], sf.init), sf.assertion)
		f, ok := fragmentFailures(res)["1"]
		if !ok || f.Code != StatusAssertionBMFFHashMalformed || !strings.Contains(f.Explanation, "no C2PA merkle box") {
			t.Errorf("an initialization segment passed as a fragment should be malformed, got %+v", f)
		}
	})
	t.Run("fragment that is not BMFF", func(t *testing.T) {
		sf := fragmentedFiles(t, 1, 1, 1, 1, splitOpts{})
		res := runFragmented(ctx, t, sf.init, readersOf([]byte("not a box structure")), sf.assertion)
		f, ok := fragmentFailures(res)["0"]
		if !ok || f.Code != StatusAssertionBMFFHashMalformed {
			t.Errorf("expected malformed at #fragment=0, got %+v", f)
		}
	})
}

// TestValidateFragmentedReaders covers what a reader can do wrong: be nil,
// fail mid-stream, be empty, or exceed the scan cap. The first three are
// failures with the caller's index; the cap is informational, as everywhere.
func TestValidateFragmentedReaders(t *testing.T) {
	ctx := context.Background()
	sf := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	errBoom := errors.New("boom")

	t.Run("nil reader", func(t *testing.T) {
		res := runFragmented(ctx, t, sf.init, []io.Reader{nil, bytes.NewReader(sf.frags[1])}, sf.assertion)
		f, ok := fragmentFailures(res)["0"]
		if !ok || f.Code != StatusGeneralError || res.Valid {
			t.Errorf("expected general.error at #fragment=0, got %v", codes(res))
		}
	})
	t.Run("read error mid-stream", func(t *testing.T) {
		frags := readersOf(sf.frags...)
		frags[1] = io.MultiReader(bytes.NewReader(sf.frags[1][:16]), iotest.ErrReader(errBoom))
		res := runFragmented(ctx, t, sf.init, frags, sf.assertion)
		f, ok := fragmentFailures(res)["1"]
		if !ok || f.Code != StatusGeneralError || !errors.Is(f.Err, errBoom) {
			t.Errorf("expected general.error carrying the reader's error at #fragment=1, got %+v", f)
		}
		if res.Valid || res.Has(StatusAssertionBMFFHashMatch) {
			t.Errorf("an unreadable fragment is a failure, not a match: %v", codes(res))
		}
	})
	t.Run("empty reader", func(t *testing.T) {
		res := runFragmented(ctx, t, sf.init, readersOf(sf.frags[0], nil), sf.assertion)
		f, ok := fragmentFailures(res)["1"]
		if !ok || f.Code != StatusGeneralError || !strings.Contains(f.Explanation, "no readable input") {
			t.Errorf("expected general.error at #fragment=1, got %+v", f)
		}
	})
	t.Run("scan cap", func(t *testing.T) {
		// The initialization segment is far smaller than a fragment, so a cap
		// the size of a fragment truncates every fragment and nothing else.
		res := runFragmented(ctx, t, sf.init, readersOf(sf.frags...), sf.assertion, WithMaxScan(len(sf.frags[0])))
		if !res.Valid || res.Has(StatusAssertionBMFFHashMatch) {
			t.Errorf("truncation is informational, never a verdict: %v", codes(res))
		}
		capped := 0
		for _, s := range res.Statuses {
			if s.Code == StatusUnsupported && strings.Contains(s.Explanation, "scan cap") && strings.Contains(s.URI, "#fragment=") {
				capped++
			}
		}
		if capped != 3 {
			t.Errorf("expected every fragment to report the cap, got %d: %v", capped, codes(res))
		}
		if got := rollupExplanation(res); !strings.Contains(got, "locations 0..2") {
			t.Errorf("coverage should name the unverified locations: %q", got)
		}
	})
}

// cancelOnRead cancels the validator's context the first time it is read.
type cancelOnRead struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (c *cancelOnRead) Read(p []byte) (int, error) {
	c.cancel()
	return c.r.Read(p)
}

// TestValidateFragmentedCancelled pins that cancellation is reported as such —
// a failure, at the fragment it interrupted — and that nothing after it is
// touched or misreported as a mismatch.
func TestValidateFragmentedCancelled(t *testing.T) {
	sf := fragmentedFiles(t, 3, 1, 1, 1, splitOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frags := readersOf(sf.frags...)
	frags[1] = &cancelOnRead{r: frags[1], cancel: cancel}
	frags[2] = &mustNotRead{t}
	res := runFragmented(ctx, t, sf.init, frags, sf.assertion)
	if res.Valid {
		t.Errorf("an aborted run must not come out valid: %v", codes(res))
	}
	failures := fragmentFailures(res)
	if f, ok := failures["1"]; !ok || f.Code != StatusGeneralError || !errors.Is(f.Err, context.Canceled) {
		t.Errorf("expected the cancellation at #fragment=1, got %+v", failures)
	}
	if _, ok := failures["2"]; ok {
		t.Errorf("nothing after the cancellation should be reported: %+v", failures)
	}
	if res.Has(StatusAssertionBMFFHashMismatch) {
		t.Errorf("a hash cut short by cancellation was misreported as a mismatch")
	}
}

// traceReader logs its first Read and its EOF.
type traceReader struct {
	r       io.Reader
	name    string
	log     *[]string
	started bool
}

func (tr *traceReader) Read(p []byte) (int, error) {
	if !tr.started {
		tr.started = true
		*tr.log = append(*tr.log, "start "+tr.name)
	}
	n, err := tr.r.Read(p)
	if err == io.EOF {
		*tr.log = append(*tr.log, "eof "+tr.name)
	}
	return n, err
}

// TestValidateFragmentedOneAtATime pins the memory contract: fragment i+1 is
// not opened until fragment i has been read to its end.
func TestValidateFragmentedOneAtATime(t *testing.T) {
	sf := fragmentedFiles(t, 4, 1, 1, 1, splitOpts{})
	var log []string
	frags := make([]io.Reader, len(sf.frags))
	for i, f := range sf.frags {
		frags[i] = &traceReader{r: bytes.NewReader(f), name: string(rune('0' + i)), log: &log}
	}
	res := runFragmented(context.Background(), t, sf.init, frags, sf.assertion)
	if !res.Has(StatusAssertionBMFFHashMatch) {
		t.Fatalf("expected a match, got %v", codes(res))
	}
	index := func(entry string) int {
		for i, e := range log {
			if e == entry {
				return i
			}
		}
		t.Fatalf("%q missing from %v", entry, log)
		return -1
	}
	for i := 0; i < len(sf.frags)-1; i++ {
		if index("eof "+string(rune('0'+i))) > index("start "+string(rune('1'+i))) {
			t.Errorf("fragment %d was opened before fragment %d was finished: %v", i+1, i, log)
		}
	}
}

// TestValidateNilReader pins the never-panic contract at the entry point: a
// nil reader is reported, not dereferenced.
func TestValidateNilReader(t *testing.T) {
	res := Validate(context.Background(), JPEG, nil)
	if res.Valid || !res.Has(StatusGeneralError) {
		t.Errorf("expected general.error for a nil reader, got %v", codes(res))
	}
	res = ValidateFragmented(context.Background(), nil, nil)
	if res.Valid || !res.Has(StatusGeneralError) {
		t.Errorf("expected general.error for a nil initialization segment, got %v", codes(res))
	}
}
