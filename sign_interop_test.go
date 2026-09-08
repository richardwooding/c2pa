package c2pa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The interop gate: everything Sign writes is handed to c2pa-rs's c2patool,
// the reference implementation. Our own validator is label-driven and lenient
// in places c2pa-rs is not — it has no first-action rule, never checks an
// ingredient's hash — so this is the only test that proves the output is
// consumable by anyone else. It skips when c2patool is absent unless
// C2PA_REQUIRE_C2PATOOL is set, which CI sets so the job cannot pass by
// skipping.

func requireC2patool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("c2patool"); err != nil {
		if os.Getenv("C2PA_REQUIRE_C2PATOOL") != "" {
			t.Fatal("C2PA_REQUIRE_C2PATOOL is set but c2patool is not on PATH")
		}
		t.Skip("c2patool not on PATH; install it to run the interop gate")
	}
}

type c2patoolStatus struct {
	Code        string `json:"code"`
	URL         string `json:"url"`
	Explanation string `json:"explanation"`
}

type c2patoolCodes struct {
	Success       []c2patoolStatus `json:"success"`
	Informational []c2patoolStatus `json:"informational"`
	Failure       []c2patoolStatus `json:"failure"`
}

// c2patoolReport is the slice of c2patool's JSON these tests read.
type c2patoolReport struct {
	ValidationState   string `json:"validation_state"`
	ActiveManifest    string `json:"active_manifest"`
	ValidationResults struct {
		ActiveManifest   *c2patoolCodes `json:"activeManifest"`
		IngredientDeltas []struct {
			IngredientAssertionURI string        `json:"ingredientAssertionURI"`
			ValidationDeltas       c2patoolCodes `json:"validationDeltas"`
		} `json:"ingredientDeltas"`
	} `json:"validation_results"`
	Manifests map[string]struct {
		ClaimGenerator     string `json:"claim_generator"` // 1.x claims
		ClaimGeneratorInfo []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"claim_generator_info"` // 2.x claims
		Title         string `json:"title"`
		SignatureInfo struct {
			Issuer string `json:"issuer"`
			Time   string `json:"time"`
		} `json:"signature_info"`
		Ingredients []struct {
			Relationship   string `json:"relationship"`
			ActiveManifest string `json:"active_manifest"`
		} `json:"ingredients"`
	} `json:"manifests"`
}

// runC2patoolJSON runs c2patool and parses its report. The exit code mirrors
// the verdict and is ignored; "No claim found" is the loudest possible interop
// failure for a file we just signed, so it is fatal.
func runC2patoolJSON(t *testing.T, args ...string) c2patoolReport {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("c2patool", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	if strings.Contains(stdout.String()+stderr.String(), "No claim found") {
		t.Fatalf("c2patool found no manifest in a file we signed (%v)\nstderr: %s", args, stderr.String())
	}
	var rep c2patoolReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("c2patool output did not parse: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return rep
}

func (c *c2patoolCodes) codes(list []c2patoolStatus) map[string]bool {
	out := map[string]bool{}
	for _, s := range list {
		out[s.Code] = true
	}
	return out
}

// assertC2patoolValid checks the verdict a private chain earns: Valid, the
// signature and bindings verified, and the ONLY failure that the signer is not
// on c2patool's trust list. c2pa-rs files timeStamp.* under informational, so
// a broken token would hide there; none may appear on an untimestamped file.
func assertC2patoolValid(t *testing.T, rep c2patoolReport, binding string) {
	t.Helper()
	if rep.ValidationState != "Valid" {
		t.Errorf("validation_state = %q, want Valid", rep.ValidationState)
	}
	am := rep.ValidationResults.ActiveManifest
	if am == nil {
		t.Fatalf("no validation_results.activeManifest in %+v", rep)
	}
	success := am.codes(am.Success)
	for _, want := range []string{"claimSignature.validated", "claimSignature.insideValidity", "assertion.hashedURI.match", binding} {
		if !success[want] {
			t.Errorf("success lacks %s: %v", want, am.Success)
		}
	}
	failure := am.codes(am.Failure)
	if len(failure) != 1 || !failure["signingCredential.untrusted"] {
		t.Errorf("failure should be exactly {signingCredential.untrusted}: %v", am.Failure)
	}
	for _, list := range [][]c2patoolStatus{am.Success, am.Informational, am.Failure} {
		for _, s := range list {
			if strings.HasPrefix(s.Code, "timeStamp.") {
				t.Errorf("unexpected %s on an untimestamped file: %s", s.Code, s.Explanation)
			}
		}
	}
	if !strings.HasPrefix(rep.ActiveManifest, "urn:c2pa:") {
		t.Errorf("active_manifest = %q", rep.ActiveManifest)
	}
}

// interopSign signs in into a temp file with the given extension and returns
// the path and the bytes.
func interopSign(t *testing.T, s *Signer, c Container, in []byte, ext string, m Manifest) (string, []byte) {
	t.Helper()
	out := signBytes(t, s, c, in, m)
	path := filepath.Join(t.TempDir(), "signed"+ext)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, out
}

func writeRootPEM(t *testing.T, sc signingChain) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, sc.rootPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSignInterop signs every supported container and asks c2patool.
func TestSignInterop(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := writeRootPEM(t, sc)
	inputs := []struct {
		name      string
		container Container
		ext       string
		in        []byte
	}{
		{"jpeg", JPEG, ".jpg", unsignedJPEG(t)},
		{"png", PNG, ".png", unsignedPNG(t)},
		{"gif", GIF, ".gif", unsignedGIF(t)},
		{"webp", RIFF, ".webp", unsignedWebP()},
		{"wav", RIFF, ".wav", unsignedWAV()},
		{"tiff", TIFF, ".tif", unsignedTIFF(false)},
		{"tiff big-endian", TIFF, ".tif", unsignedTIFF(true)},
		{"mp3", MP3, ".mp3", unsignedMP3()},
		{"svg", SVG, ".svg", unsignedSVG()},
		{"mp4", BMFF, ".mp4", fixtureBytes(t, "video_no_manifest.mp4")},
		{"mp4 minimal stco", BMFF, ".mp4", minimalMP4(false)},
		{"mp4 minimal co64", BMFF, ".mp4", minimalMP4(true)},
		{"mp4 flat fragmented", BMFF, ".mp4", unsignedFlatFragmented(t, 3, flatOpts{sidxVersion: -1})},
		{"mp4 flat fragmented with furniture", BMFF, ".mp4", unsignedFlatFragmented(t, 4, flatOpts{sidxVersion: 0, tfhdBase: true, styp: true, mfra: true, stco: true})},
		{"avif extents", BMFF, ".avif", minimalAVIF(false)},
		{"avif base offset", BMFF, ".avif", minimalAVIF(true)},
		{"pdf xref table", PDF, ".pdf", unsignedPDF(false)},
		{"pdf xref stream", PDF, ".pdf", unsignedPDF(true)},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path, out := interopSign(t, s, tc.container, tc.in, tc.ext, createdManifest("interop "+tc.name))
			rep := runC2patoolJSON(t, path)
			binding := "assertion.dataHash.match"
			if tc.container == BMFF {
				binding = "assertion.bmffHash.match"
			}
			assertC2patoolValid(t, rep, binding)

			ours := Validate(context.Background(), tc.container, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
			if rep.ActiveManifest != ours.ActiveManifestLabel {
				t.Errorf("active manifest: c2patool %q, ours %q", rep.ActiveManifest, ours.ActiveManifestLabel)
			}
			m := rep.Manifests[rep.ActiveManifest]
			generator := m.ClaimGenerator
			if len(m.ClaimGeneratorInfo) > 0 {
				generator = m.ClaimGeneratorInfo[0].Name + "/" + m.ClaimGeneratorInfo[0].Version
			}
			if m.Title != "interop "+tc.name || generator != "c2pa-go-interop/0.1" || m.SignatureInfo.Issuer != "richardwooding/c2pa tests" {
				t.Errorf("manifest as c2patool read it: title %q generator %q issuer %q", m.Title, generator, m.SignatureInfo.Issuer)
			}

			trusted := runC2patoolJSON(t, path, "trust", "--trust_anchors", rootPEM)
			if trusted.ValidationState != "Trusted" {
				t.Errorf("with our root as an anchor: %q, want Trusted; failures %v", trusted.ValidationState,
					trusted.ValidationResults.ActiveManifest.Failure)
			}
			if !ours.Valid {
				t.Errorf("our own verdict on the same bytes: %v", codes(ours))
			}
		})
	}
}

// TestSignInteropResign chains twice and checks c2patool sees the parentOf
// ingredient with no failure deltas — the ingredient shape (activeManifest,
// claimSignature, validationResults, the opened action's parameters) is what
// c2pa-rs is strict about and our validator is not.
func TestSignInteropResign(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := writeRootPEM(t, sc)
	inputs := []struct {
		name      string
		container Container
		ext       string
		in        []byte
		signFirst bool
	}{
		{"jpeg", JPEG, ".jpg", unsignedJPEG(t), true},
		{"png", PNG, ".png", unsignedPNG(t), true},
		{"gif", GIF, ".gif", unsignedGIF(t), true},
		{"webp", RIFF, ".webp", unsignedWebP(), true},
		{"tiff", TIFF, ".tif", unsignedTIFF(false), true},
		{"mp3", MP3, ".mp3", unsignedMP3(), true},
		{"svg", SVG, ".svg", unsignedSVG(), true},
		{"mp4", BMFF, ".mp4", fixtureBytes(t, "video_no_manifest.mp4"), true},
		{"pdf", PDF, ".pdf", unsignedPDF(false), true},
		{"c2pa-rs signed jpeg", JPEG, ".jpg", fixtureBytes(t, "c2pa_signed.jpg"), false},
		{"ChatGPT signed pdf", PDF, ".pdf", fixtureBytes(t, "c2pa_chatgpt.pdf"), false},
		{"c2pa-rs signed mp4", BMFF, ".mp4", fixtureBytes(t, "c2pa_signed_video.mp4"), false},
		{"c2pa-rs signed png", PNG, ".png", fixtureBytes(t, "c2pa_2x_openai.png"), false},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.in
			if tc.signFirst {
				first = signBytes(t, s, tc.container, tc.in, createdManifest("first"))
			}
			firstLabel := Validate(context.Background(), tc.container, bytes.NewReader(first), WithOnlineRevocation(false)).ActiveManifestLabel
			prior := len(parseStore(context.Background(), extractJUMBF(context.Background(), tc.container, first)).manifests)
			path, _ := interopSign(t, s, tc.container, first, tc.ext, openedManifest("second"))
			rep := runC2patoolJSON(t, path)
			if rep.ValidationState != "Valid" {
				t.Errorf("validation_state = %q; failures %v", rep.ValidationState, rep.ValidationResults.ActiveManifest.Failure)
			}
			if len(rep.Manifests) != prior+1 {
				t.Errorf("c2patool sees %d manifests, want %d (every prior manifest carried plus ours)", len(rep.Manifests), prior+1)
			}
			active := rep.Manifests[rep.ActiveManifest]
			if len(active.Ingredients) != 1 || active.Ingredients[0].Relationship != "parentOf" || active.Ingredients[0].ActiveManifest != firstLabel {
				t.Errorf("ingredients as c2patool read them: %+v (want parentOf %s)", active.Ingredients, firstLabel)
			}
			for _, d := range rep.ValidationResults.IngredientDeltas {
				for _, f := range d.ValidationDeltas.Failure {
					if f.Code != "signingCredential.untrusted" {
						t.Errorf("ingredient delta failure %s: %s", f.Code, f.Explanation)
					}
				}
			}
			if am := rep.ValidationResults.ActiveManifest; am != nil {
				for _, f := range am.Failure {
					if f.Code != "signingCredential.untrusted" {
						t.Errorf("active manifest failure %s: %s", f.Code, f.Explanation)
					}
				}
			}
			if tc.signFirst {
				trusted := runC2patoolJSON(t, path, "trust", "--trust_anchors", rootPEM)
				if trusted.ValidationState != "Trusted" {
					t.Errorf("with our root: %q; failures %v", trusted.ValidationState, trusted.ValidationResults.ActiveManifest.Failure)
				}
			}
		})
	}
}

// TestSignInteropTimestamp: c2patool sees the sigTst2 token. Without the TSA
// anchored it is informational (timeStamp.untrusted), never a malformation or
// a mismatch; with both anchors supplied through a settings file the file is
// Trusted with the timestamp validated and trusted, and the time c2patool
// reports agrees with ours.
func TestSignInteropTimestamp(t *testing.T) {
	requireC2patool(t)
	ta := liveTSA(t)
	srv := newTSAServer(t, ta, nil)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"), WithTimestampAuthority(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	path, out := interopSign(t, s, JPEG, unsignedJPEG(t), ".jpg", createdManifest("stamped"))

	rep := runC2patoolJSON(t, path)
	if rep.ValidationState != "Valid" {
		t.Errorf("validation_state = %q; failures %v", rep.ValidationState, rep.ValidationResults.ActiveManifest.Failure)
	}
	am := rep.ValidationResults.ActiveManifest
	if am == nil {
		t.Fatal("no activeManifest results")
	}
	if !am.codes(am.Informational)["timeStamp.untrusted"] {
		t.Errorf("without the TSA anchor c2patool should report timeStamp.untrusted as informational: %v", am.Informational)
	}
	for _, list := range [][]c2patoolStatus{am.Success, am.Informational, am.Failure} {
		for _, st := range list {
			if st.Code == "timeStamp.mismatch" || st.Code == "timeStamp.malformed" || st.Code == "timeStamp.outsideValidity" {
				t.Errorf("token defect reported: %s: %s", st.Code, st.Explanation)
			}
		}
	}

	// Both anchors through a settings file. c2patool v0.27.16 keeps ONE trust
	// list — `trust.trust_anchors` anchors manifest signers AND timestamp
	// authorities — so the two roots are concatenated; there is no TSA-specific
	// key (probed: a `trust_kind = "tsa"` table is silently ignored).
	settings := "[verify]\nverify_timestamp_trust = true\n\n[trust]\ntrust_anchors = \"\"\"\n" +
		string(sc.rootPEM) + string(pemCert(t, ta.root)) + "\"\"\"\n"
	settingsPath := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(settingsPath, []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	trusted := runC2patoolJSON(t, "--settings", settingsPath, path)
	if trusted.ValidationState != "Trusted" {
		t.Errorf("with both anchors: %q; failures %v informational %v", trusted.ValidationState,
			trusted.ValidationResults.ActiveManifest.Failure, trusted.ValidationResults.ActiveManifest.Informational)
	}
	tam := trusted.ValidationResults.ActiveManifest
	if tam != nil && (!tam.codes(tam.Success)["timeStamp.validated"] || !tam.codes(tam.Success)["timeStamp.trusted"]) {
		t.Errorf("timestamp not validated+trusted: %v", tam.Success)
	}
	ours := Read(context.Background(), JPEG, bytes.NewReader(out))
	if theirs := trusted.Manifests[trusted.ActiveManifest].SignatureInfo.Time; theirs != "" {
		if tt, err := time.Parse(time.RFC3339, theirs); err != nil || tt.Sub(ours.SignedAt).Abs() > time.Minute {
			t.Errorf("signature_info.time %q vs our SignedAt %v", theirs, ours.SignedAt)
		}
	}
}

func pemCert(t *testing.T, c *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// TestSignInteropMessageSigner: a key that signs whole messages (the browser
// key shape) produces a file c2patool reads exactly like any other.
func TestSignInteropMessageSigner(t *testing.T) {
	requireC2patool(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sc := newSigningChainFor(t, key)
	s, err := NewSigner(&messageOnlySigner{key: key}, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"))
	if err != nil {
		t.Fatal(err)
	}
	path, _ := interopSign(t, s, JPEG, unsignedJPEG(t), ".jpg", createdManifest("message signer"))
	assertC2patoolValid(t, runC2patoolJSON(t, path), "assertion.dataHash.match")
	if trusted := runC2patoolJSON(t, path, "trust", "--trust_anchors", writeRootPEM(t, sc)); trusted.ValidationState != "Trusted" {
		t.Errorf("with our root as an anchor: %q, want Trusted", trusted.ValidationState)
	}
}

// --- fragmented BMFF ---------------------------------------------------------

// runC2patoolFragment runs `c2patool [extra…] <init> fragment --fragments_glob
// <glob>` and parses the report. c2patool prints a "Verifying manifest:" line
// before the JSON, and on ANY failing status — a tampered fragment, an
// untrusted signer — prints no JSON at all and exits 0 with the status on
// stderr; so a nil report plus stderr is the failure shape, not an error.
func runC2patoolFragment(t *testing.T, initPath, glob string, extra ...string) (*c2patoolReport, string) {
	t.Helper()
	args := append(append([]string{}, extra...), initPath, "fragment", "--fragments_glob", glob)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("c2patool", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	out := stdout.String()
	i := strings.Index(out, "{")
	if i < 0 {
		return nil, stderr.String() + out
	}
	var rep c2patoolReport
	if err := json.Unmarshal([]byte(out[i:]), &rep); err != nil {
		t.Fatalf("c2patool fragment output did not parse: %v\nstdout: %s\nstderr: %s", err, out, stderr.String())
	}
	return &rep, stderr.String()
}

// writeFragmentedSet writes init + frags under dir/bunny with the fixture's
// names, as c2patool's basename glob expects, and returns the init path.
func writeFragmentedSet(t *testing.T, dir string, init []byte, frags [][]byte, names []string) string {
	t.Helper()
	sub := filepath.Join(dir, "bunny")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	initPath := filepath.Join(sub, "BigBuckBunny_2s_init.mp4")
	if err := os.WriteFile(initPath, init, 0o644); err != nil {
		t.Fatal(err)
	}
	for i, f := range frags {
		if err := os.WriteFile(filepath.Join(sub, names[i]), f, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return initPath
}

// trustSettings writes the c2patool settings TOML that anchors our test root.
func trustSettings(t *testing.T, sc signingChain) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(p, []byte("[trust]\ntrust_anchors = \"\"\"\n"+string(sc.rootPEM)+"\"\"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// readFragmentedSet reads a signed set back from dir/bunny.
func readFragmentedSet(t *testing.T, dir string, names []string) ([]byte, [][]byte) {
	t.Helper()
	init, err := os.ReadFile(filepath.Join(dir, "bunny", "BigBuckBunny_2s_init.mp4"))
	if err != nil {
		t.Fatal(err)
	}
	frags := make([][]byte, len(names))
	for i, n := range names {
		if frags[i], err = os.ReadFile(filepath.Join(dir, "bunny", n)); err != nil {
			t.Fatal(err)
		}
	}
	return init, frags
}

// TestSignInteropFragmented: our fragmented set is what c2patool's fragment
// verifier accepts — Trusted with our root anchored, assertion.bmffHash.match
// — and a tampered fragment is what it refuses.
func TestSignInteropFragmented(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"))
	if err != nil {
		t.Fatal(err)
	}
	init, frags, names := bunnySet(t)
	sInit, sFrags := signFragmentedSet(t, s, init, frags, createdManifest("Big Buck Bunny"))
	dir := t.TempDir()
	initPath := writeFragmentedSet(t, dir, sInit, sFrags, names)
	settings := trustSettings(t, sc)

	rep, stderr := runC2patoolFragment(t, initPath, "BigBuckBunny_2s*.m4s", "--settings", settings)
	if rep == nil {
		t.Fatalf("c2patool refused our fragmented set:\n%s", stderr)
	}
	if rep.ValidationState != "Trusted" {
		t.Errorf("validation_state = %q, want Trusted; failures %v", rep.ValidationState, rep.ValidationResults.ActiveManifest.Failure)
	}
	am := rep.ValidationResults.ActiveManifest
	if am == nil || !am.codes(am.Success)["assertion.bmffHash.match"] || !am.codes(am.Success)["claimSignature.validated"] {
		t.Errorf("success codes: %v", am)
	}
	if rep.Manifests[rep.ActiveManifest].Title != "Big Buck Bunny" {
		t.Errorf("title: %q", rep.Manifests[rep.ActiveManifest].Title)
	}
	// One fragment only: a one-leaf tree stores its leaf and the box has no proof.
	one := t.TempDir()
	oInit, oFrags := signFragmentedSet(t, s, init, frags[:1], createdManifest("one"))
	rep, stderr = runC2patoolFragment(t, writeFragmentedSet(t, one, oInit, oFrags, names[:1]), names[0], "--settings", settings)
	if rep == nil || rep.ValidationState != "Trusted" {
		t.Errorf("single-fragment set: %v\n%s", rep, stderr)
	}
	// Tamper one fragment on disk: no JSON, the status on stderr.
	bad := append([]byte(nil), sFrags[3]...)
	bad[len(bad)-1] ^= 0xFF
	if err := os.WriteFile(filepath.Join(dir, "bunny", names[3]), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, stderr = runC2patoolFragment(t, initPath, "BigBuckBunny_2s*.m4s", "--settings", settings)
	if rep != nil || !strings.Contains(stderr, "Error validating segments") || !strings.Contains(stderr, "bmffHash") {
		t.Errorf("tampered fragment: report %v\nstderr: %s", rep, stderr)
	}
}

// c2patoolSignFragmented has c2patool sign the bunny set with our test chain
// and returns the signed set. c2patool writes to OUT/<init's dir name>/ and
// refuses to overwrite, so the output dir is fresh.
func c2patoolSignFragmented(t *testing.T, sc signingChain, init []byte, frags [][]byte, names []string, title string) ([]byte, [][]byte) {
	t.Helper()
	work := t.TempDir()
	initPath := writeFragmentedSet(t, work, init, frags, names)
	keyDER, err := x509.MarshalPKCS8PrivateKey(sc.key)
	if err != nil {
		t.Fatal(err)
	}
	certs := string(pemCert(t, sc.chain[0])) + string(pemCert(t, sc.chain[1]))
	if err := os.WriteFile(filepath.Join(work, "es256_private.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "es256_certs.pem"), []byte(certs), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"alg":"es256","private_key":"es256_private.key","sign_cert":"es256_certs.pem",` +
		`"claim_generator_info":[{"name":"c2patool-interop","version":"0.1"}],"title":` + strconv.Quote(title) + `,` +
		`"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"` + DigitalSourceTypeDigitalCapture + `"}]}}]}`
	manifestPath := filepath.Join(work, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "signed")
	cmd := exec.Command("c2patool", "--settings", trustSettings(t, sc), "-m", manifestPath, "-o", out, initPath, "fragment", "--fragments_glob", "BigBuckBunny_2s*.m4s")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("c2patool fragment signing: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return readFragmentedSet(t, out, names)
}

// TestSignInteropFragmentedReverse: what c2patool signs, ValidateFragmented
// accepts in full — and Validate on the init alone points at ValidateFragmented.
func TestSignInteropFragmentedReverse(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	init, frags, names := bunnySet(t)
	cInit, cFrags := c2patoolSignFragmented(t, sc, init, frags, names, "signed by c2patool")
	res := ValidateFragmented(context.Background(), bytes.NewReader(cInit), readersOf(cFrags...), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	expectFragmentedMatch(t, res, 11)
	if res.Info.Title != "signed by c2patool" || res.VerifiedSigner() == "" {
		t.Errorf("title %q signer %q", res.Info.Title, res.VerifiedSigner())
	}
	alone := Validate(context.Background(), BMFF, bytes.NewReader(cInit), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if alone.Has(StatusAssertionBMFFHashMatch) || !strings.Contains(statusExplanation(alone, StatusUnsupported), "ValidateFragmented") {
		t.Errorf("the init alone: %v", codes(alone))
	}
	// c2pa-rs leaves sidx.first_offset stale, pointing at its merkle box.
	f := cFrags[0]
	first, end := sidxFirstOffset(f, topBox(f, "sidx"))
	if uuid := topBox(f, "uuid"); end+int(first) != uuid.start {
		t.Logf("c2patool output: sidx points at %d, merkle box at %d, moof at %d", end+int(first), uuid.start, topBox(f, "moof").start)
	}
}

// TestSignInteropFragmentedResign: a c2patool-signed set re-signed here chains
// c2patool's manifest as the parentOf ingredient, replaces its merkle boxes,
// repairs its stale sidx, and is accepted by both verifiers.
func TestSignInteropFragmentedResign(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"))
	if err != nil {
		t.Fatal(err)
	}
	init, frags, names := bunnySet(t)
	cInit, cFrags := c2patoolSignFragmented(t, sc, init, frags, names, "first, by c2patool")
	rInit, rFrags := signFragmentedSet(t, s, cInit, cFrags, openedManifest("second, by c2pa"))

	res := ValidateFragmented(context.Background(), bytes.NewReader(rInit), readersOf(rFrags...), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	expectFragmentedMatch(t, res, 11)
	if !res.Has(StatusIngredientManifestValidated) {
		t.Errorf("prior manifest not chained: %v", codes(res))
	}
	for i, f := range rFrags {
		if c2paBoxCount(f) != 1 {
			t.Errorf("fragment %d: %d C2PA boxes, want 1", i, c2paBoxCount(f))
		}
		first, end := sidxFirstOffset(f, topBox(f, "sidx"))
		if moof := topBox(f, "moof"); end+int(first) != moof.start {
			t.Errorf("fragment %d: sidx still stale (points at %d, moof at %d)", i, end+int(first), moof.start)
		}
	}
	dir := t.TempDir()
	rep, stderr := runC2patoolFragment(t, writeFragmentedSet(t, dir, rInit, rFrags, names), "BigBuckBunny_2s*.m4s", "--settings", trustSettings(t, sc))
	if rep == nil {
		t.Fatalf("c2patool refused the re-signed set:\n%s", stderr)
	}
	if rep.ValidationState != "Trusted" || len(rep.Manifests) != 2 {
		t.Errorf("state %q, %d manifests", rep.ValidationState, len(rep.Manifests))
	}
	active := rep.Manifests[rep.ActiveManifest]
	if active.Title != "second, by c2pa" || len(active.Ingredients) != 1 || active.Ingredients[0].Relationship != "parentOf" {
		t.Errorf("active manifest: %+v", active)
	}
}

// identityURLSuffix is the tail of the identity assertion's URL in c2patool's
// report, "self#jumbf=/c2pa/<manifest>/c2pa.assertions/cawg.identity".
const identityURLSuffix = "/c2pa.assertions/cawg.identity"

// identitySettings writes a c2patool settings TOML anchoring the claim root
// under [trust] and the identity root under [cawg_trust].
func identitySettings(t *testing.T, sc, idChain signingChain) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity_settings.toml")
	toml := "[trust]\ntrust_anchors = \"\"\"\n" + string(sc.rootPEM) + "\"\"\"\n\n" +
		"[cawg_trust]\ntrust_anchors = \"\"\"\n" + string(idChain.rootPEM) + "\"\"\"\n"
	if err := os.WriteFile(p, []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// assertC2patoolIdentity checks what c2patool 0.27.16 says about a CAWG X.509
// identity it accepts: cawg.identity.well-formed in success, the identity's
// hashed_uri matched, and no cawg.identity.* failure. Its trust verdict on the
// identity is always signingCredential.untrusted at the identity URL — that
// version applies no [cawg_trust] anchors — which assertC2patoolValid already
// tolerates (it counts codes, not entries); here every untrusted entry must be
// the identity's, since the claim root IS anchored.
func assertC2patoolIdentity(t *testing.T, rep c2patoolReport) {
	t.Helper()
	am := rep.ValidationResults.ActiveManifest
	if am == nil {
		t.Fatal("no activeManifest results")
	}
	var wellFormed, hashed bool
	for _, s := range am.Success {
		if s.Code == "cawg.identity.well-formed" && strings.HasSuffix(s.URL, identityURLSuffix) {
			wellFormed = true
		}
		if s.Code == "assertion.hashedURI.match" && strings.HasSuffix(s.URL, identityURLSuffix) {
			hashed = true
		}
	}
	if !wellFormed || !hashed {
		t.Errorf("c2patool did not accept the identity (well-formed %v, hashed %v): %v", wellFormed, hashed, am.Success)
	}
	for _, s := range am.Failure {
		if strings.HasPrefix(s.Code, "cawg.") {
			t.Errorf("c2patool identity failure: %s %s", s.Code, s.Explanation)
		}
		if s.Code == "signingCredential.untrusted" && !strings.HasSuffix(s.URL, identityURLSuffix) {
			t.Errorf("the claim signer should be trusted; untrusted at %s", s.URL)
		}
	}
}

// TestSignInteropIdentity: a CAWG identity assertion this library writes is one
// c2patool verifies — the signer_payload it re-serialises matches what we
// signed — with the roles and references intact in its report.
func TestSignInteropIdentity(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	idChain := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"), WithIdentitySigner(idChain.key, idChain.chain))
	if err != nil {
		t.Fatal(err)
	}
	m := createdManifest("interop identity")
	m.Identity = IdentityInfo{Roles: []string{RoleCreator, RolePublisher}, References: []string{"c2pa.actions.v2"}}
	for _, tc := range []struct {
		name      string
		container Container
		ext       string
		in        []byte
	}{
		{"jpeg", JPEG, ".jpg", unsignedJPEG(t)},
		{"png", PNG, ".png", unsignedPNG(t)},
		{"mp4", BMFF, ".mp4", minimalMP4(false)},
		{"pdf", PDF, ".pdf", unsignedPDF(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, out := interopSign(t, s, tc.container, tc.in, tc.ext, m)
			rep := runC2patoolJSON(t, "--settings", identitySettings(t, sc, idChain), path)
			binding := "assertion.dataHash.match"
			if tc.container == BMFF {
				binding = "assertion.bmffHash.match"
			}
			assertC2patoolValid(t, rep, binding)
			assertC2patoolIdentity(t, rep)

			// c2patool decodes the identity into a report: roles, references and
			// the identity leaf's issuer.
			raw := runC2patoolRaw(t, "--settings", identitySettings(t, sc, idChain), path)
			for _, want := range []string{`"cawg.identity"`, `"cawg.creator"`, `"cawg.publisher"`, `self#jumbf=c2pa.assertions/c2pa.actions.v2`, `"cawg.x509.cose"`} {
				if !strings.Contains(raw, want) {
					t.Errorf("c2patool report lacks %s", want)
				}
			}
			// And we agree with ourselves.
			res := Validate(context.Background(), tc.container, bytes.NewReader(out), WithSigningTrust(sc.roots), WithIdentityTrust(idChain.roots), WithOnlineRevocation(false))
			if !res.Valid || len(res.Identities) != 1 || !res.Identities[0].Trusted {
				t.Errorf("our verifier: valid=%v %+v %v", res.Valid, res.Identities, codes(res))
			}
		})
	}
}

// runC2patoolRaw returns c2patool's stdout as text.
func runC2patoolRaw(t *testing.T, args ...string) string {
	t.Helper()
	var stdout bytes.Buffer
	cmd := exec.Command("c2patool", args...)
	cmd.Stdout = &stdout
	_ = cmd.Run()
	return stdout.String()
}

// c2patoolSignIdentity signs a JPEG with c2patool, the claim from the manifest
// JSON and a CAWG X.509 identity from [cawg_x509_signer.local] in the settings.
func c2patoolSignIdentity(t *testing.T, sc, idChain signingChain, in []byte, roles, refs []string) []byte {
	t.Helper()
	work := t.TempDir()
	writeKeyAndCerts := func(prefix string, c signingChain) {
		keyDER, err := x509.MarshalPKCS8PrivateKey(c.key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, prefix+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			t.Fatal(err)
		}
		certs := string(pemCert(t, c.chain[0])) + string(pemCert(t, c.chain[1]))
		if err := os.WriteFile(filepath.Join(work, prefix+".pem"), []byte(certs), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeKeyAndCerts("claim", sc)
	writeKeyAndCerts("ident", idChain)
	inPath := filepath.Join(work, "in.jpg")
	if err := os.WriteFile(inPath, in, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"alg":"es256","private_key":"claim.key","sign_cert":"claim.pem",` +
		`"claim_generator_info":[{"name":"c2patool-interop","version":"0.1"}],"title":"c2patool identity",` +
		`"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"` + DigitalSourceTypeDigitalCapture + `"}]}}]}`
	if err := os.WriteFile(filepath.Join(work, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	identKey, err := os.ReadFile(filepath.Join(work, "ident.key"))
	if err != nil {
		t.Fatal(err)
	}
	identCerts, err := os.ReadFile(filepath.Join(work, "ident.pem"))
	if err != nil {
		t.Fatal(err)
	}
	quote := func(list []string) string {
		q := make([]string, len(list))
		for i, s := range list {
			q[i] = strconv.Quote(s)
		}
		return "[" + strings.Join(q, ", ") + "]"
	}
	settings := "[cawg_x509_signer.local]\nalg = \"es256\"\nsign_cert = \"\"\"\n" + string(identCerts) + "\"\"\"\nprivate_key = \"\"\"\n" + string(identKey) + "\"\"\"\n" +
		"referenced_assertions = " + quote(refs) + "\nroles = " + quote(roles) + "\n"
	settingsPath := filepath.Join(work, "sign_settings.toml")
	if err := os.WriteFile(settingsPath, []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(work, "out.jpg")
	cmd := exec.Command("c2patool", "--settings", settingsPath, "-m", filepath.Join(work, "manifest.json"), "-o", outPath, inPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("c2patool identity signing: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSignInteropIdentityReverse: an identity c2patool writes is one this
// library verifies — trusted once its root is anchored, with the roles and
// references it was given, listed under gathered_assertions.
func TestSignInteropIdentityReverse(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	idChain := newSigningChain(t)
	out := c2patoolSignIdentity(t, sc, idChain, unsignedJPEG(t), []string{RoleCreator}, []string{"c2pa.actions.v2"})
	ctx := context.Background()
	res := Validate(ctx, JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithIdentityTrust(idChain.roots), WithOnlineRevocation(false))
	if !res.Valid {
		t.Fatalf("%v: %v", codes(res), res.FirstFailure())
	}
	if len(res.Identities) != 1 {
		t.Fatalf("identities = %+v", res.Identities)
	}
	id := res.Identities[0]
	if !id.Trusted || id.Name() != "c2pa test signer" || !equalStrings(id.Roles, []string{RoleCreator}) {
		t.Errorf("identity = %+v name %q", id, id.Name())
	}
	sort.Strings(id.Referenced)
	if !equalStrings(id.Referenced, []string{"c2pa.actions.v2", "c2pa.hash.data"}) {
		t.Errorf("referenced = %v", id.Referenced)
	}
	store, err := ExtractStore(ctx, JPEG, bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	m := parseStore(ctx, store).active()
	gathered, _ := m.claim["gathered_assertions"].([]any)
	found := false
	for _, g := range gathered {
		if gm, _ := g.(map[string]any); gm["url"] == assertionURL(identityLabel) {
			found = true
		}
	}
	if !found {
		t.Errorf("c2patool's identity is not a gathered assertion: %v", m.claim["gathered_assertions"])
	}
	// Without anchors: well-formed, unproven — and c2patool's own output is
	// judged by the same rule as ours.
	res = Validate(ctx, JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Valid || res.Identities[0].Trusted || !res.Identities[0].Valid {
		t.Errorf("unanchored: valid=%v %+v", res.Valid, res.Identities)
	}
}

// TestSignInteropIdentityFragmented: the identity rides along in a DASH set.
// c2patool's fragment mode prints no report when any status fails, and its
// 0.27.16 verdict on ANY identity's credential is signingCredential.untrusted,
// so what it can show here is that it reached the identity's trust check —
// the failing status it names is the identity's, not the claim's or a
// cawg.identity.* one. Our own verifier proves the rest.
func TestSignInteropIdentityFragmented(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	idChain := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"), WithIdentitySigner(idChain.key, idChain.chain))
	if err != nil {
		t.Fatal(err)
	}
	init, frags, names := bunnySet(t)
	m := createdManifest("fragmented identity")
	m.Identity = IdentityInfo{Roles: []string{RoleProducer}}
	outInit, outFrags := signFragmentedSet(t, s, init, frags, m)
	dir := t.TempDir()
	initPath := writeFragmentedSet(t, dir, outInit, outFrags, names)
	rep, stderr := runC2patoolFragment(t, initPath, "BigBuckBunny_2s*.m4s", "--settings", identitySettings(t, sc, idChain))
	if rep != nil {
		// A c2patool that applies [cawg_trust] anchors would get here.
		assertC2patoolValid(t, *rep, "assertion.bmffHash.match")
		assertC2patoolIdentity(t, *rep)
	} else if !strings.Contains(stderr, "signingCredential.untrusted") || !strings.Contains(stderr, identityURLSuffix) || strings.Contains(stderr, "cawg.identity.") {
		t.Errorf("c2patool's failing status should be the identity's trust quirk, got: %s", stderr)
	}
	res := ValidateFragmented(context.Background(), bytes.NewReader(outInit), readersOf(outFrags...),
		WithSigningTrust(sc.roots), WithIdentityTrust(idChain.roots), WithOnlineRevocation(false))
	if !res.Valid || !res.Has(StatusAssertionBMFFHashMatch) || len(res.Identities) != 1 || !res.Identities[0].Trusted {
		t.Errorf("our verifier: valid=%v %+v %v", res.Valid, res.Identities, codes(res))
	}
}

// TestSignInteropSoftBinding is the acceptance test for what we write: a soft
// binding must not change c2patool's verdict, and c2patool must report it back.
//
// Probed before this was written, and worth recording: c2patool 0.27.16 READS a
// soft binding and validates nothing about it — there is no soft-binding status
// code on its side — so the assertion is expected to be inert. The point of the
// test is that "inert" stays true: a byte string it could not parse, or a pad it
// rejected, would surface as a changed verdict.
func TestSignInteropSoftBinding(t *testing.T) {
	requireC2patool(t)
	sc := newSigningChain(t)
	s, err := NewSigner(sc.key, sc.chain, WithClaimGenerator("c2pa-go-interop", "0.1"))
	if err != nil {
		t.Fatal(err)
	}
	plain := createdManifest("interop soft binding")
	bound := createdManifest("interop soft binding")
	bound.SoftBindings = []SoftBindingInfo{{
		Algorithm: "io.iscc.v0",
		Name:      "whole image",
		Params:    []byte{0xa1, 0x61, 0x6b, 0x01},
		Blocks: []SoftBindingBlockInfo{
			{Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
			{Value: []byte{9, 9}, Timespan: &SoftBindingTimespan{Start: 0, End: 1000}},
		},
	}}

	// The control and the subject differ only by the soft binding.
	controlPath, _ := interopSign(t, s, JPEG, unsignedJPEG(t), ".jpg", plain)
	path, out := interopSign(t, s, JPEG, unsignedJPEG(t), ".jpg", bound)

	control := runC2patoolJSON(t, controlPath)
	rep := runC2patoolJSON(t, path)
	assertC2patoolValid(t, rep, "assertion.dataHash.match")

	// Same verdict as without it: the assertion is inert to c2patool, which is
	// the honest outcome for something nobody has agreed how to check.
	if rep.ValidationState != control.ValidationState {
		t.Errorf("validation_state changed from %q to %q by adding a soft binding",
			control.ValidationState, rep.ValidationState)
	}
	if got, want := len(rep.ValidationResults.ActiveManifest.Failure), len(control.ValidationResults.ActiveManifest.Failure); got != want {
		t.Errorf("failure count changed from %d to %d: %v",
			want, got, rep.ValidationResults.ActiveManifest.Failure)
	}
	for _, s := range rep.ValidationResults.ActiveManifest.Informational {
		if strings.Contains(s.Code, "soft") {
			t.Errorf("c2patool now judges soft bindings (%s: %s) — revisit whether we should too", s.Code, s.Explanation)
		}
	}

	// It reports the assertion, with the value as base64 of the byte string —
	// which is the proof that "value" and "alg-params" travelled as bstr.
	raw := runC2patoolRaw(t, "--settings", trustSettings(t, sc), path)
	for _, want := range []string{`"c2pa.soft-binding"`, `"io.iscc.v0"`, `"whole image"`, `"AQIDBAUGBwg="`, `"oWFrAQ=="`} {
		if !strings.Contains(raw, want) {
			t.Errorf("c2patool report lacks %s", want)
		}
	}

	// And we agree with ourselves.
	res := Validate(context.Background(), JPEG, bytes.NewReader(out), WithSigningTrust(sc.roots), WithOnlineRevocation(false))
	if !res.Valid || len(res.SoftBindings) != 1 || !res.SoftBindings[0].WellFormed {
		t.Errorf("our verifier: valid=%v %+v %v", res.Valid, res.SoftBindings, codes(res))
	}
}
