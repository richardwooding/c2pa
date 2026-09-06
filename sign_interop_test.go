package c2pa

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			path, out := interopSign(t, s, tc.container, tc.in, tc.ext, createdManifest("interop "+tc.name))
			rep := runC2patoolJSON(t, path)
			assertC2patoolValid(t, rep, "assertion.dataHash.match")

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
		{"c2pa-rs signed jpeg", JPEG, ".jpg", fixtureBytes(t, "c2pa_signed.jpg"), false},
		{"c2pa-rs signed png", PNG, ".png", fixtureBytes(t, "c2pa_2x_openai.png"), false},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			first := tc.in
			if tc.signFirst {
				first = signBytes(t, s, tc.container, tc.in, createdManifest("first"))
			}
			firstLabel := Validate(context.Background(), tc.container, bytes.NewReader(first), WithOnlineRevocation(false)).ActiveManifestLabel
			path, _ := interopSign(t, s, tc.container, first, tc.ext, openedManifest("second"))
			rep := runC2patoolJSON(t, path)
			if rep.ValidationState != "Valid" {
				t.Errorf("validation_state = %q; failures %v", rep.ValidationState, rep.ValidationResults.ActiveManifest.Failure)
			}
			if len(rep.Manifests) != 2 {
				t.Errorf("c2patool sees %d manifests, want 2", len(rep.Manifests))
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
