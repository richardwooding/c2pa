package c2pa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The differential harness runs c2pa-rs (via c2patool) and this library over
// the same files and compares verdicts. The two roll up differently, so the
// comparison happens on a shared three-tier scale:
//
//	trusted — the manifest verified AND the signer chains to a trust anchor.
//	          c2pa-rs: validation_state "Trusted". Us: Valid == true.
//	valid   — well-formed and correctly signed, but not trust-anchored.
//	          c2pa-rs: "Valid" (it does not fail the roll-up on trust).
//	          Us: Valid == false with only trust-class failures.
//	invalid — a structural failure: tampered content, broken signature, missing
//	          hard binding. c2pa-rs: "Invalid". Us: any non-trust failure.
//	none    — no manifest store.
type diffTier string

const (
	tierTrusted diffTier = "trusted"
	tierValid   diffTier = "valid"
	tierInvalid diffTier = "invalid"
	tierNone    diffTier = "none"
)

// trustClassCodes are the failures that separate "valid" from "trusted" rather
// than from "invalid": the credential or its timestamp authority is simply not
// anchored. Everything else is structural.
var trustClassCodes = map[StatusCode]bool{
	StatusSigningCredentialUntrusted: true,
	StatusTimeStampUntrusted:         true,
}

func ourTier(r ValidationResult) diffTier {
	if !r.Info.Present {
		return tierNone
	}
	if r.Valid {
		return tierTrusted
	}
	structural := false
	for _, s := range r.Statuses {
		if s.Severity == SeverityFailure && !trustClassCodes[s.Code] {
			structural = true
			break
		}
	}
	if structural {
		return tierInvalid
	}
	return tierValid
}

// c2patoolView is the slice of c2patool's JSON the comparison reads.
type c2patoolView struct {
	ValidationState string `json:"validation_state"`
	ActiveManifest  string `json:"active_manifest"`
	Manifests       map[string]struct {
		SignatureInfo struct {
			Issuer string `json:"issuer"`
		} `json:"signature_info"`
	} `json:"manifests"`
}

// runC2patool returns the reference implementation's tier, active manifest
// label and signer issuer for a file. c2patool writes JSON to stdout even for
// Invalid files (with a non-zero exit), and "No claim found" for none.
func runC2patool(t *testing.T, path string) (diffTier, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("c2patool", path)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run() // the exit code mirrors the verdict; the output is what matters

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "No claim found") {
		return tierNone, "", ""
	}
	var v c2patoolView
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatalf("c2patool output for %s did not parse: %v\nstderr: %s", path, err, stderr.String())
	}
	tier := tierNone
	switch v.ValidationState {
	case "Trusted":
		tier = tierTrusted
	case "Valid":
		tier = tierValid
	case "Invalid":
		tier = tierInvalid
	default:
		t.Fatalf("c2patool reported unknown validation_state %q for %s", v.ValidationState, path)
	}
	issuer := ""
	if m, ok := v.Manifests[v.ActiveManifest]; ok {
		issuer = m.SignatureInfo.Issuer
	}
	return tier, v.ActiveManifest, issuer
}

// knownDivergence records a justified disagreement with c2pa-rs, keyed by the
// file's corpus-relative path, so it is triaged once and then watched: the test
// fails on any NEW divergence, and reports a recorded one that has healed.
type knownDivergence struct {
	Ours   string `json:"ours"`
	Theirs string `json:"theirs"`
	Reason string `json:"reason"`
}

func loadKnownDivergences(t *testing.T) map[string]knownDivergence {
	t.Helper()
	raw, err := os.ReadFile("conformance_diff_golden.json")
	if os.IsNotExist(err) {
		return map[string]knownDivergence{}
	}
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]knownDivergence
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("conformance_diff_golden.json does not parse: %v", err)
	}
	return m
}

// TestConformanceDifferential compares this library's verdict with c2pa-rs's
// over every corpus asset, on the shared tier scale plus the active manifest
// label. Set C2PA_DIFF_REPORT to also write a markdown parity table.
func TestConformanceDifferential(t *testing.T) {
	if _, err := exec.LookPath("c2patool"); err != nil {
		t.Skip("c2patool not on PATH — install it (brew install c2patool) to run the differential")
	}
	dir := corpusDir(t)
	known := loadKnownDivergences(t)

	var rows []diffRow
	healed := map[string]bool{}
	for k := range known {
		healed[k] = true // assume healed until seen diverging
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		container, ok := corpusContainer(path)
		if !ok {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		r := Validate(context.Background(), container, bytes.NewReader(data))
		ours := ourTier(r)
		theirs, theirLabel, _ := runC2patool(t, path)

		agree := ours == theirs &&
			(theirs == tierNone || r.ActiveManifestLabel == theirLabel)
		rows = append(rows, diffRow{rel, string(theirs), string(ours), r.ActiveManifestLabel, agree})

		if !agree {
			if kd, ok := known[rel]; ok {
				healed[rel] = false
				if kd.Ours != string(ours) || kd.Theirs != string(theirs) {
					t.Errorf("%s: divergence CHANGED — recorded ours=%s theirs=%s, now ours=%s theirs=%s",
						rel, kd.Ours, kd.Theirs, ours, theirs)
				}
			} else {
				t.Errorf("%s: NEW divergence — ours=%s theirs=%s (our label %q, theirs %q)",
					rel, ours, theirs, r.ActiveManifestLabel, theirLabel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for k, h := range healed {
		if h {
			t.Logf("recorded divergence for %s no longer reproduces — remove it from conformance_diff_golden.json", k)
		}
	}

	agree := 0
	for _, r := range rows {
		if r.agree {
			agree++
		}
	}
	t.Logf("differential: %d/%d files agree with c2pa-rs (%d recorded divergences)", agree, len(rows), len(known))

	if out := os.Getenv("C2PA_DIFF_REPORT"); out != "" {
		writeDiffReport(t, out, rows)
	}
}

type diffRow struct {
	rel, theirs, ours, label string
	agree                    bool
}

func writeDiffReport(t *testing.T, out string, rows []diffRow) {
	t.Helper()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].agree != rows[j].agree {
			return !rows[i].agree // disagreements first
		}
		return rows[i].rel < rows[j].rel
	})
	var b strings.Builder
	b.WriteString("# c2pa vs c2pa-rs parity\n\n| file | c2pa-rs | ours | agree |\n|---|---|---|---|\n")
	for _, r := range rows {
		mark := "✅"
		if !r.agree {
			mark = "❌"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.rel, r.theirs, r.ours, mark)
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Errorf("writing report: %v", err)
	}
	t.Logf("parity report written to %s", out)
}
