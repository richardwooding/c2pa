package c2pa

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vendor corpus is a LOCAL directory of files freshly generated from the
// AI vendors that emit Content Credentials (ChatGPT/DALL-E images and PDFs,
// Adobe Firefly, Microsoft Designer/Bing, Google Imagen, …), organised as
// <dir>/<vendor>/<file>. It is never committed anywhere: the files carry
// vendor licensing and possibly personal context.
//
// The harness is a snapshot test. The first run writes <file>.golden.json next
// to each asset; later runs diff against it, so when the corpus is refreshed a
// vendor-format drift — a new claim shape, a new TSA, a new intermediate, the
// kind of change that historically broke sigTst2 and the text-key x5chain —
// shows up as a failing diff the same day.
//
// A file whose name contains "laundered" is a NEGATIVE: a re-saved or
// screenshotted copy that must carry no credentials at all.

// vendorSnapshot is what a golden records — the stable, user-facing view.
type vendorSnapshot struct {
	Present        bool   `json:"present"`
	Attribution    string `json:"attribution,omitempty"`
	ClaimGenerator string `json:"claim_generator,omitempty"`
	SoftwareAgent  string `json:"software_agent,omitempty"`
	AIGenerated    bool   `json:"ai_generated"`
	SignedBy       string `json:"signed_by,omitempty"`
	VerifiedSigner string `json:"verified_signer,omitempty"`
	Valid          bool   `json:"valid"`
	FirstFailure   string `json:"first_failure,omitempty"`
	Stores         int    `json:"stores"`
}

func vendorContainer(path string) (Container, bool) {
	return corpusContainer(path)
}

func TestConformanceVendorCorpus(t *testing.T) {
	dir := os.Getenv("C2PA_VENDOR_CORPUS")
	if dir == "" {
		t.Skip("set C2PA_VENDOR_CORPUS to a local vendor-file directory to run (see the comment in this file)")
	}

	var files, snapped, diffed int
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, ".golden.json") {
			return err
		}
		container, ok := vendorContainer(path)
		if !ok {
			return nil
		}
		files++
		rel, _ := filepath.Rel(dir, path)
		t.Run(filepath.ToSlash(rel), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), corpusFileDeadline)
			defer cancel()

			info := Read(ctx, container, bytes.NewReader(data))
			r := Validate(ctx, container, bytes.NewReader(data))
			all := ReadAll(ctx, container, bytes.NewReader(data))

			got := vendorSnapshot{
				Present:        info.Present,
				Attribution:    string(info.Attribution),
				ClaimGenerator: info.ClaimGenerator,
				SoftwareAgent:  info.SoftwareAgent,
				AIGenerated:    info.AIGenerated,
				SignedBy:       info.SignedBy,
				VerifiedSigner: r.VerifiedSigner(),
				Valid:          r.Valid,
				Stores:         len(all),
			}
			if f := r.FirstFailure(); f != nil {
				got.FirstFailure = string(f.Code)
			}

			if strings.Contains(strings.ToLower(filepath.Base(path)), "laundered") {
				if got.Present {
					t.Errorf("a laundered copy must carry no credentials; got generator %q", got.ClaimGenerator)
				}
				return
			}

			goldenPath := path + ".golden.json"
			raw, err := os.ReadFile(goldenPath)
			if os.IsNotExist(err) {
				// First sight of this file: record what it looks like today.
				out, _ := json.MarshalIndent(got, "", "  ")
				if err := os.WriteFile(goldenPath, append(out, '\n'), 0o644); err != nil {
					t.Fatalf("writing golden: %v", err)
				}
				snapped++
				t.Logf("golden written — review it once: %s", goldenPath)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want vendorSnapshot
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("golden does not parse: %v", err)
			}
			if got != want {
				diffed++
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(want)
				t.Errorf("snapshot drifted\n got: %s\nwant: %s\n(delete the golden to re-snapshot after reviewing)", gotJSON, wantJSON)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("vendor corpus: %d files, %d new goldens, %d drifted", files, snapped, diffed)
}
