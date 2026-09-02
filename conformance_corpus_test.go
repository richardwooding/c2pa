package c2pa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The conformance corpus is c2pa-org/public-testfiles, pinned to a commit so a
// run is reproducible and an upstream change is a deliberate bump here. The
// files are CC-BY-SA-4.0 — they are downloaded into a cache, never committed.
const (
	corpusSHA = "22beccc075707475b038d8789d0136c009e43143"
	corpusURL = "https://github.com/c2pa-org/public-testfiles/archive/%s.tar.gz"
	// corpusFileDeadline bounds each file; the corpus holds nothing that a
	// healthy parser needs more than a moment for.
	corpusFileDeadline = 30 * time.Second
)

// corpusDir resolves the corpus location, or skips the test. Opt-in like
// TestPDFAdobeReferenceFile: C2PA_CORPUS_DIR names an existing checkout, or
// C2PA_CORPUS=download fetches the pinned commit into ~/.cache/c2pa-corpus.
func corpusDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("C2PA_CORPUS_DIR"); dir != "" {
		return dir
	}
	if os.Getenv("C2PA_CORPUS") != "download" {
		t.Skip("set C2PA_CORPUS_DIR or C2PA_CORPUS=download to run the conformance corpus")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(home, ".cache", "c2pa-corpus", corpusSHA)
	if _, err := os.Stat(filepath.Join(cache, ".complete")); err == nil {
		return cache
	}
	if err := fetchCorpus(cache); err != nil {
		t.Fatalf("downloading corpus: %v", err)
	}
	return cache
}

func fetchCorpus(cache string) error {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	resp, err := http.Get(fmt.Sprintf(corpusURL, corpusSHA))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("corpus download: %s", resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Strip the leading "<repo>-<sha>/" component the tarball wraps around.
		parts := strings.SplitN(hdr.Name, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}
		dst := filepath.Join(cache, filepath.FromSlash(parts[1]))
		if !strings.HasPrefix(dst, filepath.Clean(cache)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes cache: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			f, err := os.Create(dst)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(filepath.Join(cache, ".complete"), nil, 0o644)
}

// corpusContainer maps a corpus file to its Container by extension, false for
// the types this library does not read (fonts, and the corpus's own JSON/docs).
func corpusContainer(path string) (Container, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg":
		return JPEG, true
	case ".png":
		return PNG, true
	case ".mp4", ".mov", ".m4a", ".heic", ".heif", ".avif":
		return BMFF, true
	case ".webp", ".wav", ".avi":
		return RIFF, true
	case ".tif", ".tiff", ".dng":
		return TIFF, true
	case ".gif":
		return GIF, true
	case ".mp3":
		return MP3, true
	case ".svg":
		return SVG, true
	case ".pdf":
		return PDF, true
	}
	return "", false
}

// TestConformanceCorpusEveryFile is tier 1: every readable asset in the corpus
// parses to completion — Read, Validate and ExtractStore — within a deadline
// and without panicking, and the three agree on whether a store exists.
func TestConformanceCorpusEveryFile(t *testing.T) {
	dir := corpusDir(t)

	var files, present, valid int
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		container, ok := corpusContainer(path)
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

			start := time.Now()
			info := Read(ctx, container, bytes.NewReader(data))
			r := Validate(ctx, container, bytes.NewReader(data))
			store, err := ExtractStore(ctx, container, bytes.NewReader(data))
			if err != nil {
				t.Errorf("ExtractStore: %v", err)
			}
			if elapsed := time.Since(start); elapsed > corpusFileDeadline {
				t.Errorf("file took %v — the deadline was not honoured", elapsed)
			}

			if info.Present {
				present++
				if len(store) < 8 || string(store[4:8]) != "jumb" {
					t.Errorf("Read.Present but ExtractStore returned no jumb superbox (%d bytes)", len(store))
				}
				if r.ActiveManifestLabel == "" {
					t.Errorf("Read.Present but Validate placed no active manifest")
				}
			}
			if r.Valid {
				valid++
				if !info.Present {
					t.Error("Valid without Present — a verdict with no manifest")
				}
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("corpus tier 1: %d files read, %d with a store, %d fully valid", files, present, valid)
}

// corpusGolden is the subset of the corpus's manifest_store.json this library
// models: the fields Read/Validate must agree with.
type corpusGolden struct {
	ActiveManifest string `json:"active_manifest"`
	Manifests      map[string]struct {
		ClaimGenerator string `json:"claim_generator"`
		Title          string `json:"title"`
		Format         string `json:"format"`
		SignatureInfo  struct {
			Issuer string `json:"issuer"`
			Time   string `json:"time"`
		} `json:"signature_info"`
	} `json:"manifests"`
}

// TestConformanceCorpusGoldens is tier 2: the corpus assets that ship a
// manifest_store.json are compared field by field. Every divergence is
// reported (not fail-fast), so one run gives the whole picture.
func TestConformanceCorpusGoldens(t *testing.T) {
	dir := corpusDir(t)

	goldens := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "manifest_store.json" {
			return err
		}
		// <dir>/manifests/<base>/manifest_store.json pairs with <dir>/<base>.<ext>.
		base := filepath.Base(filepath.Dir(path))
		assetDir := filepath.Dir(filepath.Dir(filepath.Dir(path)))
		matches, _ := filepath.Glob(filepath.Join(assetDir, base+".*"))
		var asset string
		for _, m := range matches {
			if _, ok := corpusContainer(m); ok {
				asset = m
				break
			}
		}
		if asset == "" {
			return nil // a golden for a type this library does not read (e.g. font)
		}
		goldens++

		rel, _ := filepath.Rel(dir, asset)
		t.Run(filepath.ToSlash(rel), func(t *testing.T) {
			var want corpusGolden
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("golden does not parse: %v", err)
			}
			wantM, ok := want.Manifests[want.ActiveManifest]
			if !ok {
				t.Fatalf("golden names active manifest %q but does not describe it", want.ActiveManifest)
			}

			data, err := os.ReadFile(asset)
			if err != nil {
				t.Fatal(err)
			}
			container, _ := corpusContainer(asset)
			ctx, cancel := context.WithTimeout(context.Background(), corpusFileDeadline)
			defer cancel()

			info := Read(ctx, container, bytes.NewReader(data))
			r := Validate(ctx, container, bytes.NewReader(data))

			if !info.Present {
				t.Fatal("golden asset reports no manifest at all")
			}
			if r.ActiveManifestLabel != want.ActiveManifest {
				t.Errorf("ActiveManifestLabel = %q, golden %q", r.ActiveManifestLabel, want.ActiveManifest)
			}
			if info.ClaimGenerator != wantM.ClaimGenerator {
				t.Errorf("ClaimGenerator = %q, golden %q", info.ClaimGenerator, wantM.ClaimGenerator)
			}
			if wantM.Title != "" && info.Title != wantM.Title {
				t.Errorf("Title = %q, golden %q", info.Title, wantM.Title)
			}
			if wantM.Format != "" && info.Format != wantM.Format {
				t.Errorf("Format = %q, golden %q", info.Format, wantM.Format)
			}
			// The golden's issuer is c2pa-rs's signature_info.issuer — the signing
			// certificate's subject organisation. Our SignedBy prefers the CN, so
			// accept either field matching; a signer we cannot name at all is the
			// real failure being hunted here.
			if wantM.SignatureInfo.Issuer != "" {
				leafO := ""
				if len(r.SignerChain) > 0 && len(r.SignerChain[0].Subject.Organization) > 0 {
					leafO = r.SignerChain[0].Subject.Organization[0]
				}
				if info.SignedBy != wantM.SignatureInfo.Issuer && leafO != wantM.SignatureInfo.Issuer {
					t.Errorf("signer: SignedBy=%q leaf O=%q, golden issuer %q",
						info.SignedBy, leafO, wantM.SignatureInfo.Issuer)
				}
			}
			if wantM.SignatureInfo.Time != "" {
				goldenTime, err := time.Parse(time.RFC3339, wantM.SignatureInfo.Time)
				if err == nil && !info.SignedAt.IsZero() && !info.SignedAt.Equal(goldenTime) {
					t.Errorf("SignedAt = %v, golden %v", info.SignedAt.UTC(), goldenTime.UTC())
				}
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("corpus tier 2: %d golden assets compared", goldens)
}
