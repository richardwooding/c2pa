package c2pa

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSeedFuzzFromCorpora is not a test of the library: it plants real corpus
// and vendor files as fuzz-corpus entries in the LOCAL Go fuzz cache, so the
// nightly Fuzz* targets mutate real vendor structures rather than only the
// synthetic seeds. Opt-in via C2PA_FUZZ_SEED=1 (plus the usual corpus vars).
//
// Seeds go to GOCACHE, never to testdata/ — the corpus is CC-BY-SA-4.0 and the
// vendor files carry their own licensing, so neither may be committed to this
// MIT repository.
func TestSeedFuzzFromCorpora(t *testing.T) {
	if os.Getenv("C2PA_FUZZ_SEED") != "1" {
		t.Skip("set C2PA_FUZZ_SEED=1 (with C2PA_CORPUS_DIR / C2PA_VENDOR_CORPUS) to plant fuzz seeds")
	}
	gocache, err := exec.Command("go", "env", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	fuzzRoot := filepath.Join(strings.TrimSpace(string(gocache)), "fuzz", "github.com/richardwooding/c2pa")

	targetFor := map[Container]string{
		PDF: "FuzzPDFParse", RIFF: "FuzzRIFFParse", TIFF: "FuzzTIFFParse",
		GIF: "FuzzGIFParse", MP3: "FuzzMP3Parse", SVG: "FuzzSVGParse", BMFF: "FuzzBMFFParse",
	}

	plant := func(target string, data []byte) error {
		dir := filepath.Join(fuzzRoot, target)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		name := filepath.Join(dir, fmt.Sprintf("corpus-%x", sum[:8]))
		entry := "go test fuzz v1\n[]byte(" + strconv.Quote(string(data)) + ")\n"
		return os.WriteFile(name, []byte(entry), 0o644)
	}

	var roots []string
	if d := os.Getenv("C2PA_CORPUS_DIR"); d != "" {
		roots = append(roots, d)
	}
	if d := os.Getenv("C2PA_VENDOR_CORPUS"); d != "" {
		roots = append(roots, d)
	}
	if len(roots) == 0 {
		t.Skip("no corpus configured — set C2PA_CORPUS_DIR and/or C2PA_VENDOR_CORPUS")
	}

	planted := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || strings.HasSuffix(path, ".golden.json") {
				return err
			}
			container, ok := corpusContainer(path)
			if !ok {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Raw file bytes feed the container parser's target plus the two
			// whole-pipeline targets; the extracted store feeds the box walker.
			targets := []string{"FuzzRead", "FuzzValidate"}
			if tgt, ok := targetFor[container]; ok {
				targets = append(targets, tgt)
			}
			for _, tgt := range targets {
				if err := plant(tgt, data); err != nil {
					return err
				}
				planted++
			}
			if store := extractJUMBF(context.Background(), container, data); len(store) > 0 {
				for _, tgt := range []string{"FuzzWalkBoxes", "FuzzWalkBoxesRanges"} {
					if err := plant(tgt, store); err != nil {
						return err
					}
					planted++
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("planted %d fuzz seeds under %s", planted, fuzzRoot)
}
