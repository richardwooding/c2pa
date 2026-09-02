package c2pa

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// TestRead_SignedJPEG parses the JUMBF manifest from a real C2PA-signed JPEG
// (contentauth/c2pa-rs test fixture; see testdata/README.md).
func TestRead_SignedJPEG(t *testing.T) {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	c := Read(context.Background(), JPEG, f)
	if !c.Present {
		t.Fatal("expected a C2PA manifest")
	}
	if !bytes.Contains([]byte(c.ClaimGenerator), []byte("c2pa-rs")) {
		t.Errorf("ClaimGenerator=%q want it to mention c2pa-rs", c.ClaimGenerator)
	}
	if c.Title != "CA.jpg" {
		t.Errorf("Title=%q want CA.jpg", c.Title)
	}
	if c.AIGenerated {
		t.Errorf("CA.jpg is edited, not AI-generated; want AIGenerated=false")
	}
	// Signer identity + signing time from the COSE_Sign1 envelope.
	if c.SignedBy != "C2PA Signer" {
		t.Errorf("SignedBy=%q want %q", c.SignedBy, "C2PA Signer")
	}
	wantSignedAt := time.Date(2024, 8, 6, 21, 53, 37, 0, time.UTC)
	if !c.SignedAt.Equal(wantSignedAt) {
		t.Errorf("SignedAt=%s want %s", c.SignedAt.Format(time.RFC3339), wantSignedAt.Format(time.RFC3339))
	}
}

// TestRead_NoManifest returns Present=false for content with no manifest.
func TestRead_NoManifest(t *testing.T) {
	if c := Read(context.Background(), JPEG, bytes.NewReader([]byte("\xff\xd8\xff\xe0 not a real manifest"))); c.Present {
		t.Errorf("expected no manifest, got %+v", c)
	}
}

// TestRead_UnknownContainer returns a zero Info for an unrecognised container.
func TestRead_UnknownContainer(t *testing.T) {
	if c := Read(context.Background(), Container("tiff"), bytes.NewReader([]byte("whatever"))); c.Present {
		t.Errorf("unknown container should yield no manifest, got %+v", c)
	}
}

// TestRead_Cancellation pins that a cancelled context is honoured by the scan,
// not run to completion: a pre-cancelled ctx bails at entry and parses nothing.
func TestRead_Cancellation(t *testing.T) {
	f, err := os.Open("testdata/c2pa_signed.jpg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c := Read(ctx, JPEG, f); c.Present {
		t.Errorf("cancelled ctx should yield no manifest, got %+v", c)
	}
}

// TestActionsAreAI checks the AI-generated detection on synthetic c2pa.actions
// assertions (no public AI-positive fixture available).
func TestActionsAreAI(t *testing.T) {
	ai := mustCBOR(t, map[string]any{"actions": []any{
		map[string]any{"action": "c2pa.created",
			"digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"},
	}})
	aiParam := mustCBOR(t, map[string]any{"actions": []any{
		map[string]any{"action": "c2pa.created",
			"parameters": map[string]any{"digitalSourceType": "...compositeWithTrainedAlgorithmicMedia"}},
	}})
	notAI := mustCBOR(t, map[string]any{"actions": []any{
		map[string]any{"action": "c2pa.color_adjustments"},
		map[string]any{"action": "c2pa.opened"},
	}})

	for _, tc := range []struct {
		name string
		cbor []byte
		want bool
	}{
		{"top-level digitalSourceType", ai, true},
		{"parameters digitalSourceType", aiParam, true},
		{"edit-only actions", notAI, false},
	} {
		var m map[string]any
		if err := decMode.Unmarshal(tc.cbor, &m); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := actionsAreAI(m); got != tc.want {
			t.Errorf("%s: actionsAreAI=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestClaimGeneratorInfoShapes(t *testing.T) {
	// claim_generator_info is an array in C2PA 1.x and a single entry in 2.x. A
	// c2pa.claim.v2 from Google or OpenAI carries only the 2.x shape and no flat
	// claim_generator, so reading just the array leaves the generator empty.
	for _, tc := range []struct {
		name  string
		claim map[string]any
		want  string
	}{
		{"flat claim_generator wins", map[string]any{
			"claim_generator":      "make_test_images/0.33.1 c2pa-rs/0.33.1",
			"claim_generator_info": map[string]any{"name": "ignored"},
		}, "make_test_images/0.33.1 c2pa-rs/0.33.1"},

		{"2.x single entry", map[string]any{
			"claim_generator_info": map[string]any{"name": "OpenAI Media Service API"},
		}, "OpenAI Media Service API"},

		{"2.x single entry with version", map[string]any{
			"claim_generator_info": map[string]any{
				"name": "Google C2PA Core Generator Library", "version": "964701591:964701591"},
		}, "Google C2PA Core Generator Library/964701591:964701591"},

		{"1.x array", map[string]any{
			"claim_generator_info": []any{
				map[string]any{"name": "Firefly", "version": "1.2"},
				map[string]any{"name": "Photoshop"},
			},
		}, "Firefly/1.2 Photoshop"},

		{"entry without a name", map[string]any{
			"claim_generator_info": map[string]any{"version": "1.0"},
		}, ""},

		{"absent", map[string]any{}, ""},
	} {
		var m map[string]any
		if err := decMode.Unmarshal(mustCBOR(t, tc.claim), &m); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := claimGenerator(m); got != tc.want {
			t.Errorf("%s: claimGenerator=%q want %q", tc.name, got, tc.want)
		}
	}
}

func TestActionsSoftwareAgent(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  map[string]any
		want string
	}{
		{"2.x entry with version", map[string]any{"actions": []any{
			map[string]any{"action": "c2pa.created",
				"softwareAgent": map[string]any{"name": "gpt-image", "version": "2.0"}},
		}}, "gpt-image/2.0"},

		{"1.x plain string", map[string]any{"actions": []any{
			map[string]any{"action": "c2pa.created", "softwareAgent": "Adobe Firefly 1.0"},
		}}, "Adobe Firefly 1.0"},

		{"first action that names one", map[string]any{"actions": []any{
			map[string]any{"action": "c2pa.opened"},
			map[string]any{"action": "c2pa.created",
				"softwareAgent": map[string]any{"name": "gpt-image", "version": "2.0"}},
		}}, "gpt-image/2.0"},

		{"2.x softwareAgentIndex", map[string]any{
			"softwareAgents": []any{
				map[string]any{"name": "ignored"},
				map[string]any{"name": "gpt-image", "version": "2.0"},
			},
			"actions": []any{
				map[string]any{"action": "c2pa.created", "softwareAgentIndex": 1},
			},
		}, "gpt-image/2.0"},

		{"inline softwareAgent beats the index", map[string]any{
			"softwareAgents": []any{map[string]any{"name": "indexed"}},
			"actions": []any{
				map[string]any{"action": "c2pa.created", "softwareAgentIndex": 0,
					"softwareAgent": map[string]any{"name": "inline"}},
			},
		}, "inline"},

		{"index past the end", map[string]any{
			"softwareAgents": []any{map[string]any{"name": "gpt-image"}},
			"actions": []any{
				map[string]any{"action": "c2pa.created", "softwareAgentIndex": 5},
			},
		}, ""},

		{"index with no softwareAgents array", map[string]any{"actions": []any{
			map[string]any{"action": "c2pa.created", "softwareAgentIndex": 0},
		}}, ""},

		{"none named", map[string]any{"actions": []any{
			map[string]any{"action": "c2pa.created"},
		}}, ""},

		{"no actions", map[string]any{}, ""},
	} {
		var m map[string]any
		if err := decMode.Unmarshal(mustCBOR(t, tc.act), &m); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := actionsSoftwareAgent(m); got != tc.want {
			t.Errorf("%s: actionsSoftwareAgent=%q want %q", tc.name, got, tc.want)
		}
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRead_ActiveManifestOnly pins two Read-path fixes on the video fixture,
// whose active manifest is signed by "C2PA Signer" via the pre-1.3 text-key
// x5chain and which embeds an ingredient manifest signed by "Bob":
//
//   - SignedBy was empty, because leafCert only read the int64(33) label; and
//   - with the active manifest unreadable, nothing stopped an ingredient's
//     values standing in for the asset's.
func TestRead_ActiveManifestOnly(t *testing.T) {
	f, err := os.Open("testdata/c2pa_signed_video.mp4")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	info := Read(context.Background(), BMFF, f)
	if !info.Present {
		t.Fatal("expected a manifest")
	}
	if info.SignedBy != "C2PA Signer" {
		t.Errorf("SignedBy = %q, want the ACTIVE manifest's signer %q (Bob is the ingredient's)",
			info.SignedBy, "C2PA Signer")
	}
	if info.AIGenerated {
		t.Error("AIGenerated leaked from outside the active manifest")
	}
}
