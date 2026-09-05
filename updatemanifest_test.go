package c2pa

import (
	"bytes"
	"context"
	"testing"

	"github.com/veraison/go-cose"
)

// updateManifestAssertion builds the parentOf ingredient §11.2.3 requires,
// naming the manifest being updated.
func parentOfAssertion(t testing.TB, refLabel string) assertionSpec {
	t.Helper()
	return assertionSpec{
		label: "c2pa.ingredient.v3",
		value: map[string]any{
			"relationship": "parentOf",
			"c2pa_manifest": map[string]any{
				"url":  "self#jumbf=/c2pa/" + refLabel,
				"hash": []byte{0x00},
			},
		},
	}
}

// updatedJPEG builds a JPEG whose store holds the manifest that binds the
// content, then an update manifest on top of it. extra is appended to the
// update manifest's assertions so a test can make it violate §11.2.3.
//
// The two manifests live in one store, which is how every container but BMFF
// carries an update: BMFF splits them across an "original" and an "update" box.
func updatedJPEG(t testing.TB, sb *signerBundle, extra ...assertionSpec) []byte {
	t.Helper()
	const parentLabel = "urn:uuid:00000000-0000-4000-8000-0000000000aa"
	const updateLabel = "urn:uuid:00000000-0000-4000-8000-0000000000bb"

	return buildFramedAsset(t, func(store []byte) ([]byte, int, int) {
		return assembleAsset(JPEG, store)
	}, manifestSpec{
		signer:     sb,
		label:      parentLabel,
		assertions: []assertionSpec{markerAssertion()},
		// buildFramedAsset signs the manifest that binds the content; the
		// update manifest is appended to the same store after it, which is what
		// makes it the active one.
		updateOverlay: &manifestSpec{
			signer:         sb,
			label:          updateLabel,
			updateManifest: true,
			noHardBinding:  true,
			assertions:     append([]assertionSpec{parentOfAssertion(t, parentLabel)}, extra...),
		},
	})
}

// TestUpdateManifestValidates is the false failure this closes: an update
// manifest carries no hard binding by design, and demanding one failed every
// correctly formed asset.
func TestUpdateManifestValidates(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := updatedJPEG(t, sb)

	res := runCorpus(t, JPEG, asset, sb)
	if res.Has(StatusHardBindingMissing) {
		t.Errorf("an update manifest changes no content and needs no binding of its own: %v", codes(res))
	}
	if !res.Valid {
		t.Fatalf("expected valid, got %v", codes(res))
	}
	// The parent's binding is what covers the bytes, and it was checked.
	if !res.Has(StatusAssertionDataHashMatch) {
		t.Errorf("the updated manifest's hard binding was not verified: %v", codes(res))
	}
}

// TestUpdateManifestBindsThroughItsParent pins that the parent's hard binding
// is checked against THIS asset rather than skipped the way an ordinary
// ingredient's is — otherwise an update manifest would leave the content
// unbound entirely.
func TestUpdateManifestBindsThroughItsParent(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := updatedJPEG(t, sb)

	// Edit image data the manifest covers.
	tampered := append([]byte(nil), asset...)
	tampered[len(tampered)-8] ^= 0xFF

	res := runCorpus(t, JPEG, tampered, sb)
	if !res.Has(StatusAssertionDataHashMismatch) {
		t.Errorf("editing the content under an update manifest went unnoticed: %v", codes(res))
	}
	if res.Valid {
		t.Errorf("expected invalid after editing the content, got %v", codes(res))
	}
}

// TestUpdateManifestInvalid covers what §11.2.3 forbids an update manifest from
// carrying, each of which implies the content changed after all.
func TestUpdateManifestInvalid(t *testing.T) {
	tests := []struct {
		name  string
		extra assertionSpec
	}{
		{
			name: "hard binding",
			extra: assertionSpec{label: "c2pa.hash.data", value: map[string]any{
				"alg": "sha256", "hash": make([]byte, 32),
			}},
		},
		{
			name:  "thumbnail",
			extra: assertionSpec{label: "c2pa.thumbnail.claim.jpeg", value: map[string]any{"x": 1}},
		},
		{
			name: "an action that changes content",
			extra: assertionSpec{label: "c2pa.actions.v2", value: map[string]any{
				"actions": []any{map[string]any{"action": "c2pa.color_adjustments"}},
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			res := runCorpus(t, JPEG, updatedJPEG(t, sb, tc.extra), sb)
			if !res.Has(StatusManifestUpdateInvalid) {
				t.Errorf("missing %s; got %v", StatusManifestUpdateInvalid, codes(res))
			}
			if res.Valid {
				t.Errorf("expected invalid, got %v", codes(res))
			}
		})
	}
}

// TestUpdateManifestAllowedActions pins the other half: §11.2.3 permits four
// actions, and rejecting all actions outright would fail files the spec allows.
func TestUpdateManifestAllowedActions(t *testing.T) {
	for _, action := range []string{
		"c2pa.edited.metadata", "c2pa.opened", "c2pa.published", "c2pa.redacted",
	} {
		t.Run(action, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			asset := updatedJPEG(t, sb, assertionSpec{
				label: "c2pa.actions.v2",
				value: map[string]any{"actions": []any{map[string]any{"action": action}}},
			})
			res := runCorpus(t, JPEG, asset, sb)
			if res.Has(StatusManifestUpdateInvalid) {
				t.Errorf("%s is permitted in an update manifest: %v", action, codes(res))
			}
			if !res.Valid {
				t.Errorf("expected valid, got %v", codes(res))
			}
		})
	}
}

// TestUpdateManifestWrongParents pins §11.2.3's "exactly one parentOf
// ingredient": it is what names the manifest whose binding covers the content,
// so zero leaves the asset unbound and two leave it ambiguous.
func TestUpdateManifestWrongParents(t *testing.T) {
	const otherLabel = "urn:uuid:00000000-0000-4000-8000-0000000000cc"
	t.Run("two parents", func(t *testing.T) {
		sb := newCorpusSigner(t, cose.AlgorithmES256)
		res := runCorpus(t, JPEG, updatedJPEG(t, sb, parentOfAssertion(t, otherLabel)), sb)
		if !res.Has(StatusManifestUpdateWrongParents) {
			t.Errorf("missing %s; got %v", StatusManifestUpdateWrongParents, codes(res))
		}
		if res.Valid {
			t.Errorf("expected invalid, got %v", codes(res))
		}
	})
	t.Run("no parent", func(t *testing.T) {
		sb := newCorpusSigner(t, cose.AlgorithmES256)
		asset := buildFramedAsset(t, func(store []byte) ([]byte, int, int) {
			return assembleAsset(JPEG, store)
		}, manifestSpec{
			signer:     sb,
			label:      "urn:uuid:00000000-0000-4000-8000-0000000000aa",
			assertions: []assertionSpec{markerAssertion()},
			updateOverlay: &manifestSpec{
				signer:         sb,
				label:          "urn:uuid:00000000-0000-4000-8000-0000000000bb",
				updateManifest: true,
				noHardBinding:  true,
				assertions:     []assertionSpec{markerAssertion()},
			},
		})
		res := runCorpus(t, JPEG, asset, sb)
		if !res.Has(StatusManifestUpdateWrongParents) {
			t.Errorf("missing %s; got %v", StatusManifestUpdateWrongParents, codes(res))
		}
	})
}

// TestBMFFUpdateManifestStoreIsActive covers the container half: §A.5.3 splits
// an updated BMFF asset across an "original" box and an appended "update" box,
// and the update store holds the active manifest while the original still holds
// the manifest its parentOf reference names.
func TestBMFFUpdateManifestStoreIsActive(t *testing.T) {
	ctx := context.Background()
	original := synthJUMB([]byte("the manifest that was updated"))
	update := synthJUMB([]byte("the update manifest"))
	file := bytes.Join([][]byte{
		synthBox("ftyp", []byte("isom")),
		synthC2PABox("original", original, 0),
		synthBox("mdat", bytes.Repeat([]byte{0x11}, 32)),
		synthC2PABox("update", update, 0),
	}, nil)

	if got := bmffJUMBF(ctx, file); !bytes.Equal(got, update) {
		t.Errorf("active store is the update one; got %q", got)
	}
	stores := bmffStores(ctx, file)
	if !bytes.Equal(stores["original"], original) {
		t.Errorf("the original store must stay reachable for the parentOf reference")
	}
	if !bytes.Equal(stores["update"], update) {
		t.Errorf("update store not surfaced")
	}
}
