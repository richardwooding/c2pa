package c2pa

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"os"
	"testing"
	"time"

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

	return buildFramedAsset(t, func(store []byte) ([]byte, []byteRange) {
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
			// The rejection returns before the parent's binding is verified,
			// so nothing hashed the asset.
			if !res.Has(StatusHardBindingMissing) {
				t.Errorf("rejected update manifest left the asset unbound and said so nowhere: %v",
					codes(res))
			}
			if res.Has(StatusAssertionDataHashMatch) {
				t.Errorf("nothing should have hashed the asset: %v", codes(res))
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
		if !res.Has(StatusHardBindingMissing) {
			t.Errorf("two parents leave the binding ambiguous, so nothing was hashed: %v", codes(res))
		}
		if res.Valid {
			t.Errorf("expected invalid, got %v", codes(res))
		}
	})
	t.Run("no parent", func(t *testing.T) {
		sb := newCorpusSigner(t, cose.AlgorithmES256)
		asset := buildFramedAsset(t, func(store []byte) ([]byte, []byteRange) {
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
		if !res.Has(StatusHardBindingMissing) {
			t.Errorf("no parent means no binding at all: %v", codes(res))
		}
	})

	// The third early return: exactly one parentOf ingredient, naming a
	// manifest the store does not hold. Nothing resolves, so nothing binds.
	t.Run("parent not in the store", func(t *testing.T) {
		sb := newCorpusSigner(t, cose.AlgorithmES256)
		asset := buildFramedAsset(t, func(store []byte) ([]byte, []byteRange) {
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
				assertions:     []assertionSpec{parentOfAssertion(t, otherLabel)},
			},
		})
		res := runCorpus(t, JPEG, asset, sb)
		if !res.Has(StatusIngredientManifestMismatch) {
			t.Errorf("missing %s; got %v", StatusIngredientManifestMismatch, codes(res))
		}
		if !res.Has(StatusHardBindingMissing) {
			t.Errorf("an unresolvable parent binds nothing: %v", codes(res))
		}
	})
}

// TestUpdateManifestRelabelCannotSilenceTheBinding is why the status is
// reported rather than left implicit, on a real signed file. Two bytes of the
// superbox's JUMBF type UUID — "c2ma" to "c2um" — relabel a genuine manifest as
// an Update Manifest: no signature covers that UUID, so everything the claim
// signed still checks out, §11.2.3 now forbids the binding, and
// assertion.dataHash.match simply disappears with nothing saying so.
func TestUpdateManifestRelabelCannotSilenceTheBinding(t *testing.T) {
	ctx := context.Background()
	pool, data := fixtureSigningPool(t)

	// The standard manifest UUID differs from the update one in exactly two
	// bytes: 6332_6D61_… ("c2ma") against 6332_756D_… ("c2um").
	standard := updateManifestUUID
	standard[2], standard[3] = 'm', 'a'
	if n := bytes.Count(data, standard[:]); n != 1 {
		t.Fatalf("fixture carries %d standard manifest superboxes, want exactly 1", n)
	}
	flipped := bytes.Replace(data, standard[:], updateManifestUUID[:], 1)

	before := Validate(ctx, JPEG, bytes.NewReader(data), WithSigningTrust(pool))
	if !before.Has(StatusAssertionDataHashMatch) {
		t.Fatalf("fixture's binding did not verify to begin with: %v", codes(before))
	}

	after := Validate(ctx, JPEG, bytes.NewReader(flipped), WithSigningTrust(pool))
	if !after.Has(StatusManifestUpdateInvalid) {
		t.Fatalf("relabelled manifest was not rejected: %v", codes(after))
	}
	// The signature still validates over untouched bytes and the binding is
	// gone, so only hardBinding.missing says the bytes went unchecked.
	if !after.Has(StatusClaimSignatureValidated) {
		t.Errorf("the two flipped bytes are covered by no signature, so this should still hold: %v",
			codes(after))
	}
	if after.Has(StatusAssertionDataHashMatch) {
		t.Errorf("no binding was verified, so this must not be reported: %v", codes(after))
	}
	if !after.Has(StatusHardBindingMissing) {
		t.Errorf("nothing hashed the asset and no status said so: %v", codes(after))
	}
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

// TestManifestMultipleParents pins that a standard manifest declaring more than
// one parentOf ingredient is reported: an asset descends from one manifest, and
// two parents leave which one ambiguous.
func TestManifestMultipleParents(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	one := parentOfAssertion(t, "urn:uuid:00000000-0000-4000-8000-0000000000a1")
	two := parentOfAssertion(t, "urn:uuid:00000000-0000-4000-8000-0000000000a2")
	two.label = "c2pa.ingredient.v3__2"

	asset := buildAsset(t, JPEG, manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion(), one, two},
	})
	res := runCorpus(t, JPEG, asset, sb)
	if !res.Has(StatusManifestMultipleParents) {
		t.Errorf("missing %s; got %v", StatusManifestMultipleParents, codes(res))
	}

	// One parent is the ordinary case and must stay quiet.
	single := buildAsset(t, JPEG, manifestSpec{
		signer:     sb,
		assertions: []assertionSpec{markerAssertion(), one},
	})
	if res := runCorpus(t, JPEG, single, sb); res.Has(StatusManifestMultipleParents) {
		t.Errorf("a single parentOf ingredient is normal: %v", codes(res))
	}
}

// appendedUpdate builds what a real update looks like on the wire, which the
// corpus's updateOverlay does not: the parent manifest signs the asset FIRST,
// with an exclusion covering the store as it then is, and the update manifest
// is appended to that store afterwards, so the recorded exclusion is shorter
// than the store in the file. The store is re-embedded through the production
// embedder, which puts it back where it was (the same canonical position
// assembleAsset used) and leaves only its length changed — the in-place growth
// §15.12.1.1 describes.
func appendedUpdate(t testing.TB, container Container, sb *signerBundle) (asset []byte, updateLabel string) {
	t.Helper()
	const parentLabel = "urn:uuid:00000000-0000-4000-8000-0000000000aa"
	updateLabel = "urn:uuid:00000000-0000-4000-8000-0000000000bb"
	ctx := context.Background()

	parent := buildAsset(t, container, manifestSpec{
		signer:     sb,
		label:      parentLabel,
		assertions: []assertionSpec{markerAssertion()},
	})
	store := extractJUMBF(ctx, container, parent)
	if len(store) == 0 {
		t.Fatal("parent asset has no store")
	}
	update := buildManifest(t, manifestSpec{
		signer:         sb,
		label:          updateLabel,
		updateManifest: true,
		noHardBinding:  true,
		assertions:     []assertionSpec{parentOfAssertion(t, parentLabel)},
	})
	grown := appendToStore(store, update)
	asset, _, err := embedStore(ctx, container, parent, grown)
	if err != nil {
		t.Fatalf("re-embedding the grown store: %v", err)
	}
	return asset, updateLabel
}

// appendToStore appends a box to a manifest store superbox, as an update
// writer does, and fixes the superbox's LBox.
func appendToStore(store, box []byte) []byte {
	grown := append(append([]byte(nil), store...), box...)
	binary.BigEndian.PutUint32(grown[:4], uint32(len(grown)))
	return grown
}

// recordedExclusions reads the exclusions a manifest's c2pa.hash.data declares,
// as given.
func recordedExclusions(t testing.TB, m *parsedManifest) []byteRange {
	t.Helper()
	for _, a := range m.assertions {
		if a.label != "c2pa.hash.data" {
			continue
		}
		var assertion map[string]any
		if err := decMode.Unmarshal(a.data, &assertion); err != nil {
			t.Fatalf("decode c2pa.hash.data: %v", err)
		}
		excl, ok := decodeExclusions(assertion["exclusions"], 1<<40)
		if !ok {
			t.Fatal("c2pa.hash.data exclusions do not decode")
		}
		return excl
	}
	t.Fatalf("manifest %s has no c2pa.hash.data", m.label)
	return nil
}

// TestUpdateManifestAppendedAfterSigning is issue #72 for every container that
// carries an update in place: the parent's exclusion describes the store before
// the update was appended, and §15.12.1.1 has the verifier extend it to the
// store's current length rather than report a false mismatch. Editing the
// content under the same update is still caught, so the adjustment widens the
// exclusion to the store and nothing else.
//
// RIFF and MP3 are the two the rule cannot rescue, and the rows pin that: the
// growth also rewrites a size field the exclusion does not cover — the RIFF
// header's size (and the chunk's pad byte comes and goes), the ID3 tag's and
// the GEOB frame's — so the bytes the parent hashed are no longer all there.
// That is the exclusion convention c2pa-rs shares, not a locator defect: the
// adjustment is applied, and the hash then rightly says the header changed.
func TestUpdateManifestAppendedAfterSigning(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	for _, tc := range []struct {
		c         Container
		wantMatch bool
	}{
		{JPEG, true}, {PNG, true}, {GIF, true}, {TIFF, true}, {SVG, true},
		{RIFF, false}, {MP3, false},
	} {
		t.Run(string(tc.c), func(t *testing.T) {
			asset, updateLabel := appendedUpdate(t, tc.c, sb)
			ctx := context.Background()

			// The premise: the recorded exclusion is shorter than the store.
			store := parseStore(ctx, extractJUMBF(ctx, tc.c, asset))
			var parent *parsedManifest
			for _, m := range store.manifests {
				if !m.update {
					parent = m
				}
			}
			if parent == nil {
				t.Fatal("no standard manifest in the store")
			}
			recorded := recordedExclusions(t, parent)
			current := storeRanges(ctx, tc.c, asset)
			if len(current) == 0 {
				t.Fatalf("storeRanges found no store in the %s asset", tc.c)
			}
			if _, grew := adjustExclusionsForUpdate(recorded, current); !grew {
				t.Fatalf("premise failed: recorded %v is not shorter than the current store %v", recorded, current)
			}

			res := runCorpus(t, tc.c, asset, sb)
			if res.ActiveManifestLabel != updateLabel {
				t.Fatalf("active manifest = %s, want the update %s", res.ActiveManifestLabel, updateLabel)
			}
			if !tc.wantMatch {
				if !res.Has(StatusAssertionDataHashMismatch) || res.Binding != BindingFailed || res.Valid {
					t.Errorf("growth rewrote a hashed size field, so this should still mismatch: binding=%s valid=%v %v",
						res.Binding, res.Valid, codes(res))
				}
				return
			}
			if !res.Has(StatusAssertionDataHashMatch) || res.Binding != BindingVerified {
				t.Errorf("the parent's binding should match once its exclusion covers the current store: binding=%s %v",
					res.Binding, codes(res))
			}
			if !res.Valid {
				t.Errorf("expected valid, got %v", codes(res))
			}

			// Content edited under the update: still a mismatch.
			tampered := append([]byte(nil), asset...)
			tampered[contentOffset(t, tc.c, asset)] ^= 0xFF
			res = runCorpus(t, tc.c, tampered, sb)
			if !res.Has(StatusAssertionDataHashMismatch) || res.Binding != BindingFailed || res.Valid {
				t.Errorf("editing the content under an appended update went unnoticed: binding=%s valid=%v %v",
					res.Binding, res.Valid, codes(res))
			}
		})
	}
}

// contentOffset is a byte of asset the hard binding covers and the container's
// reader does not interpret, so flipping it is an edit to the content and
// nothing else. The last byte serves where the store is not last; TIFF's store
// is appended last, so its one pixel (tag 273, StripOffsets) is used instead.
func contentOffset(t testing.TB, c Container, asset []byte) int {
	t.Helper()
	if c != TIFF {
		return len(asset) - 1
	}
	l, err := parseTIFFLayout(asset)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := l.ifds(context.Background(), asset)
	if err != nil {
		t.Fatal(err)
	}
	for e := 0; e < chain[0].count; e++ {
		at := chain[0].entriesAt + e*l.entryLen
		if l.bo.Uint16(asset[at:at+2]) == 273 {
			return int(l.readW(asset[at+4+l.entryCountW:at+4+l.entryCountW+l.offW], l.offW))
		}
	}
	t.Fatal("TIFF has no StripOffsets entry")
	return 0
}

// TestStoreGrowthWithoutUpdateIsAMismatch pins the gate: the exclusion is
// extended only when an update manifest was encountered. A store that grew
// with no update manifest in it — here, an unsigned box appended to it — is
// bytes the standard manifest never covered, and the hash says so.
func TestStoreGrowthWithoutUpdateIsAMismatch(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ctx := context.Background()
	parent := buildAsset(t, JPEG, manifestSpec{
		signer:     sb,
		label:      "urn:uuid:00000000-0000-4000-8000-0000000000aa",
		assertions: []assertionSpec{markerAssertion()},
	})
	grown := appendToStore(extractJUMBF(ctx, JPEG, parent), leafBox("free", make([]byte, 100)))
	asset, _, err := embedStore(ctx, JPEG, parent, grown)
	if err != nil {
		t.Fatal(err)
	}
	res := runCorpus(t, JPEG, asset, sb)
	if !res.Has(StatusAssertionDataHashMismatch) || res.Binding != BindingFailed || res.Valid {
		t.Errorf("a store that grew without an update manifest must not be excused: binding=%s valid=%v %v",
			res.Binding, res.Valid, codes(res))
	}
}

// TestUpdateManifestFixture is the file issue #72 was reported on: c2pa-rs's
// own update_manifest.jpg, whose parent manifest records the exclusion
// {9964, 18874} over a store that now spans {9964, 43607}. It is the one
// update-manifest asset here written by a real producer, so it is also what
// pins the JPEG locator against c2pa-rs's layout.
func TestUpdateManifestFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/update_manifest.jpg")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, want := storeRanges(ctx, JPEG, data), []byteRange{{start: 9964, length: 43607}}; !sameRanges(got, want) {
		t.Fatalf("storeRanges = %v, want %v", got, want)
	}
	store := parseStore(ctx, extractJUMBF(ctx, JPEG, data))
	const parentLabel = "adobe:urn:uuid:6a6b4dbe-5ef9-40ec-81ec-d8955db3e95c"
	parent := store.byLabel()[parentLabel]
	if parent == nil {
		t.Fatalf("fixture has no manifest %s", parentLabel)
	}
	if got, want := recordedExclusions(t, parent), []byteRange{{start: 9964, length: 18874}}; !sameRanges(got, want) {
		t.Fatalf("recorded exclusions = %v, want %v", got, want)
	}

	pool := ownChainPool(t, store.active())
	clock := func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }
	res := Validate(ctx, JPEG, bytes.NewReader(data), WithSigningTrust(pool), WithClock(clock))
	if !res.Info.Present || res.ActiveManifestLabel == parentLabel || !store.active().update {
		t.Fatalf("active manifest = %s, want the update manifest", res.ActiveManifestLabel)
	}
	if !hasAt(res, StatusAssertionDataHashMatch, parentLabel+"/c2pa.hash.data") || res.Binding != BindingVerified {
		t.Errorf("the parent's binding should match with the exclusion extended: binding=%s %v", res.Binding, codes(res))
	}
	if res.Has(StatusAssertionDataHashMismatch) || res.Has(StatusManifestUpdateInvalid) || res.Has(StatusHardBindingMissing) {
		t.Errorf("unexpected failures: %v", codes(res))
	}
	if !res.Valid || res.VerifiedSigner() != "C2PA Signer" {
		t.Errorf("valid=%v signer=%q: %v", res.Valid, res.VerifiedSigner(), codes(res))
	}

	// The same file with a byte of image data flipped is still a mismatch.
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-4] ^= 0xFF
	res = Validate(ctx, JPEG, bytes.NewReader(tampered), WithSigningTrust(pool), WithClock(clock))
	if !res.Has(StatusAssertionDataHashMismatch) || res.Binding != BindingFailed || res.Valid {
		t.Errorf("tampered fixture: binding=%s valid=%v %v", res.Binding, res.Valid, codes(res))
	}
}

// ownChainPool anchors a trust pool at the top certificate of a manifest's own
// COSE x5chain, the way fixtureSigningPool does for c2pa_signed.jpg.
func ownChainPool(t testing.TB, m *parsedManifest) *x509.CertPool {
	t.Helper()
	if m == nil || len(m.signature) == 0 {
		t.Fatal("manifest has no signature")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(m.signature); err != nil {
		t.Fatalf("decode COSE: %v", err)
	}
	chain := parseChain(msg.Headers.Protected[cose.HeaderLabelX5Chain])
	if len(chain) == 0 {
		t.Fatal("manifest has no x5chain")
	}
	pool := x509.NewCertPool()
	pool.AddCert(chain[len(chain)-1])
	return pool
}

// TestAdjustExclusionsForUpdate is the arithmetic of §15.12.1.1 on its own: the
// exclusion that starts where the store starts takes the store's current
// length, the ones after it shift by the growth, and nothing else moves.
func TestAdjustExclusionsForUpdate(t *testing.T) {
	cases := []struct {
		name              string
		recorded, current []byteRange
		want              []byteRange
		changed           bool
	}{
		{"grows", []byteRange{{100, 50}}, []byteRange{{100, 80}}, []byteRange{{100, 80}}, true},
		{"later exclusions shift", []byteRange{{100, 50}, {400, 10}}, []byteRange{{100, 80}},
			[]byteRange{{100, 80}, {430, 10}}, true},
		{"earlier exclusions stay", []byteRange{{10, 4}, {100, 50}}, []byteRange{{100, 80}},
			[]byteRange{{10, 4}, {100, 80}}, true},
		{"order as given", []byteRange{{400, 10}, {100, 50}}, []byteRange{{100, 80}},
			[]byteRange{{430, 10}, {100, 80}}, true},
		{"tiff count field and store", []byteRange{{10, 4}, {100, 50}}, []byteRange{{10, 4}, {100, 80}},
			[]byteRange{{10, 4}, {100, 80}}, true},
		{"same length", []byteRange{{100, 50}}, []byteRange{{100, 50}}, []byteRange{{100, 50}}, false},
		{"shrank", []byteRange{{100, 50}}, []byteRange{{100, 20}}, []byteRange{{100, 50}}, false},
		{"no exclusion at the store", []byteRange{{90, 60}}, []byteRange{{100, 80}}, []byteRange{{90, 60}}, false},
		{"no store found", []byteRange{{100, 50}}, nil, []byteRange{{100, 50}}, false},
		{"no exclusions", nil, []byteRange{{100, 80}}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorded := append([]byteRange(nil), tc.recorded...)
			got, changed := adjustExclusionsForUpdate(recorded, tc.current)
			if changed != tc.changed || !sameRanges(got, tc.want) {
				t.Errorf("got %v changed=%v, want %v changed=%v", got, changed, tc.want, tc.changed)
			}
			if !sameRanges(recorded, tc.recorded) {
				t.Errorf("input was modified: %v", recorded)
			}
		})
	}
}
