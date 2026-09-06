package c2pa

import (
	"bytes"
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ingredientAssertion builds a c2pa.ingredient assertion CBOR referencing the
// given manifest label via its c2pa_manifest hashed_uri.
func ingredientAssertion(t *testing.T, refLabel string) rawAssertion {
	t.Helper()
	b, err := cbor.Marshal(map[string]any{
		"relationship": "componentOf",
		"c2pa_manifest": map[string]any{
			"url":  "self#jumbf=/c2pa/" + refLabel,
			"hash": []byte{0x00},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rawAssertion{label: "c2pa.ingredient", tbox: "cbor", data: b}
}

// TestValidate_IngredientCycle ensures a cyclic ingredient graph (A→B→A)
// terminates via the visited-set guard rather than recursing forever, and that
// the cycle is reported.
func TestValidate_IngredientCycle(t *testing.T) {
	mA := &parsedManifest{label: "urn:A", assertions: []rawAssertion{ingredientAssertion(t, "urn:B")}}
	mB := &parsedManifest{label: "urn:B", assertions: []rawAssertion{ingredientAssertion(t, "urn:A")}}
	store := &parsedStore{manifests: []*parsedManifest{mA, mB}}

	v := testValidator(false, nil)
	v.data = []byte("x")
	v.validateManifest(mA, store, 0) // must terminate

	if !v.visited["urn:A"] || !v.visited["urn:B"] {
		t.Errorf("expected both manifests visited; visited=%v", v.visited)
	}
	if !v.res.Has(StatusUnsupported) {
		t.Errorf("expected a cycle-detected status; got %v", codes(v.res))
	}
}

// TestValidate_IngredientDepthCap ensures recursion stops at the configured
// maximum ingredient depth.
func TestValidate_IngredientDepthCap(t *testing.T) {
	// Chain A→B→C; cap depth at 1 so C is never visited.
	mA := &parsedManifest{label: "urn:A", assertions: []rawAssertion{ingredientAssertion(t, "urn:B")}}
	mB := &parsedManifest{label: "urn:B", assertions: []rawAssertion{ingredientAssertion(t, "urn:C")}}
	mC := &parsedManifest{label: "urn:C"}
	store := &parsedStore{manifests: []*parsedManifest{mA, mB, mC}}

	v := testValidator(false, nil)
	v.cfg.maxIngredientDepth = 1
	v.validateManifest(mA, store, 0)

	if !v.visited["urn:B"] {
		t.Errorf("expected B visited at depth 1")
	}
	if v.visited["urn:C"] {
		t.Errorf("expected C NOT visited (depth cap); visited=%v", v.visited)
	}
}

// TestValidate_IngredientMissing reports a failure when an ingredient references
// a manifest absent from the store.
func TestValidate_IngredientMissing(t *testing.T) {
	mA := &parsedManifest{label: "urn:A", assertions: []rawAssertion{ingredientAssertion(t, "urn:GONE")}}
	store := &parsedStore{manifests: []*parsedManifest{mA}}

	v := testValidator(false, nil)
	v.validateIngredients(mA, store, 0)
	if !v.res.Has(StatusIngredientManifestMismatch) {
		t.Errorf("expected ingredient.manifest.mismatch; got %v", codes(v.res))
	}
}

// TestValidate_FixtureIngredientNoRecursion confirms the real fixture's
// parentOf ingredient (which carries no nested manifest) does not produce an
// ingredient failure.
func TestValidate_FixtureIngredientNoRecursion(t *testing.T) {
	pool, data := fixtureSigningPool(t)
	tsaPool := fixtureTimestampPool(t)
	r := Validate(context.Background(), JPEG, bytes.NewReader(data), WithSigningTrust(pool), WithTimestampTrust(tsaPool))
	if r.Has(StatusIngredientManifestMismatch) {
		t.Errorf("fixture ingredient should not fail; got %v", codes(r))
	}
	if !r.Valid {
		t.Errorf("expected Valid=true; first failure=%+v", r.FirstFailure())
	}
}
