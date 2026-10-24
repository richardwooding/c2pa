package c2pa

import (
	"slices"
	"strings"
)

// Claim-structure status codes (§15.2): the shape of the claim box itself and
// of the assertions it references, checked before any signature or hash is
// trusted.
const (
	StatusClaimCBORInvalid           StatusCode = "claim.cbor.invalid"
	StatusClaimMalformed             StatusCode = "claim.malformed"
	StatusClaimHardBindingsMissing   StatusCode = "claim.hardBindings.missing"
	StatusAssertionCBORInvalid       StatusCode = "assertion.cbor.invalid"
	StatusAssertionIngredientMalform StatusCode = "assertion.ingredient.malformed"
)

func init() {
	for _, c := range []StatusCode{
		StatusClaimCBORInvalid, StatusClaimMalformed, StatusClaimHardBindingsMissing,
		StatusAssertionCBORInvalid, StatusAssertionIngredientMalform,
	} {
		statusSeverity[c] = SeverityFailure
	}
}

// hardBindingLabels are the assertions that bind a claim to its asset's bytes.
var hardBindingLabels = []string{
	"c2pa.hash.data", "c2pa.hash.boxes", "c2pa.hash.bmff",
	"c2pa.hash.bmff.v2", "c2pa.hash.bmff.v3", "c2pa.hash.multi-asset",
}

func isClaimV2(m *parsedManifest) bool {
	_, ok := m.claim["created_assertions"]
	return ok || m.claim["instanceID"] != nil && m.claim["assertions"] == nil
}

// checkClaimStructure records claim.cbor.invalid, claim.malformed and
// claim.hardBindings.missing for the manifest's claim box, and the assertion
// well-formedness failures (assertion.cbor.invalid,
// assertion.ingredient.malformed). It reports whether the claim is
// structurally sound enough to go on with hard-binding evaluation.
func (v *validator) checkClaimStructure(m *parsedManifest, uri string) (hardBindingsOK bool) {
	hardBindingsOK = true
	if m.claimBytes != nil && m.claim == nil {
		v.add(StatusClaimCBORInvalid, uri, "claim box is not valid CBOR", nil)
		return false
	}
	if m.claim != nil {
		v2 := isClaimV2(m)
		required := []string{"instanceID", "signature"}
		if v2 {
			required = append(required, "claim_generator_info", "created_assertions")
		} else {
			required = append(required, "assertions")
		}
		var missing []string
		for _, k := range required {
			if m.claim[k] == nil {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			v.add(StatusClaimMalformed, uri, "claim is missing required field(s): "+strings.Join(missing, ", "), nil)
		}
		// A hard binding present in the store but not covered by the claim binds
		// nothing the signature vouches for. A manifest with no hard-binding
		// assertion at all is hardBinding.missing instead, reported where the
		// binding is evaluated; an update manifest legitimately carries none.
		if !m.update && len(missing) == 0 && hasHardBindingAssertion(m) {
			referenced := false
			for _, e := range claimAssertionEntries(m.claim) {
				if l := assertionLabelBase(assertionLabelFromURL(e.url)); slices.Contains(hardBindingLabels, l) {
					referenced = true
					break
				}
			}
			if !referenced {
				v.add(StatusClaimHardBindingsMissing, uri, "claim references no hard-binding assertion", nil)
				hardBindingsOK = false
			}
		}
	}
	for _, a := range m.assertions {
		if a.tbox != "cbor" {
			continue
		}
		var val any
		if decMode.Unmarshal(a.data, &val) != nil {
			v.add(StatusAssertionCBORInvalid, uri+"/"+a.label, "assertion content is not valid CBOR", nil)
			continue
		}
		if strings.HasPrefix(a.label, "c2pa.ingredient.v") {
			if im, ok := val.(map[string]any); ok && im["activeManifest"] != nil && im["validationResults"] == nil {
				v.add(StatusAssertionIngredientMalform, uri+"/"+a.label,
					"ingredient assertion names an active manifest but carries no validationResults", nil)
			}
		}
	}
	return hardBindingsOK
}

// assertionLabelBase strips a multiple-instance suffix ("__1") from a label.
func assertionLabelBase(label string) string {
	if i := strings.Index(label, "__"); i > 0 {
		return label[:i]
	}
	return label
}

func hasHardBindingAssertion(m *parsedManifest) bool {
	for _, a := range m.assertions {
		if slices.Contains(hardBindingLabels, assertionLabelBase(a.label)) {
			return true
		}
	}
	return false
}
