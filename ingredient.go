package c2pa

import "strings"

// validateIngredients recursively validates the nested manifests referenced by
// this manifest's c2pa.ingredient assertions. Recursion is bounded by
// cfg.maxIngredientDepth and by a visited-set of manifest labels so a cyclic or
// adversarial ingredient graph terminates instead of recursing forever. A
// referenced manifest absent from the store is a failure; a cycle is reported
// informationally and stops the descent.
func (v *validator) validateIngredients(m *parsedManifest, store *parsedStore, depth int) {
	if depth >= v.cfg.maxIngredientDepth {
		return
	}
	byLabel := store.byLabel()
	for _, a := range m.assertions {
		if !strings.Contains(a.label, "c2pa.ingredient") {
			continue
		}
		var ing map[string]any
		if decMode.Unmarshal(a.data, &ing) != nil {
			continue
		}
		ref := ingredientManifestURL(ing)
		if ref == "" {
			continue // a plain ingredient with no embedded manifest to validate
		}
		child := resolveManifest(ref, byLabel)
		if child == nil {
			// Every store the carrier holds is now resolved against as one
			// (§A.4.2.1), update sections and object-level manifests included,
			// so a reference that lands nowhere is a real finding rather than
			// something this extractor merely failed to look at.
			v.add(StatusIngredientManifestMismatch, a.label, "ingredient references a manifest not present in the store", nil)
			continue
		}
		if v.visited[child.label] {
			v.add(StatusUnsupported, a.label, "ingredient manifest cycle detected; descent stopped", nil)
			continue
		}
		before := v.failureCount()
		v.validateManifest(child, store, depth+1)
		if v.failureCount() == before {
			v.add(StatusIngredientManifestValidated, a.label, "ingredient manifest validated", nil)
		}
	}
}

// byLabel indexes the store's manifests by their JUMBF label (URN).
func (s *parsedStore) byLabel() map[string]*parsedManifest {
	out := make(map[string]*parsedManifest, len(s.manifests))
	for _, m := range s.manifests {
		out[m.label] = m
	}
	return out
}

// failureCount returns the number of failure statuses recorded so far, used to
// tell whether a recursive ingredient validation introduced any new failures.
func (v *validator) failureCount() int {
	n := 0
	for i := range v.res.Statuses {
		if v.res.Statuses[i].Severity == SeverityFailure {
			n++
		}
	}
	return n
}

// ingredientManifestURL extracts the JUMBF URL of an ingredient's referenced
// C2PA manifest, if any. C2PA spells the field c2pa_manifest (and, in some
// versions, activeManifest); both are hashed_uri maps carrying a url.
func ingredientManifestURL(ing map[string]any) string {
	for _, key := range []string{"c2pa_manifest", "activeManifest"} {
		if hu, ok := ing[key].(map[string]any); ok {
			if url, ok := hu["url"].(string); ok && url != "" {
				return url
			}
		}
	}
	return ""
}

// resolveManifest finds the store manifest a reference URL points to, matching
// by label substring (handling the self#jumbf=/c2pa/<label>/… URI forms).
func resolveManifest(ref string, byLabel map[string]*parsedManifest) *parsedManifest {
	if m, ok := byLabel[ref]; ok {
		return m
	}
	for label, m := range byLabel {
		if label != "" && strings.Contains(ref, label) {
			return m
		}
	}
	return nil
}

// verifyUpdateManifest checks an Update Manifest (spec §11.2.3) and hands the
// hard binding to the manifest it updates.
//
// An update manifest records assertions added WITHOUT changing the content, so
// it carries no hard binding of its own: §11.2.3 forbids c2pa.hash.data,
// c2pa.hash.boxes, c2pa.hash.collection.data and both c2pa.hash.bmff versions,
// along with a thumbnail and any action beyond the four that leave content
// alone. Treating a missing binding as hardBinding.missing therefore failed
// every correctly formed update manifest.
//
// What does bind the content is the manifest being updated, named by the single
// parentOf ingredient §11.2.3 requires. That manifest describes THESE bytes —
// unlike an ordinary ingredient's, which describes the ingredient's own — so
// its hard binding is verified against the asset rather than skipped.
func (v *validator) verifyUpdateManifest(m *parsedManifest, store *parsedStore, uri string) {
	for _, a := range m.assertions {
		switch {
		case isHardBindingLabel(a.label):
			v.add(StatusManifestUpdateInvalid, uri,
				"update manifest carries the hard binding "+a.label+
					", but it changed no content", nil)
			return
		case strings.Contains(a.label, "c2pa.thumbnail"):
			v.add(StatusManifestUpdateInvalid, uri,
				"update manifest carries a thumbnail assertion, which implies a content change", nil)
			return
		case isActionsLabel(a.label):
			if bad, ok := disallowedUpdateAction(a.data); !ok {
				v.add(StatusManifestUpdateInvalid, uri,
					"update manifest declares the action "+bad+
						", which is not one an update may perform", nil)
				return
			}
		}
	}

	parents := v.parentIngredients(m)
	if len(parents) != 1 {
		v.add(StatusManifestUpdateWrongParents, uri,
			"update manifest must name exactly one parentOf ingredient, the manifest it updates", nil)
		return
	}
	parent := resolveManifest(parents[0], store.byLabel())
	if parent == nil {
		v.add(StatusIngredientManifestMismatch, uri,
			"update manifest's parentOf ingredient names a manifest not present in the store", nil)
		return
	}
	// The parent's binding covers this asset, so it is checked here rather than
	// skipped the way an ingredient's is — and recorded, so the ingredient walk
	// that reaches the same manifest a moment later does not also report it as
	// unevaluated.
	if v.hardBound == nil {
		v.hardBound = map[string]bool{}
	}
	v.hardBound[parent.label] = true
	v.verifyHardBinding(parent, parent.label)
}

// parentIngredients returns the manifest URLs of every ingredient whose
// relationship is parentOf.
func (v *validator) parentIngredients(m *parsedManifest) []string {
	var out []string
	for _, a := range m.assertions {
		if !strings.Contains(a.label, "c2pa.ingredient") {
			continue
		}
		var ing map[string]any
		if decMode.Unmarshal(a.data, &ing) != nil {
			continue
		}
		if rel, _ := ing["relationship"].(string); rel != "parentOf" {
			continue
		}
		if ref := ingredientManifestURL(ing); ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

// isHardBindingLabel reports whether a label names one of the hard-binding
// assertions §11.2.3 forbids an update manifest from carrying.
func isHardBindingLabel(label string) bool {
	switch label {
	case "c2pa.hash.data", "c2pa.hash.boxes", "c2pa.hash.collection.data",
		"c2pa.hash.bmff", "c2pa.hash.bmff.v2", "c2pa.hash.bmff.v3",
		"c2pa.hash.multi-asset":
		return true
	}
	return false
}

// isActionsLabel reports whether a label names an actions assertion, in either
// spelling.
func isActionsLabel(label string) bool {
	return label == "c2pa.actions" || strings.HasPrefix(label, "c2pa.actions.v")
}

// updateManifestActions are the only actions §11.2.3 permits an update manifest
// to declare: the four that add or remove metadata without touching content.
var updateManifestActions = map[string]bool{
	"c2pa.edited.metadata": true,
	"c2pa.opened":          true,
	"c2pa.published":       true,
	"c2pa.redacted":        true,
}

// disallowedUpdateAction reports the first action an update manifest may not
// perform, or ok when every declared action is permitted. An assertion that
// does not decode declares nothing and is left to the hash checks.
//
// This follows the spec, which permits the four listed actions; c2pa-rs's own
// status-code documentation describes an update manifest containing ANY actions
// assertion as invalid, which would reject files §11.2.3 allows.
func disallowedUpdateAction(data []byte) (string, bool) {
	var assertion map[string]any
	if decMode.Unmarshal(data, &assertion) != nil {
		return "", true
	}
	list, _ := assertion["actions"].([]any)
	for _, item := range list {
		am, ok := item.(map[string]any)
		if !ok {
			continue
		}
		action, _ := am["action"].(string)
		if action != "" && !updateManifestActions[action] {
			return action, false
		}
	}
	return "", true
}
