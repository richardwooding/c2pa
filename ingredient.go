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
			// The document's own stores are now read as one across update
			// sections (§A.4.2.1), so a cross-section reference resolves and
			// absence is a real finding. What remains unproven is a store no
			// catalog associates — an attachment's own manifest (§A.4.3) that
			// this extractor cannot attribute, and so does not parse.
			if v.partialStores {
				v.add(StatusUnsupported, a.label,
					"ingredient references a manifest absent from the document's stores, "+
						"which also carry an unattributed store that was not evaluated", nil)
				continue
			}
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
