package c2pa

import (
	"embed"
	"encoding/json"
	"sync"
)

// The C2PA soft binding algorithm list (spec §9.3.2): the authoritative set of
// identifiers a c2pa.soft-binding assertion's "alg" may name. Embedded as a
// point-in-time snapshot, exactly as the trust lists are — see
// softbindings/README.md for the refresh procedure and for why staleness here
// degrades a reported FIELD rather than a verdict.

//go:embed softbindings/softbinding-algorithm-list.json
var embeddedSoftBindingFS embed.FS

// SoftBindingListSnapshot is the date of the embedded C2PA soft binding
// algorithm list snapshot, in RFC 3339 date form.
//
// It matters because the list grows: a caller acting on
// SoftBinding.AlgorithmRegistered == false needs to know whether the answer is
// "nobody registered this" or "we have not looked since this date". Validate
// names it in the explanation of softBinding.alg.unlisted for the same reason.
const SoftBindingListSnapshot = "2026-08-20"

// SoftBindingAlgorithm is one entry of the C2PA soft binding algorithm list.
// It describes an algorithm this library can NAME but not compute: c2pa
// implements no soft binding algorithm (see SoftBinding).
type SoftBindingAlgorithm struct {
	// Identifier is the registry's own numeric id, unique across the list.
	Identifier int
	// Alg is the identifier that appears on the wire, in a soft binding
	// assertion's "alg" or a claim's "alg_soft" — e.g. "io.iscc.v0".
	Alg string
	// Type is "watermark" (embedded in the content) or "fingerprint"
	// (computed from it).
	Type string
	// Description and DateEntered are the registry's own metadata.
	Description string
	DateEntered string
	// DecodedMediaTypes names the media FAMILIES the algorithm applies to
	// ("image", "audio", "video", "text", "application"), while
	// EncodedMediaTypes names full media types ("audio/mpeg", …). The registry
	// uses two keys with two vocabularies and an entry may carry either or
	// both, so both are surfaced as stored rather than merged.
	DecodedMediaTypes []string
	EncodedMediaTypes []string
	// ResolutionAPIs are the C2PA Soft Binding Resolution API endpoints the
	// registrant published, if any: where a caller could ask "which manifests
	// match this value". This library does not call them.
	ResolutionAPIs []string
}

// softBindingEntry is the wire shape of one registry entry. Only the fields the
// library uses are modelled; the list is third-party and will grow more.
type softBindingEntry struct {
	Identifier        int      `json:"identifier"`
	Alg               string   `json:"alg"`
	Type              string   `json:"type"`
	DecodedMediaTypes []string `json:"decodedMediaTypes"`
	EncodedMediaTypes []string `json:"encodedMediaTypes"`
	ResolutionAPIs    []string `json:"softBindingResolutionApis"`
	EntryMetadata     struct {
		Description string `json:"description"`
		DateEntered string `json:"dateEntered"`
	} `json:"entryMetadata"`
}

var (
	softBindingOnce  sync.Once
	softBindingAlgs  []SoftBindingAlgorithm
	softBindingByAlg map[string]SoftBindingAlgorithm
)

// loadSoftBindingList parses the embedded snapshot once. A parse failure leaves
// both the slice and the map empty rather than panicking — never panicking is
// the contract, and an empty list degrades every algorithm to "unlisted", which
// is informational. TestSoftBindingRegistry makes such a failure loud instead.
func loadSoftBindingList() {
	data, err := embeddedSoftBindingFS.ReadFile("softbindings/softbinding-algorithm-list.json")
	if err != nil {
		return
	}
	var entries []softBindingEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	algs := make([]SoftBindingAlgorithm, 0, len(entries))
	byAlg := make(map[string]SoftBindingAlgorithm, len(entries))
	for _, e := range entries {
		if e.Alg == "" {
			continue
		}
		a := SoftBindingAlgorithm{
			Identifier:        e.Identifier,
			Alg:               e.Alg,
			Type:              e.Type,
			Description:       e.EntryMetadata.Description,
			DateEntered:       e.EntryMetadata.DateEntered,
			DecodedMediaTypes: e.DecodedMediaTypes,
			EncodedMediaTypes: e.EncodedMediaTypes,
			ResolutionAPIs:    e.ResolutionAPIs,
		}
		algs = append(algs, a)
		if _, seen := byAlg[e.Alg]; !seen {
			byAlg[e.Alg] = a
		}
	}
	softBindingAlgs, softBindingByAlg = algs, byAlg
}

// SoftBindingAlgorithms returns the embedded C2PA soft binding algorithm list,
// in the registry's own order. The result is a copy: the list is package data,
// and a caller mutating it must not change what Validate reports.
//
// This is a point-in-time snapshot (softbindings/README.md records which), so
// an algorithm's absence is not proof it was never registered.
func SoftBindingAlgorithms() []SoftBindingAlgorithm {
	softBindingOnce.Do(loadSoftBindingList)
	out := make([]SoftBindingAlgorithm, len(softBindingAlgs))
	copy(out, softBindingAlgs)
	return out
}

// LookupSoftBindingAlgorithm returns the registry entry for an algorithm
// identifier as it appears on the wire. ok is false when this snapshot does not
// name it — which means "not in this snapshot", not "not registered": see
// softbindings/README.md.
func LookupSoftBindingAlgorithm(alg string) (SoftBindingAlgorithm, bool) {
	softBindingOnce.Do(loadSoftBindingList)
	a, ok := softBindingByAlg[alg]
	return a, ok
}
