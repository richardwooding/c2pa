package c2pa

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Fragmented BMFF split across files (C2PA spec §A.5.4, §18.6.6). A DASH/CMAF
// asset ships as an initialization segment — 'ftyp' and 'moov', carrying the
// manifest store — and media fragments, each a 'moof'/'mdat' pair carrying the
// C2PA merkle box that places it in the assertion's Merkle tree. Nothing in
// one of those files reaches the bytes of another, which is why this needs an
// entry point that takes more than one reader; bmffhash.go holds everything
// that one file can settle on its own, and this file holds the rest.

// fragmentSet is the media fragments ValidateFragmented was given. A validator
// carries one only on that path — and even an empty one says the caller
// declared the asset fragmented, so the split-file rules apply: no flat hash,
// an initHash on every merkle-map.
type fragmentSet struct {
	readers []io.Reader
}

// ValidateFragmented validates a fragmented BMFF asset — DASH / CMAF / HLS
// fMP4 — whose initialization segment and media fragments are separate files.
// init is the initialization segment ('ftyp' + 'moov', carrying the C2PA
// manifest store in its uuid box, spec §A.5); fragments are the media
// segments ('styp'/'moof'/'mdat', each carrying a C2PA merkle uuid box), in
// any order. It reads up to ValidateMaxScan bytes from init and then from each
// fragment in turn, holding one fragment at a time, so memory is bounded by
// the initialization segment plus the largest fragment.
//
// The initialization segment receives exactly the validation Validate gives a
// single BMFF file — COSE signature, certificate chain and profile, RFC 3161
// timestamp, assertion hashes, revocation, ingredients — and only the hard
// binding differs. A c2pa.hash.bmff.v2/.v3 assertion's merkle array (spec
// §18.6.3) binds the initialization segment through each merkle-map's
// initHash, and binds every fragment through the merkle box the fragment
// carries, paired to its map by uniqueId/localId and placed in the tree by
// location. Each supplied fragment is verified against that proof; one that
// fails is a failure status whose URI ends in "#fragment=<i>", i being its
// index in fragments. The roll-up is assertion.bmffHash.match only when the
// initialization segment AND every location the trees bind — 0 through
// count-1 of each merkle-map THAT BINDS THIS INITIALIZATION SEGMENT,
// §15.12.2 — were verified; a map whose initHash belongs to another rendition
// (c2pa-rs signs several renditions into one manifest) is named as not
// evaluated here, and a fragment claiming such a map is a mismatch. Supplying a subset is
// a legitimate partial check: what was not covered is named in an
// informational general.unsupported status, and Valid stays true unless
// something supplied was disproved. No match is ever reported for a partial
// set, so Has(StatusAssertionBMFFHashMatch) keeps meaning "fully bound".
//
// Like Validate, ValidateFragmented never returns an error and never panics:
// malformed, truncated, unreadable or cancelled input is reported through
// statuses. It is the counterpart of c2pa-rs's verify_stream_segments.
func ValidateFragmented(ctx context.Context, init io.Reader, fragments []io.Reader, opts ...ValidateOption) ValidationResult {
	v := newValidator(ctx, BMFF, opts)
	v.fragments = &fragmentSet{readers: fragments}
	return v.run(init)
}

// fragmentURI qualifies the assertion's URI with which input a status is
// about: the caller's index into fragments, which is the handle they can act
// on. The fragment's location in the tree, when known, is in the explanation.
func fragmentURI(subj string, i int) string {
	return subj + "#fragment=" + strconv.Itoa(i)
}

// merkleContext is what verifying a fragment needs from the assertion: the
// exclusions to re-resolve against the fragment's own boxes, the maps to pair
// with, and the algorithm a map without one falls back to.
type merkleContext struct {
	defaultAlg string
	excl       []bmffExclusion
	maps       []merkleMap
}

// fragmentOutcomeKind is the verdict on one merkle box of one fragment.
type fragmentOutcomeKind int

const (
	fragmentMatch fragmentOutcomeKind = iota
	fragmentMismatch
	fragmentMalformed
)

// fragmentOutcome is what verifyFragmentBuffer says about one merkle box.
type fragmentOutcome struct {
	kind        fragmentOutcomeKind
	mapIndex    int // into merkleContext.maps; -1 when no map matched
	location    int // the box's leaf position; -1 when unknown
	explanation string
}

// verifyBMFFFragmented is the hard-binding step for an asset split across
// files: the assertion's merkle array against the initialization segment held
// in seg and the fragments in v.fragments, read one at a time. Statuses
// accumulate; it returns early only where later work would be meaningless.
func (v *validator) verifyBMFFFragmented(subj string, assertion map[string]any, defaultAlg string, seg bmffSegment) {
	if want, _ := assertion["hash"].([]byte); len(want) > 0 {
		// c2pa-rs refuses this too: a flat hash over the initialization segment
		// says nothing about the fragments, and a writer that emitted one did
		// not produce a fragmented binding.
		v.add(StatusAssertionBMFFHashMalformed, subj,
			"fragmented BMFF assertion carries a flat hash; an asset split across files is bound by its merkle array alone", nil)
		return
	}
	raw, present := assertion["merkle"]
	if !present || raw == nil {
		v.add(StatusAssertionBMFFHashMalformed, subj, "fragmented BMFF assertion has no merkle array", nil)
		return
	}
	maps, ok := decodeBMFFMerkle(raw)
	if !ok {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash merkle array did not decode", nil)
		return
	}
	if len(maps) == 0 {
		v.add(StatusAssertionBMFFHashMalformed, subj, "BMFF-hash merkle array is empty", nil)
		return
	}
	algs := make([]string, len(maps))
	for i, m := range maps {
		algs[i] = m.alg
		if algs[i] == "" {
			algs[i] = defaultAlg
		}
		if _, ok := hashByName(algs[i]); !ok {
			v.add(StatusAlgorithmUnsupported, subj, "unsupported merkle-map algorithm", nil)
			return
		}
		if len(m.initHash) == 0 {
			// c2pa-rs silently accepts a map without one, leaving the
			// initialization segment — where the manifest itself lives —
			// bound by nothing. Deliberately not replicated.
			v.add(StatusAssertionBMFFHashMalformed, subj,
				fmt.Sprintf("merkle map %d (uniqueId %d, localId %d) has no initHash; a fragmented asset's initialization segment must be bound",
					i, m.uniqueID, m.localID), nil)
			return
		}
		if m.count > maxMerkleLeaves {
			// count is attacker-controlled and sizes the coverage bookkeeping.
			v.add(StatusAssertionBMFFHashMalformed, subj, "merkle-map count exceeds the leaf cap", nil)
			return
		}
	}

	// The init hash once per map — c2pa-rs recomputes it per fragment. A map
	// whose initHash is not this segment's may be another rendition's: c2pa-rs
	// signs several renditions into ONE manifest, one merkle map each, and
	// writes the identical store into every initialization segment. Such a map
	// is judged only when a supplied fragment claims it — then it is a
	// mismatch, since the caller asserted these are this asset's fragments —
	// and is otherwise named as not evaluated here. No map matching at all is
	// the tampered-init verdict, reported per map and carried on: "segment
	// tampered, fragments intact" is a report worth having.
	initOK := make([]bool, len(maps))
	anyOK := false
	for i, m := range maps {
		initOK[i] = initHashMatches(v.ctx, seg, m, algs[i], len(seg.data))
		if v.ctx.Err() != nil {
			v.add(StatusGeneralError, subj, "validation cancelled while verifying the initialization segment", v.ctx.Err())
			return
		}
		anyOK = anyOK || initOK[i]
	}
	initFailed := !anyOK
	if initFailed {
		for i, m := range maps {
			v.add(StatusAssertionBMFFHashMismatch, subj,
				fmt.Sprintf("fragmented BMFF initialization segment hash does not match merkle map %d (uniqueId %d, localId %d)",
					i, m.uniqueID, m.localID), nil)
		}
	}

	mc := merkleContext{defaultAlg: defaultAlg, excl: seg.excl, maps: maps}
	covered := make([]map[int]bool, len(maps))
	for i := range covered {
		covered[i] = map[int]bool{}
	}
	before := v.failureCount()
	for i, r := range v.fragments.readers {
		uri := fragmentURI(subj, i)
		if r == nil {
			v.add(StatusGeneralError, uri, fmt.Sprintf("fragment %d: nil reader", i), nil)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(r, int64(v.cfg.maxScan)))
		if err != nil {
			v.add(StatusGeneralError, uri, fmt.Sprintf("fragment %d: read failed", i), err)
			continue
		}
		if len(data) == 0 {
			v.add(StatusGeneralError, uri, fmt.Sprintf("fragment %d: no readable input", i), nil)
			continue
		}
		if len(data) >= v.cfg.maxScan {
			// The same rule as the single-file path: truncation is never
			// misread as a mismatch or as malformed.
			v.add(StatusUnsupported, uri, fmt.Sprintf("fragment %d reached the scan cap; not verified", i), nil)
			continue
		}
		outcomes := verifyFragmentBuffer(v.ctx, mc, data)
		if v.ctx.Err() != nil {
			// A hash cut short by cancellation looks like a mismatch; report
			// the cancellation instead, and as a failure — an aborted run must
			// not come out Valid.
			v.add(StatusGeneralError, uri, fmt.Sprintf("validation cancelled while verifying fragment %d", i), v.ctx.Err())
			return
		}
		for _, o := range outcomes {
			switch o.kind {
			case fragmentMatch:
				if anyOK && !initOK[o.mapIndex] {
					// The proof holds, but against a tree this initialization
					// segment does not bind: a fragment of another rendition.
					m := maps[o.mapIndex]
					v.add(StatusAssertionBMFFHashMismatch, uri,
						fmt.Sprintf("fragment %d: merkle box names tree uniqueId %d/localId %d, whose initHash does not match this initialization segment",
							i, m.uniqueID, m.localID), nil)
					continue
				}
				// No per-fragment success entry: a match entry here would make
				// Has(StatusAssertionBMFFHashMatch) true on a partial set.
				covered[o.mapIndex][o.location] = true
			case fragmentMismatch:
				v.add(StatusAssertionBMFFHashMismatch, uri, fmt.Sprintf("fragment %d: %s", i, o.explanation), nil)
			case fragmentMalformed:
				v.add(StatusAssertionBMFFHashMalformed, uri, fmt.Sprintf("fragment %d: %s", i, o.explanation), nil)
			}
		}
	}

	if initFailed || v.failureCount() > before {
		return // the failure is the verdict; coverage would only be noise on top
	}
	// Coverage is over the maps that bind THIS initialization segment; the
	// others are another rendition's and are named, not counted.
	var bound []merkleMap
	var boundCovered []map[int]bool
	var foreign []string
	for i, m := range maps {
		if initOK[i] {
			bound = append(bound, m)
			boundCovered = append(boundCovered, covered[i])
		} else {
			foreign = append(foreign, fmt.Sprintf("uniqueId %d/localId %d", m.uniqueID, m.localID))
		}
	}
	verified, total, missing := fragmentCoverage(bound, boundCovered)
	if missing == "" {
		v.add(StatusAssertionBMFFHashMatch, subj,
			fmt.Sprintf("fragmented BMFF hash matches: initialization segment and all %d fragments verified", total), nil)
	} else {
		detail := fmt.Sprintf("initialization segment and %d of %d fragments verified; not verified: %s", verified, total, missing)
		if len(v.fragments.readers) == 0 {
			detail += " (no fragments supplied)"
		}
		v.add(StatusUnsupported, subj, "fragmented BMFF hash only partly verified: "+detail, nil)
	}
	if len(foreign) > 0 {
		v.add(StatusUnsupported, subj,
			fmt.Sprintf("merkle maps %s bind other initialization segments (other renditions of this asset) and were not evaluated here",
				strings.Join(foreign, ", ")), nil)
	}
}

// verifyFragmentBuffer checks one fragment file against the assertion. Every
// C2PA merkle box it carries is paired with its map by uniqueId/localId; the
// whole fragment is hashed from its own offset 0 with the exclusions
// re-resolved against its own boxes — so the mandatory "/uuid" exclusion
// removes the fragment's own merkle box — and the hash is folded up the box's
// proof to the row the map stores. One outcome per merkle box (a multiplexed
// fragment carries one per track), or a single malformed outcome when the
// fragment cannot be parsed or has none. It never panics. A hash cut short by
// cancellation comes out as a mismatch, so the caller checks ctx before
// reporting anything.
func verifyFragmentBuffer(ctx context.Context, mc merkleContext, frag []byte) []fragmentOutcome {
	malformed := func(explanation string) []fragmentOutcome {
		return []fragmentOutcome{{kind: fragmentMalformed, mapIndex: -1, location: -1, explanation: explanation}}
	}
	seg, ok := newBMFFSegment(ctx, frag, mc.excl)
	if !ok {
		return malformed("no parseable BMFF box structure")
	}
	boxes, ok := bmffMerkleBoxes(seg.data, seg.top)
	if !ok {
		return malformed("C2PA merkle box did not decode")
	}
	if len(boxes) == 0 {
		return malformed("no C2PA merkle box")
	}
	// The fragment's hash does not depend on which box is being checked, so
	// it is computed once per algorithm.
	sums := map[string][]byte{}
	fragmentHash := func(alg string) ([]byte, bool) {
		if sum, done := sums[alg]; done {
			return sum, true
		}
		h, ok := hashByName(alg)
		if !ok {
			return nil, false
		}
		hashBMFFTopLevel(ctx, seg.data, seg.top, seg.ranges, h)
		sums[alg] = h.Sum(nil)
		return sums[alg], true
	}
	out := make([]fragmentOutcome, 0, len(boxes))
	for _, mb := range boxes {
		o := fragmentOutcome{mapIndex: -1, location: mb.location}
		for i, m := range mc.maps {
			if m.uniqueID == mb.uniqueID && m.localID == mb.localID {
				o.mapIndex = i
				break
			}
		}
		if o.mapIndex < 0 {
			o.kind = fragmentMismatch
			o.explanation = fmt.Sprintf("merkle box uniqueId %d/localId %d matches no merkle map; not a fragment of this asset",
				mb.uniqueID, mb.localID)
			out = append(out, o)
			continue
		}
		m := mc.maps[o.mapIndex]
		if mb.location >= m.count {
			o.kind = fragmentMalformed
			o.explanation = fmt.Sprintf("location %d is outside the tree's 0..%d", mb.location, m.count-1)
			out = append(out, o)
			continue
		}
		alg := m.alg
		if alg == "" {
			alg = mc.defaultAlg
		}
		sum, ok := fragmentHash(alg)
		if !ok {
			o.kind = fragmentMalformed
			o.explanation = "unsupported merkle-map algorithm"
			out = append(out, o)
			continue
		}
		ok, malformed := merkleProve(alg, m, sum, mb.location, mb.hashes)
		switch {
		case malformed:
			o.kind = fragmentMalformed
			o.explanation = fmt.Sprintf("location %d carries a merkle proof that does not fit the tree", mb.location)
		case !ok:
			o.kind = fragmentMismatch
			o.explanation = fmt.Sprintf("location %d hash does not match its merkle proof", mb.location)
		default:
			o.kind = fragmentMatch
		}
		out = append(out, o)
	}
	return out
}

// fragmentCoverage reports how many of the leaves the maps bind were proven
// and names the rest. §15.12.2 has each tree's locations run 0..count-1, so
// what is missing is exactly the locations no supplied fragment covered.
func fragmentCoverage(maps []merkleMap, covered []map[int]bool) (verified, total int, missing string) {
	var parts []string
	for i, m := range maps {
		total += m.count
		verified += len(covered[i])
		if len(covered[i]) == m.count {
			continue
		}
		runs := missingRuns(m.count, covered[i])
		if len(maps) == 1 {
			parts = append(parts, "locations "+runs)
		} else {
			parts = append(parts, fmt.Sprintf("tree uniqueId %d/localId %d locations %s", m.uniqueID, m.localID, runs))
		}
	}
	return verified, total, strings.Join(parts, "; ")
}

// maxCoverageRuns caps how many runs of missing locations a status names, so
// a million-leaf tree cannot turn one status line into a megabyte.
const maxCoverageRuns = 8

// missingRuns formats the locations of 0..count-1 absent from covered as
// compacted runs — "0..2, 5" — naming at most maxCoverageRuns before "…".
func missingRuns(count int, covered map[int]bool) string {
	var b strings.Builder
	runs := 0
	for loc := 0; loc < count; {
		if covered[loc] {
			loc++
			continue
		}
		start := loc
		for loc < count && !covered[loc] {
			loc++
		}
		if runs == maxCoverageRuns {
			b.WriteString(", …")
			break
		}
		if runs > 0 {
			b.WriteString(", ")
		}
		if loc-1 == start {
			fmt.Fprintf(&b, "%d", start)
		} else {
			fmt.Fprintf(&b, "%d..%d", start, loc-1)
		}
		runs++
	}
	return b.String()
}
