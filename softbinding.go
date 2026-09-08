package c2pa

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Soft binding assertions (spec §18.10, label "c2pa.soft-binding" — a HYPHEN,
// unlike every c2pa.hash.* label; the underscore spelling circulates and is
// wrong). A soft binding is a perceptual identifier — a watermark embedded in
// the content, or a fingerprint computed from it — so that content whose bits
// have changed can still be matched to the manifest that describes it, and so
// that a manifest stripped from an asset can be recovered from a provenance
// store elsewhere (§9.3.1).
//
// This library READS and REPORTS them and computes none of them, which is the
// honest position: verifying a soft binding means recomputing the algorithm
// over the asset and comparing within a TOLERANCE, and a tolerance is a policy
// rather than a fact. So there is no Matched field and no Valid field here —
// only WellFormed, which is about the structure — and a well-formed soft
// binding earns one informational status saying it was not evaluated.
//
// A soft binding is never a content binding: §9.1 allows zero or more of them
// but the hard binding is what proves THESE bytes, which is what
// ValidationResult.Binding answers. verifySoftBindings therefore runs AFTER the
// hard-binding step, so it structurally cannot participate in the first-wins
// bind decision.

// softBindingLabel is the assertion label; instances beyond the first take the
// standard "__N" suffix.
const softBindingLabel = "c2pa.soft-binding"

// isSoftBindingLabel reports whether an assertion label is a soft binding:
// c2pa.soft-binding or a multiple-instance form c2pa.soft-binding__N.
func isSoftBindingLabel(label string) bool {
	return label == softBindingLabel || strings.HasPrefix(label, softBindingLabel+"__")
}

// SoftBinding is one c2pa.soft-binding assertion of a manifest, AS PRESENTED.
//
// It says "content matching this value under this algorithm is the content this
// manifest describes". Nothing here is proven: this library implements no soft
// binding algorithm, so it neither confirms nor refutes a match. Hand Algorithm
// and Blocks[i].Value to a matcher of your own, or to a C2PA Soft Binding
// Resolution API.
//
// What IS proven, and by a different step, is that these assertion bytes are
// the ones the claim signed — assertion.hashedURI.match at this URI.
type SoftBinding struct {
	// Label is the assertion label, "c2pa.soft-binding" or an instance form.
	Label string
	// URI is "<manifest label>/<Label>", where this assertion's statuses are
	// recorded.
	URI string

	// Algorithm is the resolved identifier: the assertion's own "alg", else the
	// enclosing claim's "alg_soft" (§10.2.1). PRESENTED — a name, not a
	// verified property of the value bytes. Empty only when neither is present,
	// which the spec calls invalid (softBinding.alg.missing).
	Algorithm string
	// AlgorithmFromClaim reports that Algorithm came from the claim's alg_soft,
	// this assertion carrying none of its own.
	AlgorithmFromClaim bool
	// AlgorithmRegistered reports that Algorithm appears in this build's
	// EMBEDDED SNAPSHOT of the C2PA soft binding algorithm list. It is derived
	// from our data rather than presented by the manifest, and false means "not
	// in this snapshot" — which may mean "registered upstream since", since the
	// list grows. See SoftBindingListSnapshot and softbindings/README.md, and
	// note that §9.3.2 requires a listed algorithm while this library reports
	// an unlisted one informationally rather than failing it.
	AlgorithmRegistered bool
	// AlgorithmType is "watermark" or "fingerprint" from that same list, or ""
	// when the algorithm is not in this snapshot. Also from our data.
	AlgorithmType string

	// Name is the optional human-readable "name". PRESENTED free text with no
	// meaning to this library.
	Name string
	// Params is the optional "alg-params", verbatim and uninterpreted. The CDDL
	// says a byte string; c2pa-rs models a text string, so what a producer
	// wrote may be either (see CLAUDE.md).
	Params []byte
	// URL is the optional "url", which the spec marks UNUSED AND DEPRECATED. It
	// is presented verbatim and NEVER dereferenced: a manifest-controlled
	// outbound request would be an SSRF.
	URL string

	// Blocks are the algorithm's outputs, in stored order; at least one when
	// WellFormed.
	Blocks []SoftBindingBlock

	// WellFormed reports that the assertion decoded and satisfied the
	// structural rules of the spec's CDDL — that no softBinding.* failure was
	// recorded for it. It says NOTHING about whether any content matches.
	//
	// Named WellFormed rather than Valid deliberately: Identity.Valid means a
	// signature verified, and nothing is verified here.
	WellFormed bool
}

// SoftBindingBlock is one block of a soft binding: a value, and the part of the
// content it covers.
type SoftBindingBlock struct {
	// Value is the block's "value" byte string, verbatim — the algorithm's
	// output as PRESENTED, opaque to this library.
	Value []byte
	// Scope is what part of the content the value covers.
	Scope SoftBindingScope
}

// SoftBindingScope is the part of the content a block covers, AS PRESENTED.
// Every field is optional in the spec's CDDL and the spec does not say what an
// empty scope means, so an all-zero SoftBindingScope is reported as found
// rather than interpreted as "the whole asset".
type SoftBindingScope struct {
	// Extent is the "extent" byte string, verbatim — DEPRECATED by the spec in
	// favour of Region.
	Extent []byte
	// Timespan is the "timespan" range in milliseconds from the start of a
	// temporal asset, nil when absent. Start and End are as PRESENTED: the
	// spec gives no ordering rule, so End < Start is reported, not rejected.
	Timespan *SoftBindingTimespan
	// Region is the "region" region-of-interest as RAW CBOR, exactly as stored,
	// nil when absent. Deliberately not decoded: this library evaluates no
	// region, and modelling the structure would imply that it did.
	Region []byte
}

// SoftBindingTimespan is a millisecond range of a temporal asset.
type SoftBindingTimespan struct {
	Start uint64
	End   uint64
}

// softBindingDecoded is the wire form of a soft binding assertion.
type softBindingDecoded struct {
	alg      string
	hasAlg   bool
	name     string
	params   []byte
	url      string
	pad      []byte
	pad2     []byte
	hasPad2  bool
	blocks   []SoftBindingBlock
	deprecat []string // deprecated fields present, for the explanation
}

// decodeSoftBinding decodes a soft binding assertion, enforcing the structural
// rules of the spec's CDDL: a map with a "blocks" array of at least one map,
// each carrying a "scope" map and a byte-string "value"; a byte-string "pad";
// and correct types for the optional fields. Unknown keys are ignored.
//
// It reports structure only. Whether the algorithm resolves, whether it is
// registered, and whether the padding is zero-filled are the validator's job,
// because each is a separate status.
func decodeSoftBinding(data []byte) (softBindingDecoded, error) {
	var sb softBindingDecoded
	var top map[string]cbor.RawMessage
	// identityDecMode, not decMode: duplicate map keys must be refused, since
	// this decodes in two stages (raw keys, then values) and fxamacker keeps
	// the LAST duplicate for a map and the FIRST for a struct — so without it
	// the two stages could check one value and present another.
	if err := identityDecMode.Unmarshal(data, &top); err != nil {
		return sb, fmt.Errorf("soft binding is not a CBOR map: %w", err)
	}

	rawBlocks, ok := top["blocks"]
	if !ok {
		return sb, errors.New(`soft binding lacks "blocks"`)
	}
	if _, ok := top["pad"]; !ok {
		return sb, errors.New(`soft binding lacks "pad"`)
	}
	for _, key := range []string{"pad", "pad2", "alg-params", "extent"} {
		if raw, present := top[key]; present && !isCBORByteString(raw) {
			return sb, fmt.Errorf("soft binding %q is not a byte string", key)
		}
	}
	if err := identityDecMode.Unmarshal(top["pad"], &sb.pad); err != nil {
		return sb, fmt.Errorf(`soft binding "pad" did not decode: %w`, err)
	}
	if raw, present := top["pad2"]; present {
		if err := identityDecMode.Unmarshal(raw, &sb.pad2); err != nil {
			return sb, fmt.Errorf(`soft binding "pad2" did not decode: %w`, err)
		}
		sb.hasPad2 = true
	}
	if raw, present := top["alg"]; present {
		if err := identityDecMode.Unmarshal(raw, &sb.alg); err != nil {
			return sb, fmt.Errorf(`soft binding "alg" is not a text string: %w`, err)
		}
		if sb.alg == "" {
			return sb, errors.New(`soft binding "alg" is empty`)
		}
		sb.hasAlg = true
	}
	if raw, present := top["name"]; present {
		if err := identityDecMode.Unmarshal(raw, &sb.name); err != nil {
			return sb, fmt.Errorf(`soft binding "name" is not a text string: %w`, err)
		}
	}
	if raw, present := top["alg-params"]; present {
		if err := identityDecMode.Unmarshal(raw, &sb.params); err != nil {
			return sb, fmt.Errorf(`soft binding "alg-params" did not decode: %w`, err)
		}
	}
	if raw, present := top["url"]; present {
		if err := identityDecMode.Unmarshal(raw, &sb.url); err != nil {
			return sb, fmt.Errorf(`soft binding "url" is not a text string: %w`, err)
		}
		sb.deprecat = append(sb.deprecat, "url")
	}

	var blocks []cbor.RawMessage
	if err := identityDecMode.Unmarshal(rawBlocks, &blocks); err != nil {
		return sb, fmt.Errorf(`soft binding "blocks" is not an array: %w`, err)
	}
	if len(blocks) == 0 {
		return sb, errors.New(`soft binding "blocks" is empty`)
	}
	for i, rawBlock := range blocks {
		block, deprecated, err := decodeSoftBindingBlock(rawBlock, i)
		if err != nil {
			return sb, err
		}
		sb.deprecat = append(sb.deprecat, deprecated...)
		sb.blocks = append(sb.blocks, block)
	}
	return sb, nil
}

// decodeSoftBindingBlock decodes one soft-binding-block-map: a required
// byte-string "value" and a required "scope" map whose own fields are all
// optional.
func decodeSoftBindingBlock(raw cbor.RawMessage, i int) (SoftBindingBlock, []string, error) {
	var block SoftBindingBlock
	var deprecated []string
	var m map[string]cbor.RawMessage
	if err := identityDecMode.Unmarshal(raw, &m); err != nil {
		return block, nil, fmt.Errorf("blocks[%d] is not a CBOR map: %w", i, err)
	}
	rawValue, ok := m["value"]
	if !ok {
		return block, nil, fmt.Errorf(`blocks[%d] lacks "value"`, i)
	}
	if !isCBORByteString(rawValue) {
		return block, nil, fmt.Errorf("blocks[%d] value is not a byte string", i)
	}
	if err := identityDecMode.Unmarshal(rawValue, &block.Value); err != nil {
		return block, nil, fmt.Errorf("blocks[%d] value did not decode: %w", i, err)
	}
	rawScope, ok := m["scope"]
	if !ok {
		return block, nil, fmt.Errorf(`blocks[%d] lacks "scope"`, i)
	}
	var scope map[string]cbor.RawMessage
	if err := identityDecMode.Unmarshal(rawScope, &scope); err != nil {
		return block, nil, fmt.Errorf("blocks[%d] scope is not a CBOR map: %w", i, err)
	}
	if raw, present := scope["extent"]; present {
		if !isCBORByteString(raw) {
			return block, nil, fmt.Errorf("blocks[%d] scope.extent is not a byte string", i)
		}
		if err := identityDecMode.Unmarshal(raw, &block.Scope.Extent); err != nil {
			return block, nil, fmt.Errorf("blocks[%d] scope.extent did not decode: %w", i, err)
		}
		deprecated = append(deprecated, fmt.Sprintf("blocks[%d].scope.extent", i))
	}
	if raw, present := scope["timespan"]; present {
		var ts struct {
			Start uint64 `cbor:"start"`
			End   uint64 `cbor:"end"`
		}
		if err := identityDecMode.Unmarshal(raw, &ts); err != nil {
			return block, nil, fmt.Errorf("blocks[%d] scope.timespan did not decode: %w", i, err)
		}
		block.Scope.Timespan = &SoftBindingTimespan{Start: ts.Start, End: ts.End}
	}
	if raw, present := scope["region"]; present {
		// Kept verbatim: this library evaluates no region of interest, and
		// modelling the structure would imply that it did.
		block.Scope.Region = append([]byte(nil), raw...)
	}
	return block, deprecated, nil
}

// verifySoftBindings reports every soft binding assertion of one manifest.
// They are listed on the result only at depth 0: a soft binding identifies the
// content of the manifest that carries it, so an ingredient's would identify an
// earlier work rather than these bytes — the same reasoning that scopes
// Identities. Ingredient soft bindings are still decoded, and their structural
// failures still fail the report at their own URIs.
func (v *validator) verifySoftBindings(m *parsedManifest, uri string, depth int) {
	claimAlg, _ := m.claim["alg_soft"].(string)
	for _, a := range m.assertions {
		if !isSoftBindingLabel(a.label) {
			continue
		}
		suri := uri + "/" + a.label
		if v.cancelled(suri, "before reporting a soft binding") {
			return
		}
		sb := v.verifySoftBinding(a, suri, claimAlg)
		if depth == 0 {
			v.res.SoftBindings = append(v.res.SoftBindings, sb)
		}
	}
}

// verifySoftBinding reports one soft binding assertion: its structure is
// checked, its algorithm resolved and looked up, and the whole thing then
// declared unevaluated — which is the only honest verdict a library that
// computes no soft binding algorithm can reach.
func (v *validator) verifySoftBinding(a rawAssertion, suri, claimAlg string) SoftBinding {
	sb := SoftBinding{Label: a.label, URI: suri}
	start := len(v.res.Statuses)

	if a.tbox != "cbor" {
		v.add(StatusSoftBindingMalformed, suri, "soft binding assertion is not a CBOR box", nil)
		return sb
	}
	dec, err := decodeSoftBinding(a.data)
	if err != nil {
		v.add(StatusSoftBindingMalformed, suri, "soft binding did not decode", err)
		return sb
	}

	sb.Name, sb.Params, sb.URL, sb.Blocks = dec.name, dec.params, dec.url, dec.blocks

	// The assertion's own alg wins; the claim's alg_soft is the default; with
	// neither the structure is invalid and the spec says there is no default.
	switch {
	case dec.hasAlg:
		sb.Algorithm = dec.alg
	case claimAlg != "":
		sb.Algorithm, sb.AlgorithmFromClaim = claimAlg, true
	default:
		v.add(StatusSoftBindingAlgMissing, suri,
			`soft binding carries no "alg" and the claim carries no "alg_soft"; the spec defines no default`, nil)
	}
	if sb.Algorithm != "" {
		if reg, ok := LookupSoftBindingAlgorithm(sb.Algorithm); ok {
			sb.AlgorithmRegistered, sb.AlgorithmType = true, reg.Type
		} else {
			v.add(StatusSoftBindingAlgUnlisted, suri, fmt.Sprintf(
				"soft binding algorithm %q is not in the C2PA soft binding algorithm list as of %s, which §9.3.2 requires; it may have been registered since",
				sb.Algorithm, SoftBindingListSnapshot), nil)
		}
	}

	if !allZero(dec.pad) || (dec.hasPad2 && !allZero(dec.pad2)) {
		v.add(StatusSoftBindingPadInvalid, suri, "soft binding pad or pad2 holds non-zero bytes", nil)
	}

	if v.failedSince(start) {
		return sb
	}
	sb.WellFormed = true
	v.add(StatusSoftBindingUnevaluated, suri, softBindingExplanation(sb, dec.deprecat), nil)
	return sb
}

// softBindingExplanation words the one informational status a well-formed soft
// binding earns. It names the algorithm and what is known about it, says
// plainly that no match was proved or disproved, and lists any deprecated
// fields carried along — the "recognised but not evaluated" treatment the
// identity assertion's expected_* fields get.
func softBindingExplanation(sb SoftBinding, deprecated []string) string {
	var b strings.Builder
	b.WriteString("soft binding not evaluated: ")
	switch {
	case sb.AlgorithmRegistered:
		fmt.Fprintf(&b, "%s is a registered %s algorithm", sb.Algorithm, sb.AlgorithmType)
	default:
		fmt.Fprintf(&b, "%s is not in this build's algorithm list", sb.Algorithm)
	}
	if sb.AlgorithmFromClaim {
		b.WriteString(` (from the claim's "alg_soft")`)
	}
	fmt.Fprintf(&b, ", and this library computes no soft binding algorithm, so a match over %s is neither proved nor disproved",
		blockCount(len(sb.Blocks)))
	if len(deprecated) > 0 {
		fmt.Fprintf(&b, "; deprecated fields present and not evaluated: %s", strings.Join(deprecated, ", "))
	}
	return b.String()
}

// blockCount words a block count for the explanation.
func blockCount(n int) string {
	if n == 1 {
		return "its 1 block"
	}
	return fmt.Sprintf("its %d blocks", n)
}

// hasSoftBinding reports whether a manifest carries any soft binding
// assertion. Used only to word the hardBinding.missing explanation: §9.1
// forbids a soft binding as the sole content binding, and saying so is more
// useful than a second status code for one condition.
func hasSoftBinding(m *parsedManifest) bool {
	for _, a := range m.assertions {
		if isSoftBindingLabel(a.label) {
			return true
		}
	}
	return false
}

// --- writing -----------------------------------------------------------------

// SoftBindingInfo is a c2pa.soft-binding assertion Sign writes.
//
// The VALUE is yours to compute. This library implements no soft binding
// algorithm — see SoftBinding for why that is a decision rather than a gap —
// so it takes the algorithm's output from the caller, as WithIdentitySigner
// takes a key rather than minting one. That also means every algorithm in the
// C2PA list works here, including the proprietary watermarks this package could
// never implement.
type SoftBindingInfo struct {
	// Algorithm is written as "alg": an identifier from the C2PA soft binding
	// algorithm list (§9.3.2). Required. Sign refuses one this build's embedded
	// snapshot does not name — strict in what it emits, where Validate is
	// liberal in what it accepts; see softbindings/README.md.
	Algorithm string
	// Name is an optional human-readable description of what the binding
	// covers, written as "name".
	Name string
	// Params is an optional "alg-params", written verbatim as a CBOR byte
	// string, which is what the CDDL asks for.
	Params []byte
	// Blocks are the algorithm's outputs: at least one, each with a non-empty
	// Value.
	Blocks []SoftBindingBlockInfo
}

// SoftBindingBlockInfo is one block of a soft binding Sign writes.
//
// The deprecated "extent" and "url" fields have no counterpart here: Validate
// reports them where a producer wrote them, and this writer does not.
type SoftBindingBlockInfo struct {
	// Value is the algorithm's output over this block of content, written as a
	// CBOR byte string. Required and non-empty.
	Value []byte
	// Timespan optionally scopes the block to a millisecond range of a
	// temporal asset.
	Timespan *SoftBindingTimespan
	// Region optionally scopes the block to a region of interest, written
	// verbatim as raw CBOR. This package models no region, so a caller who
	// needs one supplies its encoding.
	Region []byte
}

// softBindingInstanceLabel is the label of the i-th soft binding assertion:
// the bare label first, then the "__N" suffix — c2pa-rs's own
// Claim::label_with_instance rule, where instance 0 takes no suffix.
func softBindingInstanceLabel(i int) string {
	if i == 0 {
		return softBindingLabel
	}
	return fmt.Sprintf("%s__%d", softBindingLabel, i)
}

// validateSoftBindings is what Sign refuses before it reads a byte of the
// asset. Every rule here is one Validate would fail on read-back, so the
// refusal is early rather than new — except the algorithm check, which is
// deliberately stricter than the reader.
//
// Nothing here is about the hard binding: Sign always writes the container's
// own, so §9.1's "never the sole content binding" cannot be violated by this
// writer. Do not add a check for it — one phrased that way would refuse
// update manifests, which §11.2.3 forbids a hard binding.
func validateSoftBindings(sbs []SoftBindingInfo) error {
	for i, sb := range sbs {
		switch {
		case sb.Algorithm == "":
			return fmt.Errorf("%w: soft binding %d has no algorithm", ErrManifestInvalid, i)
		case len(sb.Blocks) == 0:
			return fmt.Errorf("%w: soft binding %d has no blocks", ErrManifestInvalid, i)
		}
		if _, ok := LookupSoftBindingAlgorithm(sb.Algorithm); !ok {
			return fmt.Errorf("%w: soft binding %d names algorithm %q, which is not in the C2PA soft binding algorithm list as of %s (§9.3.2 requires a listed one)",
				ErrManifestInvalid, i, sb.Algorithm, SoftBindingListSnapshot)
		}
		for j, b := range sb.Blocks {
			if len(b.Value) == 0 {
				return fmt.Errorf("%w: soft binding %d block %d has no value", ErrManifestInvalid, i, j)
			}
		}
	}
	return nil
}

// softBindingAssertion encodes one soft binding as the spec's
// soft-binding-map. Optional fields are OMITTED rather than written empty: a
// nil []byte encodes as CBOR null, not as an empty byte string, which our own
// reader would then call malformed (the same trap dataHashAssertion documents).
//
// "pad" is written as an empty byte string. The CDDL requires the field, and
// this signer needs no padding: sign() converges the layout, so an assertion
// whose size is fixed reserves no slack. c2pa-rs writes an empty pad for the
// same reason.
func softBindingAssertion(sb SoftBindingInfo) ([]byte, error) {
	blocks := make([]any, 0, len(sb.Blocks))
	for _, b := range sb.Blocks {
		scope := map[string]any{}
		if b.Timespan != nil {
			scope["timespan"] = map[string]any{"start": b.Timespan.Start, "end": b.Timespan.End}
		}
		if len(b.Region) > 0 {
			scope["region"] = cbor.RawMessage(b.Region)
		}
		blocks = append(blocks, map[string]any{"scope": scope, "value": b.Value})
	}
	m := map[string]any{
		"alg":    sb.Algorithm,
		"pad":    []byte{},
		"blocks": blocks,
	}
	if sb.Name != "" {
		m["name"] = sb.Name
	}
	if len(sb.Params) > 0 {
		m["alg-params"] = sb.Params
	}
	return encMode.Marshal(m)
}
