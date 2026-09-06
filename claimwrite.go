package c2pa

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Claim and assertion writers for Sign (spec §10, §11). Everything here is
// pure: bytes in, bytes out, no I/O — the pipeline in sign.go decides the
// order and the signing.

// encMode is RFC 8949 §4.2.1 core deterministic encoding, which C2PA requires
// of claims (§10.2) and which go-cose already uses for COSE headers, so a map
// encoded here and a header encoded there sort their keys the same way. NOT
// CanonicalEncOptions: that is RFC 7049's length-first order, which c2pa-rs
// does not use. Two gotchas: a nil []byte encodes as CBOR null, so an empty
// byte string must be []byte{}; and a Go int encodes at its shortest width,
// which is exactly why exclusion offsets need the layout fixpoint in sign.go.
var encMode = func() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err) // static options; can't fail
	}
	return em
}()

// newUUIDv4 returns a lowercase hyphenated random UUID (RFC 4122 version 4)
// from crypto/rand. No dependency is worth one function.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// newManifestLabel returns a v2 manifest label, urn:c2pa:<uuid>[:<vendor>]
// (spec §10.2.1 ABNF; c2pa-rs claim.rs C2PA_NAMESPACE_V2). vendor is already
// lowercased and validated by NewSigner.
func newManifestLabel(vendor string) (string, error) {
	u, err := newUUIDv4()
	if err != nil {
		return "", err
	}
	if vendor != "" {
		return "urn:c2pa:" + u + ":" + vendor, nil
	}
	return "urn:c2pa:" + u, nil
}

// newInstanceID returns an XMP instance ID, "xmp.iid:<uuid>" — the dot, not a
// colon, is what c2pa-rs writes (builder.rs default_instance_id).
func newInstanceID() (string, error) {
	u, err := newUUIDv4()
	if err != nil {
		return "", err
	}
	return "xmp.iid:" + u, nil
}

// validVendor reports whether vendor is a legal claim-generator label segment:
// 1..32 visible ASCII characters, none of them space or colon (the ABNF's
// visible-char-except-space, with the separator excluded so the label stays
// parseable).
func validVendor(vendor string) bool {
	if vendor == "" || len(vendor) > 32 {
		return false
	}
	for i := 0; i < len(vendor); i++ {
		c := vendor[i]
		if c <= 0x20 || c >= 0x7F || c == ':' {
			return false
		}
	}
	return true
}

// hashedURI builds a hashed_uri map for a JUMBF box: the URL and the hash of
// the box's content — everything after its 8-byte header — which is what
// verifyAssertionHashes checks (rawAssertion.boxContent) and what c2pa-rs's
// calc_assertion_box_hash computes.
func hashedURI(alg, url string, box []byte) (map[string]any, error) {
	h, ok := hashByName(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %q", alg)
	}
	if len(box) < 8 {
		return nil, fmt.Errorf("box too short to hash")
	}
	h.Write(box[8:])
	return map[string]any{"url": url, "hash": h.Sum(nil)}, nil
}

// assertionURL is the claim's URL for an assertion in this manifest's store.
func assertionURL(label string) string {
	return "self#jumbf=c2pa.assertions/" + label
}

// claimParams is what a c2pa.claim.v2 carries.
type claimParams struct {
	title      string
	instanceID string
	alg        string
	generator  GeneratorInfo
	created    []any // hashed_uri maps, in assertion-store order
}

// buildClaimV2 encodes a c2pa.claim.v2 exactly as c2pa-rs's Claim::serialize_v2
// does: instanceID, ONE claim_generator_info map (not the 1.x array),
// signature, created_assertions, dc:title when set, alg. No dc:format (gone
// in v2), no "assertions" key, no empty gathered_assertions.
func buildClaimV2(p claimParams) ([]byte, error) {
	if p.generator.Name == "" {
		return nil, fmt.Errorf("claim_generator_info is mandatory")
	}
	claim := map[string]any{
		"alg":                  p.alg,
		"claim_generator_info": generatorInfoMap(p.generator),
		"created_assertions":   p.created,
		"instanceID":           p.instanceID,
		"signature":            "self#jumbf=c2pa.signature",
	}
	if p.title != "" {
		claim["dc:title"] = p.title
	}
	return encMode.Marshal(claim)
}

// generatorInfoMap renders a generator-info-map: name is required, version is
// omitted when empty.
func generatorInfoMap(g GeneratorInfo) map[string]any {
	m := map[string]any{"name": g.Name}
	if g.Version != "" {
		m["version"] = g.Version
	}
	return m
}

// dataHashAssertion encodes a c2pa.hash.data (§18.5): the exclusions as
// {start, length} pairs, the conventional name, the algorithm, the digest and
// an empty pad — pad is always present in c2pa-rs's output, and []byte{} (not
// nil) is what keeps it a byte string rather than a null.
func dataHashAssertion(alg string, excl []byteRange, digest []byte) ([]byte, error) {
	list := make([]any, 0, len(excl))
	for _, r := range excl {
		list = append(list, map[string]any{"start": r.start, "length": r.length})
	}
	return encMode.Marshal(map[string]any{
		"exclusions": list,
		"name":       "jumbf manifest",
		"alg":        alg,
		"hash":       digest,
		"pad":        []byte{},
	})
}

// bmffStandardExclusions are the exclusions §A.5.6 requires of every
// c2pa.hash.bmff.v3: the C2PA uuid box (by usertype at offset 8, so foreign
// uuid boxes stay bound), 'ftyp' and 'mfra'. Returned in the CBOR-ready form
// the assertion carries; bmffHashDigest decodes that same form to hash with, so
// writer and verifier cannot drift.
func bmffStandardExclusions() []any {
	return []any{
		map[string]any{"xpath": "/uuid", "data": []any{map[string]any{"offset": 8, "value": c2paBoxUUID[:]}}},
		map[string]any{"xpath": "/ftyp"},
		map[string]any{"xpath": "/mfra"},
	}
}

// bmffHashAssertion encodes a c2pa.hash.bmff.v3 with a flat hash (§18.6).
func bmffHashAssertion(alg string, digest []byte) ([]byte, error) {
	return encMode.Marshal(map[string]any{
		"exclusions": bmffStandardExclusions(),
		"alg":        alg,
		"hash":       digest,
	})
}

// merkleMapSpec is one merkle-map of a fragmented c2pa.hash.bmff.v3 (§A.5.4):
// the tree over one rendition's fragments.
type merkleMapSpec struct {
	uniqueID, localID, count int
	alg                      string
	initHash                 []byte
	hashes                   [][]byte // the stored row
}

// bmffMerkleAssertion encodes the fragmented form of c2pa.hash.bmff.v3: the
// standard exclusions, the algorithm and a merkle array — and NO flat hash,
// which verifyBMFFFragmented (and c2pa-rs) calls malformed on a fragmented
// assertion because it says nothing about the fragments.
func bmffMerkleAssertion(alg string, maps []merkleMapSpec) ([]byte, error) {
	list := make([]any, len(maps))
	for i, m := range maps {
		list[i] = map[string]any{
			"uniqueId": m.uniqueID, "localId": m.localID, "count": m.count,
			"alg": m.alg, "initHash": m.initHash, "hashes": m.hashes,
		}
	}
	return encMode.Marshal(map[string]any{
		"exclusions": bmffStandardExclusions(),
		"alg":        alg,
		"merkle":     list,
	})
}

// bmffStandardSegment resolves the standard exclusions against a BMFF file's
// own boxes — the segment verifyBMFFHash would build for it.
func bmffStandardSegment(ctx context.Context, data []byte) (bmffSegment, error) {
	excl, ok := decodeBMFFExclusions(bmffStandardExclusions())
	if !ok {
		return bmffSegment{}, errors.New("standard BMFF exclusions did not decode")
	}
	seg, ok := newBMFFSegment(ctx, data, excl)
	if !ok {
		return bmffSegment{}, errors.New("no BMFF box structure to hash")
	}
	return seg, nil
}

// bmffHashDigest is the c2pa.hash.bmff.v3 flat hash of a whole BMFF file: the
// verifier's own offset-marker walk (hashBMFFTopLevel) with the standard
// exclusions resolved against the file's own boxes, exactly as verifyBMFFHash
// will recompute it.
func bmffHashDigest(ctx context.Context, alg string, data []byte) ([]byte, error) {
	h, ok := hashByName(alg)
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm %q", alg)
	}
	seg, err := bmffStandardSegment(ctx, data)
	if err != nil {
		return nil, err
	}
	hashBMFFTopLevel(ctx, seg.data, seg.top, seg.ranges, h)
	return h.Sum(nil), nil
}

// actionsAssertion encodes a c2pa.actions.v2. When ingredients is non-empty it
// becomes the FIRST action's parameters.ingredients — the reference a
// c2pa.opened action must carry to its parentOf ingredient, without which
// c2pa-rs reports assertion.action.ingredientMismatch.
func actionsAssertion(actions []Action, ingredients []any) ([]byte, error) {
	list := make([]any, 0, len(actions))
	for i, a := range actions {
		m := map[string]any{"action": a.Action}
		if a.DigitalSourceType != "" {
			m["digitalSourceType"] = a.DigitalSourceType
		}
		if a.SoftwareAgent.Name != "" {
			m["softwareAgent"] = generatorInfoMap(a.SoftwareAgent)
		}
		params := make(map[string]any, len(a.Parameters)+1)
		for k, v := range a.Parameters {
			params[k] = v
		}
		if i == 0 && len(ingredients) > 0 {
			params["ingredients"] = ingredients
		}
		if len(params) > 0 {
			m["parameters"] = params
		}
		list = append(list, m)
	}
	return encMode.Marshal(map[string]any{"actions": list})
}

// parentIngredientAssertion encodes the c2pa.ingredient.v3 that names what an
// ActionOpened manifest opened (§11.3.4). With a prior manifest it carries
// activeManifest and claimSignature hashed_uris — the hash is over the
// referenced superbox's content, c2pa-rs's write_box_payload — plus the
// validationResults c2pa-rs requires alongside activeManifest (it reports
// assertion.ingredient.malformed without them). Without one it is the minimal
// parentOf a c2pa.opened action can point at.
func parentIngredientAssertion(alg string, prior *priorManifest, results *ValidationResult, instanceID string) ([]byte, error) {
	ing := map[string]any{
		"relationship": "parentOf",
		"instanceID":   instanceID,
	}
	if prior != nil {
		h, ok := hashByName(alg)
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm %q", alg)
		}
		h.Write(prior.content)
		ing["activeManifest"] = map[string]any{
			"url":  "self#jumbf=/c2pa/" + prior.label,
			"hash": h.Sum(nil),
		}
		if prior.signature != nil {
			sig, err := hashedURI(alg, "self#jumbf=/c2pa/"+prior.label+"/c2pa.signature", prior.signature.full)
			if err != nil {
				return nil, err
			}
			ing["claimSignature"] = sig
		}
		if prior.title != "" {
			ing["dc:title"] = prior.title
		}
		if results != nil {
			ing["validationResults"] = validationResultsMap(*results)
		}
	}
	return encMode.Marshal(ing)
}

// validationResultsMap renders a ValidationResult in the validation-results-map
// shape c2pa-rs serialises (validation_results.rs): the active manifest's
// statuses bucketed by severity, each as {code, url?, explanation?}.
func validationResultsMap(res ValidationResult) map[string]any {
	success, informational, failure := []any{}, []any{}, []any{}
	for _, s := range res.Statuses {
		e := map[string]any{"code": string(s.Code)}
		if s.URI != "" {
			e["url"] = s.URI
		}
		if s.Explanation != "" {
			e["explanation"] = s.Explanation
		}
		switch s.Severity {
		case SeveritySuccess:
			success = append(success, e)
		case SeverityFailure:
			failure = append(failure, e)
		default:
			informational = append(informational, e)
		}
	}
	return map[string]any{
		"activeManifest": map[string]any{
			"success":       success,
			"informational": informational,
			"failure":       failure,
		},
	}
}

// reservedAssertionLabel reports whether a caller-supplied assertion label
// collides with one Sign writes itself or one only the pipeline may produce.
func reservedAssertionLabel(label string) bool {
	switch {
	case label == "", strings.HasPrefix(label, "c2pa.hash."),
		strings.HasPrefix(label, "c2pa.actions"), strings.HasPrefix(label, "c2pa.claim"),
		label == "c2pa.signature", label == "c2pa.ingredient.v3":
		return true
	}
	return false
}
