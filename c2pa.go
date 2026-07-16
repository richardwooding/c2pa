// Package c2pa is a pure-Go, read-only reader for C2PA / Content Credentials
// (https://c2pa.org) provenance manifests embedded in media files.
//
// It surfaces what a file CLAIMS about its provenance — the creating tool,
// title, declared media type, whether it declares AI-generated content, and
// the signer identity + signing time — by parsing the embedded JUMBF manifest
// (ISO 19566-5), CBOR-decoding the active manifest's claim and c2pa.actions
// assertion, and decoding the COSE_Sign1 signature envelope.
//
// # This is UNVERIFIED
//
// The reader is deliberately read-only: it does NOT validate the COSE
// cryptographic signature, and it does NOT check the signer's certificate
// chain against the C2PA trust list. Full validation requires the Rust
// c2pa-rs library via CGO, which this pure-Go package intentionally avoids.
//
// Treat every field like EXIF or an email From header: accurate-as-recorded,
// not authenticated. SignedBy is who the file CLAIMS signed it, not a verified
// identity. A file with no manifest yields Info{Present:false}; absence of a
// signal (e.g. AIGenerated) does not prove its negation.
//
// All parsing is best-effort and never panics: malformed or truncated input
// yields zero values rather than an error. Every input-scaled loop honours the
// supplied context.Context, so a cancelled call surrenders promptly.
package c2pa

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// MaxScan caps how many leading bytes Read consumes looking for a manifest.
// C2PA manifests sit in the file header (before image data) and rarely exceed
// a few MB even with embedded thumbnails; past the cap Read gives up.
const MaxScan = 16 << 20

// Container identifies the carrier file format whose C2PA manifest to read.
type Container string

const (
	// JPEG reads the manifest from APP11 (0xFFEB) marker segments.
	JPEG Container = "jpeg"
	// PNG reads the manifest from caBX chunks.
	PNG Container = "png"
	// BMFF reads the manifest from a top-level C2PA `uuid` box in any ISO Base
	// Media File Format file: MP4, MOV, M4A, HEIC, HEIF, AVIF. One constant
	// covers every brand — the carrier mechanics are identical; sniff the ftyp
	// brand yourself if you need to distinguish them. Note that Read's MaxScan
	// (16 MiB) can miss a manifest box placed after a large mdat; Validate's
	// larger cap usually will not.
	BMFF Container = "bmff"
)

// Info is the surfaced, CLAIMED, UNVERIFIED subset of a C2PA manifest. See the
// package doc: these are the file's assertions, not authenticated facts.
type Info struct {
	// Present is true when a C2PA manifest was found and parsed.
	Present bool
	// ClaimGenerator is the tool that created/edited the asset (e.g.
	// "Adobe Firefly", "make_test_images/0.33.1 c2pa-rs/0.33.1").
	ClaimGenerator string
	// Title is the claim's dc:title.
	Title string
	// Format is the claim's dc:format (declared media type).
	Format string
	// AIGenerated is true when a c2pa.actions assertion declares a
	// digitalSourceType of trainedAlgorithmicMedia or
	// compositeWithTrainedAlgorithmicMedia.
	AIGenerated bool
	// SignedBy is the COSE_Sign1 signer's leaf x509 certificate common name
	// (Subject CN, falling back to the first Organization). UNVERIFIED — the
	// certificate chain is not validated against the C2PA trust list.
	SignedBy string
	// SignedAt is the signing time from the RFC 3161 timestamp embedded in the
	// signature (sigTst). Zero when absent. UNVERIFIED.
	SignedAt time.Time
}

// decMode decodes CBOR maps (including nested ones) into map[string]any rather
// than fxamacker's default map[any]any, so the field lookups below work at
// every depth. C2PA claims/assertions use text keys throughout.
var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{DefaultMapType: reflect.TypeFor[map[string]any]()}.DecMode()
	if err != nil {
		panic(err) // static options; can't fail
	}
	return dm
}()

// Read reads up to MaxScan bytes from r and, for the given container, locates
// and parses the embedded JUMBF manifest. It returns a zero Info
// (Present=false) when there's no manifest. It never returns an error —
// provenance is best-effort metadata, surfaced like EXIF.
//
// ctx is honoured at entry and inside the input-scaled scan loops, so a
// cancelled call surrenders promptly mid-scan rather than parsing a full
// adversarial header.
func Read(ctx context.Context, container Container, r io.Reader) Info {
	if ctx.Err() != nil {
		return Info{}
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxScan))
	if err != nil || len(data) == 0 {
		return Info{}
	}
	var jumbf []byte
	switch container {
	case JPEG:
		jumbf = jpegJUMBF(ctx, data)
	case PNG:
		jumbf = pngJUMBF(ctx, data)
	case BMFF:
		jumbf = bmffJUMBF(ctx, data)
	default:
		return Info{}
	}
	if len(jumbf) == 0 {
		return Info{}
	}
	return parseManifest(ctx, jumbf)
}

// jpegJUMBF reassembles the JUMBF box from APP11 (0xFFEB) marker segments,
// stopping at start-of-scan. Packet 1 of a box keeps its LBox+TBox; later
// packets repeat them and are skipped (ISO 19566-5 JPEG embedding).
func jpegJUMBF(ctx context.Context, data []byte) []byte {
	var out []byte
	i := 2 // skip SOI
	for i < len(data)-1 {
		if ctx.Err() != nil {
			return out
		}
		if data[i] != 0xFF {
			i++
			continue
		}
		m := data[i+1]
		switch {
		case m == 0xD9 || m == 0xDA: // EOI / SOS — image data starts; stop.
			return out
		case m == 0xD8 || (m >= 0xD0 && m <= 0xD7) || m == 0x01: // standalone markers
			i += 2
			continue
		}
		if i+4 > len(data) {
			break
		}
		ln := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if ln < 2 || i+2+ln > len(data) {
			break
		}
		if m == 0xEB { // APP11
			p := data[i+4 : i+2+ln]
			if len(p) > 8 && binary.BigEndian.Uint16(p[:2]) == 0x4A50 { // "JP"
				box := p[8:] // skip CI(2)+En(2)+Z(4)
				if binary.BigEndian.Uint32(p[4:8]) == 1 {
					out = append(out, box...)
				} else if len(box) > 8 {
					out = append(out, box[8:]...)
				}
			}
		}
		i += 2 + ln
	}
	return out
}

// pngJUMBF concatenates the data of all `caBX` chunks (PNG's C2PA carrier),
// stopping at IDAT. PNG: 8-byte signature, then [len(4)][type(4)][data][crc(4)].
func pngJUMBF(ctx context.Context, data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	var out []byte
	i := 8
	for i+8 <= len(data) {
		if ctx.Err() != nil {
			return out
		}
		ln := int(binary.BigEndian.Uint32(data[i : i+4]))
		typ := string(data[i+4 : i+8])
		if ln < 0 || i+12+ln > len(data) {
			break
		}
		switch typ {
		case "IDAT", "IEND":
			return out
		case "caBX":
			out = append(out, data[i+8:i+8+ln]...)
		}
		i += 12 + ln // len + type + data + crc
	}
	return out
}

// parseManifest walks the JUMBF box tree, decodes the c2pa.claim and
// c2pa.actions CBOR, and decodes the c2pa.signature COSE_Sign1 envelope.
func parseManifest(ctx context.Context, jumbf []byte) Info {
	info := Info{}
	WalkBoxes(ctx, jumbf, func(label string, tbox string, content []byte) {
		switch {
		case tbox != "cbor":
			return
		case strings.HasSuffix(label, "c2pa.claim") || strings.Contains(label, "c2pa.claim.v"):
			info.Present = true
			var claim map[string]any
			if decMode.Unmarshal(content, &claim) == nil {
				info.ClaimGenerator = claimGenerator(claim)
				info.Title, _ = claim["dc:title"].(string)
				info.Format, _ = claim["dc:format"].(string)
			}
		case strings.HasSuffix(label, "c2pa.actions") || strings.Contains(label, "c2pa.actions.v"):
			info.Present = true
			var act map[string]any
			if decMode.Unmarshal(content, &act) == nil && actionsAreAI(act) {
				info.AIGenerated = true
			}
		case strings.HasSuffix(label, "c2pa.signature"):
			// The signature box content is a COSE_Sign1 (a raw CBOR array,
			// not a text-keyed map), so it bypasses the claim/actions
			// decode above and is parsed by signerIdentity.
			info.Present = true
			if by, at := signerIdentity(content); by != "" || !at.IsZero() {
				info.SignedBy = by
				info.SignedAt = at
			}
		}
	})
	return info
}

// signerIdentity decodes the COSE_Sign1 envelope of a c2pa.signature box and
// returns the signer's leaf-certificate name and the signing time. It is
// best-effort and never panics: any decode failure yields the zero values.
// This reads the CLAIMED identity only — it performs NO trust-chain validation.
func signerIdentity(coseSign1 []byte) (signedBy string, signedAt time.Time) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseSign1); err != nil {
		return "", time.Time{}
	}
	if leaf := leafCert(msg.Headers); leaf != nil {
		signedBy = leaf.Subject.CommonName
		if signedBy == "" && len(leaf.Subject.Organization) > 0 {
			signedBy = leaf.Subject.Organization[0]
		}
	}
	signedAt = signingTime(msg.Headers.Unprotected)
	return signedBy, signedAt
}

// leafCert pulls the x5chain (header label 33) from the COSE headers
// (protected first, then unprotected) and parses its first entry — the leaf
// signer certificate.
func leafCert(h cose.Headers) *x509.Certificate {
	for _, store := range []map[any]any{h.Protected, h.Unprotected} {
		// go-cose keys protected/unprotected headers with its int64 label
		// constants, so look up the x5chain with cose.HeaderLabelX5Chain
		// (== 33) rather than an untyped int literal — int(33) would miss.
		der := firstX5ChainDER(store[cose.HeaderLabelX5Chain])
		if der == nil {
			continue
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			return c
		}
	}
	return nil
}

// firstX5ChainDER extracts the first DER certificate from an x5chain header
// value, which may be a single []byte (one cert) or an array of them.
func firstX5ChainDER(v any) []byte {
	switch x := v.(type) {
	case []byte:
		return x
	case [][]byte:
		if len(x) > 0 {
			return x[0]
		}
	case []any:
		for _, e := range x {
			if b, ok := e.([]byte); ok {
				return b
			}
		}
	}
	return nil
}

// signingTime extracts the signing time from the COSE unprotected `sigTst`
// header — a C2PA timestamp container holding RFC 3161 timestamp tokens.
// Returns the zero time if absent or unparseable.
func signingTime(unprotected map[any]any) time.Time {
	tst, ok := unprotected["sigTst"].(map[any]any)
	if !ok {
		return time.Time{}
	}
	tokens, ok := tst["tstTokens"].([]any)
	if !ok {
		return time.Time{}
	}
	for _, tk := range tokens {
		m, ok := tk.(map[any]any)
		if !ok {
			continue
		}
		der, ok := m["val"].([]byte)
		if !ok {
			continue
		}
		if t := rfc3161GenTime(der); !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// rfc3161GenTime walks an RFC 3161 timestamp (a TimeStampResp wrapping a CMS
// SignedData, or a bare ContentInfo) down to TSTInfo.genTime. It is defensive
// — any structural surprise returns the zero time rather than erroring.
func rfc3161GenTime(der []byte) time.Time {
	contentInfo := der
	// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
	// When the optional token is present, descend into it; otherwise `der`
	// is already a bare ContentInfo.
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &resp); err == nil && len(resp.Token.FullBytes) > 0 {
		contentInfo = resp.Token.FullBytes
	}

	// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
	var ci struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(contentInfo, &ci); err != nil {
		return time.Time{}
	}

	// SignedData ::= SEQUENCE { version, digestAlgorithms SET,
	//   encapContentInfo SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }, ... }
	var sd struct {
		Version     int
		DigestAlgos asn1.RawValue `asn1:"set"`
		Encap       struct {
			OID     asn1.ObjectIdentifier
			Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
		}
		Rest []asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}
	}

	// eContent is an OCTET STRING wrapping the DER-encoded TSTInfo.
	var eContent []byte
	if _, err := asn1.Unmarshal(sd.Encap.Content.Bytes, &eContent); err != nil {
		return time.Time{}
	}

	// TSTInfo ::= SEQUENCE { version, policy OID, messageImprint, serialNumber INTEGER, genTime GeneralizedTime, ... }
	var tst struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint asn1.RawValue
		SerialNumber   *big.Int
		GenTime        time.Time       `asn1:"generalized"`
		Rest           []asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(eContent, &tst); err != nil {
		return time.Time{}
	}
	return tst.GenTime
}

// maxJUMBFDepth caps superbox nesting. Real C2PA manifests nest only a few
// levels (store → manifest → c2pa.assertions → assertion ≈ 4); 64 is far
// above that yet well below a stack-overflow threshold. Without this an
// adversarial input — a chain of nested `jumb` boxes, each stripping only
// the 8-byte header — could nest ~MaxScan/8 levels deep and exhaust the
// goroutine stack. We degrade gracefully (stop descending) instead.
const maxJUMBFDepth = 64

// WalkBoxes recursively walks a JUMBF box tree, invoking fn(label, tbox,
// content) for every leaf box. label is the nearest enclosing superbox's jumd
// label, tbox is the 4-character box type, and content is the box payload.
// Nesting is capped at an internal depth limit so adversarial input cannot
// exhaust the stack; ctx is honoured at the top of every iteration.
//
// This is a lower-level primitive — most callers want Read. It is exported for
// advanced use (e.g. surfacing assertions Read does not model).
func WalkBoxes(ctx context.Context, jumbf []byte, fn func(label, tbox string, content []byte)) {
	walkBoxesDepth(ctx, jumbf, "", 0, fn)
}

func walkBoxesDepth(ctx context.Context, b []byte, label string, depth int, fn func(label, tbox string, content []byte)) {
	if depth > maxJUMBFDepth {
		return
	}
	for len(b) >= 8 {
		if ctx.Err() != nil {
			return
		}
		lbox := int(binary.BigEndian.Uint32(b[:4]))
		tbox := string(b[4:8])
		if lbox < 8 || lbox > len(b) {
			return
		}
		content := b[8:lbox]
		if tbox == "jumb" {
			childLabel, rest := jumdLabel(content)
			walkBoxesDepth(ctx, rest, childLabel, depth+1, fn)
		} else {
			fn(label, tbox, content)
		}
		b = b[lbox:]
	}
}

// jumdLabel parses the leading jumd description box of a superbox's content
// and returns its label plus the remaining child boxes.
func jumdLabel(content []byte) (label string, rest []byte) {
	if len(content) < 8 {
		return "", content
	}
	lbox := int(binary.BigEndian.Uint32(content[:4]))
	if string(content[4:8]) != "jumd" || lbox < 8 || lbox > len(content) {
		return "", content
	}
	d := content[8:lbox]
	rest = content[lbox:]
	if len(d) < 17 { // 16-byte type UUID + 1-byte toggles
		return "", rest
	}
	if d[16]&0x02 != 0 { // toggles bit 1: label present (null-terminated)
		end := 17
		for end < len(d) && d[end] != 0 {
			end++
		}
		label = string(d[17:end])
	}
	return label, rest
}

// claimGenerator returns the claim's generator string, preferring the flat
// `claim_generator` field and falling back to claim_generator_info[].
func claimGenerator(claim map[string]any) string {
	if s, ok := claim["claim_generator"].(string); ok && s != "" {
		return s
	}
	infos, ok := claim["claim_generator_info"].([]any)
	if !ok {
		return ""
	}
	var parts []string
	for _, e := range infos {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		if ver, ok := m["version"].(string); ok && ver != "" {
			name += "/" + ver
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, " ")
}

// actionsAreAI reports whether a c2pa.actions assertion declares AI-generated
// content via a digitalSourceType of trainedAlgorithmicMedia or
// compositeWithTrainedAlgorithmicMedia (anywhere in the action or its
// parameters).
func actionsAreAI(actAssertion map[string]any) bool {
	actions, ok := actAssertion["actions"].([]any)
	if !ok {
		return false
	}
	for _, a := range actions {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if isAIDigitalSourceType(m["digitalSourceType"]) {
			return true
		}
		if params, ok := m["parameters"].(map[string]any); ok {
			if isAIDigitalSourceType(params["digitalSourceType"]) {
				return true
			}
		}
	}
	return false
}

func isAIDigitalSourceType(v any) bool {
	s, ok := v.(string)
	// Matches both digitalSourceType values that denote AI generation:
	// `trainedAlgorithmicMedia` and `compositeWithTrainedAlgorithmicMedia`
	// (note the capitalised "Trained" in the latter) — hence ToLower.
	return ok && strings.Contains(strings.ToLower(s), "trainedalgorithmicmedia")
}
