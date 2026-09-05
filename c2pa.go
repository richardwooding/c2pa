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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math"
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
	// PDF reads the manifest from the embedded file the document catalog
	// associates with the relationship /C2PA_Manifest (spec §A.4). An
	// incremental update appends a new store and the newest is the active one.
	// Note that Read's MaxScan (16 MiB) can miss the store in a large document,
	// since the embedded file sits wherever the producer appended it; Validate's
	// larger cap usually will not.
	PDF Container = "pdf"
	// RIFF reads the manifest from a top-level `C2PA` chunk in any RIFF asset:
	// WebP, WAV, AVI. One constant covers all three — like BMFF, the carrier
	// mechanics are identical and only the form type differs. An AVI over 1 GB
	// spills into further RIFF/AVIX containers, but the store lives in the
	// first.
	RIFF Container = "riff"
	// TIFF reads the manifest from IFD tag 0xCD41 in a TIFF, BigTIFF or DNG
	// file — classic and BigTIFF are the same walk at different field widths.
	TIFF Container = "tiff"
	// GIF reads the manifest from the application extension whose identifier is
	// "C2PA_GIF", its payload reassembled from the extension's data sub-blocks.
	GIF Container = "gif"
	// MP3 reads the manifest from an ID3v2 GEOB frame whose MIME type is
	// application/c2pa. An unsynchronised tag is not read.
	MP3 Container = "mp3"
	// SVG reads the manifest from a base64 <c2pa:manifest> element bound to
	// http://c2pa.org/manifest. The document is parsed as XML, not scanned.
	SVG Container = "svg"
)

// Attribution says what a manifest is a claim about. A container can carry a
// manifest describing a file inside the asset rather than the asset itself, and
// the C2PA markers on the two are identical, so only a reference from the
// document's own structure separates them.
type Attribution string

const (
	// AttributionNone is the zero value: no manifest, nothing to attribute.
	AttributionNone Attribution = ""
	// AttributionAsset means the asset's own structure associates the manifest,
	// so it is a claim about the asset.
	AttributionAsset Attribution = "asset"
	// AttributionEmbedded means the asset's structure associates the manifest
	// with something the asset CARRIES rather than with the asset itself — a
	// PDF object-level manifest (spec §A.4.3), attached to the image, font or
	// other stream whose provenance it records. The attribution is resolved,
	// not guessed; what it says is that this is a claim about an embedded
	// resource. Do not report its signer or generator as the asset's.
	AttributionEmbedded Attribution = "embedded"
	// AttributionUnknown means the manifest was identified by its markers alone,
	// with nothing associating it with the asset. It may be an embedded
	// resource's manifest whose referring object could not be resolved, or the
	// reference may simply be unreadable. Do not report its signer or generator
	// as the asset's.
	AttributionUnknown Attribution = "unknown"
)

// Info is the surfaced, CLAIMED, UNVERIFIED subset of a C2PA manifest. See the
// package doc: these are the file's assertions, not authenticated facts.
type Info struct {
	// Present is true when a C2PA manifest was found and parsed.
	Present bool
	// Attribution says whether the manifest is a claim about this asset. Only
	// PDF can currently return AttributionUnknown; the other containers give a
	// manifest no place to hide that the carrier does not point at.
	Attribution Attribution
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
	// SoftwareAgent is the tool the first c2pa.actions action that names one
	// says performed it, as "name/version" (e.g. "gpt-image/2.0"). It is the
	// model or application, where ClaimGenerator is the signing service.
	// Empty when no action names one. UNVERIFIED, like every Read field.
	SoftwareAgent string
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
	attribution := AttributionAsset
	switch container {
	case JPEG:
		jumbf = jpegJUMBF(ctx, data)
	case PNG:
		jumbf = pngJUMBF(ctx, data)
	case BMFF:
		jumbf = bmffJUMBF(ctx, data)
	case RIFF:
		jumbf = riffJUMBF(ctx, data)
	case TIFF:
		jumbf = tiffJUMBF(ctx, data)
	case GIF:
		jumbf = gifJUMBF(ctx, data)
	case MP3:
		jumbf = mp3JUMBF(ctx, data)
	case SVG:
		jumbf = svgJUMBF(ctx, data)
	case PDF:
		var src pdfStoreSource
		_, jumbf, src = pdfScan(ctx, data)
		attribution = pdfAttribution(src)
	default:
		return Info{}
	}
	if len(jumbf) == 0 {
		return Info{}
	}
	info := parseManifest(ctx, jumbf)
	if info.Present {
		info.Attribution = attribution
	}
	return info
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
	// Info describes the ACTIVE manifest only. Walking every box in the store
	// let an ingredient leak into the summary: AIGenerated stuck if any nested
	// manifest declared AI, and an ingredient's signer stood as SignedBy
	// whenever the active manifest's own extraction came back empty — the Read
	// path's sibling of the SignerChain bug fixed in v0.8.0.
	m := parseStore(ctx, jumbf).active()
	if m == nil {
		return Info{}
	}
	info := Info{Present: true}
	if m.claim != nil {
		info.ClaimGenerator = claimGenerator(m.claim)
		info.Title, _ = m.claim["dc:title"].(string)
		info.Format, _ = m.claim["dc:format"].(string)
	}
	for i := range m.assertions {
		a := &m.assertions[i]
		isActions := strings.HasSuffix(a.label, "c2pa.actions") || strings.Contains(a.label, "c2pa.actions.v")
		if a.tbox != "cbor" || !isActions {
			continue
		}
		var act map[string]any
		if decMode.Unmarshal(a.data, &act) == nil {
			if actionsAreAI(act) {
				info.AIGenerated = true
			}
			// Assigned unconditionally so within this manifest the newest
			// actions box wins, as before.
			info.SoftwareAgent = actionsSoftwareAgent(act)
		}
	}
	if by, at := signerIdentity(m.signature); by != "" || !at.IsZero() {
		info.SignedBy = by
		info.SignedAt = at
	}
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
	for _, v := range x5chainCandidates(h) {
		der := firstX5ChainDER(v)
		if der == nil {
			continue
		}
		// parseCert, not bare x509.ParseCertificate: C2PA RSA certs encode an
		// id-RSASSA-PSS SPKI Go leaves unparsed, and parseCert repairs it.
		if c, err := parseCert(der); err == nil {
			return c
		}
	}
	return nil
}

// firstX5ChainDER extracts the first DER certificate from an x5chain header
// value, which may be a single []byte (one cert) or an array of them.
// x5chainCandidates returns every place a COSE signer chain may live, in
// precedence order: the x5chain label (RFC 9360, int 33) in the protected then
// unprotected header, and the text key "x5chain" pre-1.3 c2pa-rs signers used.
// go-cose keys headers with its int64 constants, so the int lookup must use
// cose.HeaderLabelX5Chain — an untyped int(33) literal misses the entry.
func x5chainCandidates(h cose.Headers) []any {
	var out []any
	for _, hdr := range []map[any]any{h.Protected, h.Unprotected} {
		for _, key := range []any{cose.HeaderLabelX5Chain, "x5chain"} {
			if v, ok := hdr[key]; ok {
				out = append(out, v)
			}
		}
	}
	return out
}

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
// (C2PA 1.x) or `sigTst2` (2.x) header, each a timestamp container holding RFC
// 3161 tokens. Returns the zero time if absent or unparseable.
//
// Both headers must be read: a c2pa.claim.v2 signature carries its timestamp in
// sigTst2, so looking only at sigTst leaves SignedAt zero for every 2.x file.
func signingTime(unprotected map[any]any) time.Time {
	for _, name := range []string{"sigTst", "sigTst2"} {
		tst, ok := unprotected[name].(map[any]any)
		if !ok {
			continue
		}
		tokens, ok := tst["tstTokens"].([]any)
		if !ok {
			continue
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
	}
	return time.Time{}
}

// rfc3161GenTime walks an RFC 3161 timestamp (a TimeStampResp wrapping a CMS
// SignedData, or a bare ContentInfo) down to TSTInfo.genTime. It is defensive
// — any structural surprise returns the zero time rather than erroring.
func rfc3161GenTime(der []byte) time.Time {
	contentInfo := timestampContentInfo(der)

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

// ReadAll returns one Info per manifest store the asset carries: the store the
// asset's own structure associates first, with AttributionAsset; then the
// object-level manifests an object associates with itself, with
// AttributionEmbedded; then whatever the C2PA markers alone identify, with
// AttributionUnknown. Nil when there is none.
//
// Only PDF can return more than one entry today — §A.4.1 embeds a store as an
// associated file, and §A.4.3 lets an object carry a manifest of its own, so a
// document and the image inside it can both bear provenance. Read is exactly
// the first entry's view; a triage caller that wants to see a signed
// attachment inside an unsigned document is who this is for. It grew out of
// the review discussion on the PDF containers (#14).
//
// Like Read: unverified, non-failing, capped at MaxScan.
func ReadAll(ctx context.Context, container Container, r io.Reader) []Info {
	if ctx.Err() != nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxScan))
	if err != nil || len(data) == 0 {
		return nil
	}
	if container != PDF {
		info := parseManifest(ctx, extractJUMBF(ctx, container, data))
		if !info.Present {
			return nil
		}
		info.Attribution = AttributionAsset
		return []Info{info}
	}

	objs, primary, src := pdfScan(ctx, data)
	var out []Info
	seen := [][]byte{}
	add := func(store []byte, attr Attribution) {
		for _, have := range seen {
			if bytes.Equal(have, store) {
				return
			}
		}
		info := parseManifest(ctx, store)
		if !info.Present {
			return
		}
		info.Attribution = attr
		out = append(out, info)
		seen = append(seen, store)
	}
	if src != pdfStoreNone {
		add(primary, pdfAttribution(src))
	}
	if objs != nil {
		// An object-level store names the object it describes, so it is
		// attributed; whatever is left is only the markers' word.
		for _, os := range pdfObjectStores(ctx, objs) {
			add(os.store, AttributionEmbedded)
		}
		for _, store := range pdfMarkedStores(ctx, objs) {
			add(store, AttributionUnknown)
		}
	}
	return out
}

// pdfAttribution maps how a store was found to what that says about who it is a
// claim about.
func pdfAttribution(src pdfStoreSource) Attribution {
	switch src {
	case pdfStoreCatalog:
		return AttributionAsset
	case pdfStoreObject:
		return AttributionEmbedded
	case pdfStoreMarker:
		return AttributionUnknown
	}
	return AttributionNone
}

// ExtractStore returns the raw JUMBF manifest store embedded in r, byte for
// byte as it appears in the file, or nil when the container carries none.
//
// It is the byte-level counterpart to Read: WalkBoxes over the result reaches
// boxes and assertions Info does not model, which is what a manifest viewer
// needs. Reading is capped at MaxScan, as in Read. A nil store is "none found",
// not a failure — err is non-nil only when r itself errors.
func ExtractStore(ctx context.Context, container Container, r io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxScan))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return extractJUMBF(ctx, container, data), nil
}

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
// `claim_generator` field and falling back to claim_generator_info.
//
// claim_generator_info is an array of entries in C2PA 1.x and a single entry in
// 2.x, so a c2pa.claim.v2 written by Google or OpenAI has no array to read and
// reading only the array shape leaves the generator empty for every such file.
func claimGenerator(claim map[string]any) string {
	if s, ok := claim["claim_generator"].(string); ok && s != "" {
		return s
	}
	switch info := claim["claim_generator_info"].(type) {
	case map[string]any:
		return generatorInfoName(info)
	case []any:
		var parts []string
		for _, e := range info {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if name := generatorInfoName(m); name != "" {
				parts = append(parts, name)
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// generatorInfoName renders one claim_generator_info entry as "name/version",
// or as the bare name when it carries no version.
func generatorInfoName(entry map[string]any) string {
	name, _ := entry["name"].(string)
	if name == "" {
		return ""
	}
	if ver, ok := entry["version"].(string); ok && ver != "" {
		return name + "/" + ver
	}
	return name
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

// actionsSoftwareAgent returns the softwareAgent of the first action that names
// one, rendered as "name/version". C2PA 1.x writes it as a plain string on the
// action and 2.x as an entry, either inline or as a softwareAgentIndex into the
// assertion's softwareAgents array, so all three shapes are read.
func actionsSoftwareAgent(actAssertion map[string]any) string {
	actions, ok := actAssertion["actions"].([]any)
	if !ok {
		return ""
	}
	for _, a := range actions {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		switch agent := m["softwareAgent"].(type) {
		case string:
			if agent != "" {
				return agent
			}
		case map[string]any:
			if name := generatorInfoName(agent); name != "" {
				return name
			}
		}
		if name := indexedSoftwareAgent(actAssertion, m["softwareAgentIndex"]); name != "" {
			return name
		}
	}
	return ""
}

// indexedSoftwareAgent resolves an action's softwareAgentIndex against the
// assertion's softwareAgents array, the deduplicated form C2PA 2.x uses when
// several actions share one agent.
func indexedSoftwareAgent(actAssertion map[string]any, index any) string {
	i, ok := asIndex(index)
	if !ok {
		return ""
	}
	agents, ok := actAssertion["softwareAgents"].([]any)
	if !ok || i >= len(agents) {
		return ""
	}
	entry, ok := agents[i].(map[string]any)
	if !ok {
		return ""
	}
	return generatorInfoName(entry)
}

// asIndex reads a non-negative array index from the CBOR decoder's integer
// forms, which vary with the encoded value's sign and width.
func asIndex(v any) (int, bool) {
	switch n := v.(type) {
	case uint64:
		if n <= math.MaxInt32 {
			return int(n), true
		}
	case int64:
		if n >= 0 && n <= math.MaxInt32 {
			return int(n), true
		}
	case int:
		if n >= 0 {
			return n, true
		}
	}
	return 0, false
}

func isAIDigitalSourceType(v any) bool {
	s, ok := v.(string)
	// Matches both digitalSourceType values that denote AI generation:
	// `trainedAlgorithmicMedia` and `compositeWithTrainedAlgorithmicMedia`
	// (note the capitalised "Trained" in the latter) — hence ToLower.
	return ok && strings.Contains(strings.ToLower(s), "trainedalgorithmicmedia")
}
