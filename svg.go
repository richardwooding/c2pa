package c2pa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const (
	// svgManifestNS is the namespace the c2pa:manifest element is bound to.
	svgManifestNS = "http://c2pa.org/manifest"
	// svgManifestLocal is the element's local name once the namespace is resolved.
	svgManifestLocal = "manifest"
	// maxSVGTokens bounds the XML walk over adversarial input.
	maxSVGTokens = 1 << 20
)

// svgJUMBF returns the raw JUMBF manifest store from an SVG, or nil when there
// is none.
//
// SVG is the one text carrier: the store is base64 inside a <c2pa:manifest>
// element bound to http://c2pa.org/manifest, nested in <metadata>. The document
// is parsed as XML rather than pattern-matched, so a matching string in a
// comment, a CDATA section or an attribute is not mistaken for the store.
//
// encoding/xml does not resolve external entities, so the classic XXE and
// billion-laughs expansions are not reachable here; the token walk is still
// bounded and honours ctx.
func svgJUMBF(ctx context.Context, data []byte) []byte {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose

	for tokens := 0; tokens < maxSVGTokens; tokens++ {
		if ctx.Err() != nil {
			return nil
		}
		tok, err := dec.Token()
		if err != nil {
			return nil // io.EOF included: no manifest element found
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != svgManifestLocal || start.Name.Space != svgManifestNS {
			continue
		}
		var encoded string
		if err := dec.DecodeElement(&encoded, &start); err != nil {
			return nil
		}
		store, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
		if err != nil || len(store) == 0 {
			return nil
		}
		return store
	}
	return nil
}

// --- writing ------------------------------------------------------------------

// svgEmbedder writes the store as base64 in a <c2pa:manifest> element inside
// <metadata> directly under <svg> (spec §A.3.3), binding the c2pa prefix on the
// root. The document is edited by byte-exact splicing at offsets the XML
// tokenizer reports, so everything else — prolog, comments, formatting — is
// preserved untouched.
type svgEmbedder struct{}

// svgDoc is what the walk learned about the document's shape.
type svgDoc struct {
	rootStart, rootEnd int    // the root start tag's span
	rootSelfClosing    bool   //
	rootQName          string // the raw tag name, e.g. "svg" or "svg:svg"
	nsBound            bool   // xmlns:c2pa already bound to the manifest namespace
	metaStart, metaEnd int    // the first direct-child <metadata> start tag's span; -1 when none
	metaSelfClosing    bool   //
	metaQName          string //
	cuts               []edit // existing c2pa:manifest elements, at any depth
}

// svgLayout tokenizes strictly and records the spans the writer edits. A root
// that is not <svg>, a c2pa prefix bound elsewhere, or XML the strict decoder
// rejects (a non-UTF-8 declared encoding included) is refused.
func svgLayout(ctx context.Context, data []byte) (svgDoc, error) {
	doc := svgDoc{metaStart: -1}
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	seenRoot := false
	var manifestStart int
	manifestDepth := -1
	for tokens := 0; tokens < maxSVGTokens; tokens++ {
		if err := ctx.Err(); err != nil {
			return svgDoc{}, err
		}
		prev := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return svgDoc{}, fmt.Errorf("%w: SVG does not parse as XML: %v", errCarrierMalformed, err)
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			if !seenRoot {
				if t.Name.Local != "svg" {
					return svgDoc{}, fmt.Errorf("%w: root element is <%s>, not <svg>", errCarrierMalformed, t.Name.Local)
				}
				seenRoot = true
				doc.rootStart, doc.rootEnd = prev, end
				doc.rootSelfClosing = bytes.HasSuffix(data[prev:end], []byte("/>"))
				doc.rootQName = xmlQName(data[prev:end])
				for _, a := range t.Attr {
					if a.Name.Space == "xmlns" && a.Name.Local == "c2pa" {
						if a.Value != svgManifestNS {
							return svgDoc{}, fmt.Errorf("%w: xmlns:c2pa is bound to %q", errCarrierUnsupported, a.Value)
						}
						doc.nsBound = true
					}
				}
			} else if depth == 1 && t.Name.Local == "metadata" && doc.metaStart < 0 {
				doc.metaStart, doc.metaEnd = prev, end
				doc.metaSelfClosing = bytes.HasSuffix(data[prev:end], []byte("/>"))
				doc.metaQName = xmlQName(data[prev:end])
			}
			if t.Name.Space == svgManifestNS && t.Name.Local == svgManifestLocal && manifestDepth < 0 {
				manifestStart, manifestDepth = prev, depth
			}
			depth++
		case xml.EndElement:
			depth--
			if manifestDepth == depth {
				doc.cuts = append(doc.cuts, edit{at: manifestStart, remove: end - manifestStart})
				manifestDepth = -1
			}
			if depth == 0 {
				return doc, nil // the root is closed; whatever follows is left alone
			}
		}
	}
	if !seenRoot {
		return svgDoc{}, fmt.Errorf("%w: no root element", errCarrierMalformed)
	}
	return svgDoc{}, fmt.Errorf("%w: SVG root element is never closed", errCarrierMalformed)
}

// xmlQName returns the raw tag name of a start tag: the bytes after '<' up to
// the first space, '/' or '>'.
func xmlQName(tag []byte) string {
	i := 1
	for i < len(tag) && tag[i] != ' ' && tag[i] != '\t' && tag[i] != '\n' && tag[i] != '\r' && tag[i] != '/' && tag[i] != '>' {
		i++
	}
	return string(tag[1:i])
}

func (svgEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	doc, err := svgLayout(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	edits := append([]edit(nil), doc.cuts...)
	if !doc.nsBound {
		at := doc.rootEnd - 1
		if doc.rootSelfClosing {
			at = doc.rootEnd - 2
		}
		edits = append(edits, edit{at: at, insert: []byte(` xmlns:c2pa="` + svgManifestNS + `"`)})
	}
	encoded := base64.StdEncoding.EncodeToString(store)
	elem := "<c2pa:manifest>" + encoded + "</c2pa:manifest>"
	var ins edit
	base64At := len("<c2pa:manifest>")
	switch {
	case doc.metaStart >= 0 && !doc.metaSelfClosing:
		ins = edit{at: doc.metaEnd, insert: []byte(elem)}
	case doc.metaStart >= 0:
		// <metadata/> → <metadata>…</metadata>
		ins = edit{at: doc.metaEnd - 2, remove: 2, insert: []byte(">" + elem + "</" + doc.metaQName + ">")}
		base64At++
	default:
		meta := "metadata"
		if i := strings.IndexByte(doc.rootQName, ':'); i >= 0 {
			meta = doc.rootQName[:i] + ":metadata"
		}
		wrapped := "<" + meta + ">" + elem + "</" + meta + ">"
		if doc.rootSelfClosing {
			ins = edit{at: doc.rootEnd - 2, remove: 2, insert: []byte(">" + wrapped + "</" + doc.rootQName + ">")}
			base64At += 1 + len("<"+meta+">")
		} else {
			ins = edit{at: doc.rootEnd, insert: []byte(wrapped)}
			base64At += len("<" + meta + ">")
		}
	}
	edits = append(edits, ins)
	out, placed, _, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	return out, []byteRange{{start: placed[len(edits)-1] + base64At, length: len(encoded)}}, nil
}
