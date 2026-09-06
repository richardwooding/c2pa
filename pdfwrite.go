package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
)

// Writing a manifest store into a PDF (spec §A.4): an incremental update
// appended after the last %%EOF that adds the embedded file stream, its file
// specification, and a new definition of the document catalog carrying /AF and
// /Names/EmbeddedFiles, then a cross-reference section — a classic table when
// the document uses tables, an uncompressed cross-reference stream when it
// uses streams — whose /Prev links back to the section that resolved the
// catalog. Nothing before the appended bytes changes, which is how PDF is
// meant to be edited and what lets a prior update section's store stay put.
//
// c2pa-rs has no PDF writer, so there is no reference layout to match; its
// reader wants exactly what §A.4.2.1 says — the current catalog's /AF naming a
// file specification with /AFRelationship /C2PA_Manifest — and that is what
// this writes, in the shape the ChatGPT fixture's own producer used.

// pdfEmbedder appends the incremental update.
type pdfEmbedder struct{}

// pdfWriteContext is what the resolving cross-reference section says about the
// document: the catalog and where it lives, the section's offset (the new
// section's /Prev), whether it is a stream, and the trailer entries to carry.
type pdfWriteContext struct {
	rootNum, rootGen int
	loc              pdfXrefLoc
	xrefOffset       int
	stream           bool
	size             int
	info, id         []byte
	encrypted        bool
}

// pdfResolveForWrite finds the catalog the way pdfXrefRoot does — the newest
// startxref whose /Prev chain PLACES the /Root object at a definition that is
// a catalog — but keeps what the writer needs from the chain. A document whose
// catalog is only reachable by lexical guessing is refused: appending to it
// would build on a foundation the reader itself does not trust.
func pdfResolveForWrite(ctx context.Context, data []byte, objs *pdfObjects) (pdfWriteContext, error) {
	end := len(data)
	for tries := 0; tries < maxPDFXrefStarts; tries++ {
		p := bytes.LastIndex(data[:end], []byte("startxref"))
		if p < 0 {
			break
		}
		end = p
		pos, _, ok := pdfUint(data, pdfSkipSpace(data, p+len("startxref")), len(data))
		if !ok {
			continue
		}
		wc, ok := pdfChainForWrite(ctx, data, objs, pos)
		if ok && objs.catalog(wc.rootNum, wc.loc, true) != nil {
			return wc, nil
		}
	}
	return pdfWriteContext{}, fmt.Errorf("%w: PDF catalog is not placed by any cross-reference section", errCarrierUnsupported)
}

// pdfChainForWrite walks one /Prev chain, gathering the write context. The
// newest section's trailer supplies /Size, /Info and /ID; /Encrypt anywhere in
// the chain marks the document encrypted.
func pdfChainForWrite(ctx context.Context, data []byte, objs *pdfObjects, pos int) (pdfWriteContext, bool) {
	wc := pdfWriteContext{xrefOffset: pos}
	locs := map[int]pdfXrefLoc{}
	for hop := 0; hop < maxPDFXrefHops; hop++ {
		if ctx.Err() != nil || pos <= 0 || pos >= len(data) {
			break
		}
		if hop == 0 {
			q := pdfSkipSpace(data, pos)
			wc.stream = !bytes.HasPrefix(data[q:], []byte("xref"))
		}
		trailer := pdfXrefSection(data, pos, objs, locs)
		if trailer == nil {
			break
		}
		if wc.rootNum == 0 {
			if n, g, ok := pdfRefGen(trailer, "Root"); ok {
				wc.rootNum, wc.rootGen = n, g
			}
		}
		if hop == 0 {
			wc.size, _ = pdfInt(trailer, "Size")
			if n, g, ok := pdfRefGen(trailer, "Info"); ok {
				wc.info = []byte(strconv.Itoa(n) + " " + strconv.Itoa(g) + " R")
			}
			if p := pdfFindName(trailer, "ID", 0); p >= 0 {
				if q := pdfSkipSpace(trailer, p); q < len(trailer) && trailer[q] == '[' {
					if e := pdfArrayEnd(trailer, q+1); e < len(trailer) {
						wc.id = trailer[q : e+1]
					}
				}
			}
		}
		if pdfFindName(trailer, "Encrypt", 0) >= 0 {
			wc.encrypted = true
		}
		prev, ok := pdfInt(trailer, "Prev")
		if !ok {
			break
		}
		pos = prev
	}
	if wc.rootNum == 0 {
		return wc, false
	}
	wc.loc = locs[wc.rootNum]
	return wc, wc.loc.found()
}

// pdfRefGen reads /key's value as an indirect reference, keeping the generation.
func pdfRefGen(b []byte, key string) (num, gen int, ok bool) {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return 0, 0, false
	}
	return pdfRefGenAt(b, p, len(b))
}

// pdfRefGenAt parses `N G R` at b[p:end].
func pdfRefGenAt(b []byte, p, end int) (num, gen int, ok bool) {
	p = pdfSkipSpace(b, p)
	num, p, ok = pdfUint(b, p, end)
	if !ok {
		return 0, 0, false
	}
	q := pdfSkipSpace(b, p)
	if q == p {
		return 0, 0, false
	}
	if gen, p, ok = pdfUint(b, q, end); !ok {
		return 0, 0, false
	}
	q = pdfSkipSpace(b, p)
	if q == p || q >= end || b[q] != 'R' {
		return 0, 0, false
	}
	return num, gen, true
}

// pdfEntry is one top-level key of a dictionary and the span of its value.
type pdfEntry struct {
	key        string
	start, end int
}

// pdfDictEntries tokenizes the first dictionary in b — `<<` through its
// matching `>>` — into top-level entries, returning the span of the whole
// dictionary too. Strings, hex strings, names, numbers, references, arrays and
// nested dictionaries are skipped as whole objects, so a `>>` inside a string
// does not end the scan.
func pdfDictEntries(b []byte) (open, close int, entries []pdfEntry, ok bool) {
	open = bytes.Index(b, []byte("<<"))
	if open < 0 {
		return 0, 0, nil, false
	}
	p := open + 2
	for {
		p = pdfSkipTokenSpace(b, p)
		if p >= len(b) {
			return 0, 0, nil, false
		}
		if bytes.HasPrefix(b[p:], []byte(">>")) {
			return open, p + 2, entries, true
		}
		if b[p] != '/' {
			return 0, 0, nil, false
		}
		k := p + 1
		for k < len(b) && !pdfIsSpace(b[k]) && !pdfIsDelim(b[k]) {
			k++
		}
		key := pdfUnescapeName(b[p+1 : k])
		vs := pdfSkipTokenSpace(b, k)
		ve, ok := pdfSkipValue(b, vs)
		if !ok {
			return 0, 0, nil, false
		}
		entries = append(entries, pdfEntry{key: key, start: vs, end: ve})
		p = ve
	}
}

// pdfSkipTokenSpace skips whitespace and comments.
func pdfSkipTokenSpace(b []byte, p int) int {
	for {
		p = pdfSkipSpace(b, p)
		if p < len(b) && b[p] == '%' {
			for p < len(b) && b[p] != '\n' && b[p] != '\r' {
				p++
			}
			continue
		}
		return p
	}
}

// pdfSkipValue returns the offset past the one object starting at b[p].
func pdfSkipValue(b []byte, p int) (int, bool) {
	p = pdfSkipTokenSpace(b, p)
	if p >= len(b) {
		return 0, false
	}
	switch b[p] {
	case '<':
		if p+1 < len(b) && b[p+1] == '<' {
			depth := 0
			for i := p; i < len(b); {
				switch {
				case bytes.HasPrefix(b[i:], []byte("<<")):
					depth++
					i += 2
				case bytes.HasPrefix(b[i:], []byte(">>")):
					depth--
					i += 2
					if depth == 0 {
						return i, true
					}
				case b[i] == '(':
					e, ok := pdfSkipValue(b, i)
					if !ok {
						return 0, false
					}
					i = e
				case b[i] == '<':
					e := bytes.IndexByte(b[i:], '>')
					if e < 0 {
						return 0, false
					}
					i += e + 1
				case b[i] == '%':
					i = pdfSkipTokenSpace(b, i)
				default:
					i++
				}
			}
			return 0, false
		}
		e := bytes.IndexByte(b[p:], '>')
		if e < 0 {
			return 0, false
		}
		return p + e + 1, true
	case '[':
		i := p + 1
		for {
			i = pdfSkipTokenSpace(b, i)
			if i >= len(b) {
				return 0, false
			}
			if b[i] == ']' {
				return i + 1, true
			}
			e, ok := pdfSkipValue(b, i)
			if !ok {
				return 0, false
			}
			i = e
		}
	case '(':
		depth := 0
		for i := p; i < len(b); i++ {
			switch b[i] {
			case '\\':
				i++
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return i + 1, true
				}
			}
		}
		return 0, false
	case '/':
		i := p + 1
		for i < len(b) && !pdfIsSpace(b[i]) && !pdfIsDelim(b[i]) {
			i++
		}
		return i, true
	case ']', '>', ')', '}', '{':
		return 0, false
	}
	// A number, a reference (N G R), or a keyword.
	if _, _, ok := pdfRefGenAt(b, p, len(b)); ok {
		_, next, _ := pdfRefAt(b, p, len(b))
		return next, true
	}
	i := p
	for i < len(b) && !pdfIsSpace(b[i]) && !pdfIsDelim(b[i]) {
		i++
	}
	if i == p {
		return 0, false
	}
	return i, true
}

// pdfDecodeString decodes a literal `(…)` or hex `<…>` string object.
func pdfDecodeString(raw []byte) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 {
		return nil, false
	}
	switch raw[0] {
	case '(':
		if raw[len(raw)-1] != ')' {
			return nil, false
		}
		var out []byte
		s := raw[1 : len(raw)-1]
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c != '\\' {
				out = append(out, c)
				continue
			}
			i++
			if i >= len(s) {
				return nil, false
			}
			switch s[i] {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '\n':
			case '\r':
				if i+1 < len(s) && s[i+1] == '\n' {
					i++
				}
			default:
				if s[i] >= '0' && s[i] <= '7' {
					v, n := 0, 0
					for n < 3 && i < len(s) && s[i] >= '0' && s[i] <= '7' {
						v = v*8 + int(s[i]-'0')
						i++
						n++
					}
					i--
					out = append(out, byte(v))
				} else {
					out = append(out, s[i])
				}
			}
		}
		return out, true
	case '<':
		if raw[len(raw)-1] != '>' {
			return nil, false
		}
		hex := bytes.Map(func(r rune) rune {
			if pdfIsSpace(byte(r)) {
				return -1
			}
			return r
		}, raw[1:len(raw)-1])
		if len(hex)%2 == 1 {
			hex = append(hex, '0')
		}
		out := make([]byte, len(hex)/2)
		for i := range out {
			v, err := strconv.ParseUint(string(hex[2*i:2*i+2]), 16, 8)
			if err != nil {
				return nil, false
			}
			out[i] = byte(v)
		}
		return out, true
	}
	return nil, false
}

// pdfIsC2PAFilespec reports whether object num is a file specification for a
// C2PA manifest — the ones the new catalog's /AF must stop naming so that one
// section associates one store (§15.5.2.2).
func pdfIsC2PAFilespec(objs *pdfObjects, num int) bool {
	body := objs.body(num)
	return body != nil && pdfName(pdfDict(body), "AFRelationship") == pdfC2PARelationship
}

// pdfRewriteCatalog copies every entry of the catalog dictionary verbatim except
// /AF, which loses any earlier C2PA file specification and gains ours, and
// /Names, which gains an EmbeddedFiles entry when that can be done in place:
// absent, a direct dictionary without EmbeddedFiles, or a flat direct name
// array. An indirect /Names or a Kids tree is copied untouched and the
// association rests on /AF alone — the normative one (ISO 32000-2 §14.13) and
// the only one c2pa-rs or this package reads.
func pdfRewriteCatalog(objs *pdfObjects, catalog []byte, spec int) ([]byte, error) {
	_, _, entries, ok := pdfDictEntries(catalog)
	if !ok {
		return nil, fmt.Errorf("%w: PDF catalog dictionary does not parse", errCarrierUnsupported)
	}
	if pdfFindName(catalog, "Perms", 0) >= 0 {
		return nil, fmt.Errorf("%w: certified PDF (/Perms); a later signature would invalidate it", errCarrierUnsupported)
	}
	ref := fmt.Sprintf("%d 0 R", spec)
	var out bytes.Buffer
	out.WriteString("<<")
	af, names := false, false
	for _, e := range entries {
		val := catalog[e.start:e.end]
		switch e.key {
		case "AF":
			af = true
			list := val
			if n, _, ok := pdfRefGenAt(val, 0, len(val)); ok && pdfPeek(val) != '[' {
				list = objs.body(n) // an indirect array
			}
			out.WriteString(" /AF [")
			for _, kept := range pdfRefsGen(list) {
				if !pdfIsC2PAFilespec(objs, kept.num) {
					fmt.Fprintf(&out, "%d %d R ", kept.num, kept.gen)
				}
			}
			out.WriteString(ref + "]")
		case "Names":
			names = true
			out.WriteString(" /Names " + pdfRewriteNames(objs, val, ref))
		default:
			out.WriteString(" /" + e.key + " ")
			out.Write(val)
		}
	}
	if !af {
		out.WriteString(" /AF [" + ref + "]")
	}
	if !names {
		out.WriteString(" /Names << /EmbeddedFiles << /Names [(Content Credentials) " + ref + "] >> >>")
	}
	out.WriteString(" >>")
	return out.Bytes(), nil
}

// pdfRef is an indirect reference with its generation.
type pdfRef struct{ num, gen int }

// pdfRefsGen collects the references in an array (or a single bare reference).
func pdfRefsGen(b []byte) []pdfRef {
	p := pdfSkipTokenSpace(b, 0)
	end := len(b)
	if p < end && b[p] == '[' {
		p++
		end = pdfArrayEnd(b, p)
	}
	var out []pdfRef
	for len(out) < maxPDFAssociatedFiles {
		n, g, ok := pdfRefGenAt(b, p, end)
		if !ok {
			break
		}
		out = append(out, pdfRef{n, g})
		_, p, _ = pdfRefAt(b, p, end)
	}
	return out
}

// pdfRewriteNames returns the catalog's /Names value with our file
// specification registered under EmbeddedFiles when that is possible in place,
// and the value verbatim otherwise.
func pdfRewriteNames(objs *pdfObjects, val []byte, ref string) string {
	ours := "(Content Credentials) " + ref
	if pdfPeek(val) != '<' {
		return string(val) // indirect: left alone
	}
	_, _, entries, ok := pdfDictEntries(val)
	if !ok {
		return string(val)
	}
	var out bytes.Buffer
	out.WriteString("<<")
	seen := false
	for _, e := range entries {
		v := val[e.start:e.end]
		if e.key != "EmbeddedFiles" {
			out.WriteString(" /" + e.key + " ")
			out.Write(v)
			continue
		}
		seen = true
		rebuilt, ok := pdfRewriteNameTree(objs, v, ref)
		if !ok {
			return string(val) // a Kids tree or an indirect node: leave the whole value alone
		}
		out.WriteString(" /EmbeddedFiles " + rebuilt)
	}
	if !seen {
		out.WriteString(" /EmbeddedFiles << /Names [" + ours + "] >>")
	}
	out.WriteString(" >>")
	return out.String()
}

// pdfRewriteNameTree rebuilds a flat, direct name-tree node: its /Names pairs
// minus any that name a C2PA file specification or carry our key, plus ours,
// in the byte order a name tree requires.
func pdfRewriteNameTree(objs *pdfObjects, node []byte, ref string) (string, bool) {
	if pdfPeek(node) != '<' {
		return "", false
	}
	_, _, entries, ok := pdfDictEntries(node)
	if !ok {
		return "", false
	}
	type pair struct {
		key      []byte
		raw, val []byte
	}
	var pairs []pair
	var other bytes.Buffer
	for _, e := range entries {
		v := node[e.start:e.end]
		switch e.key {
		case "Kids", "Limits":
			return "", false
		case "Names":
			if pdfPeek(v) != '[' {
				return "", false
			}
			p := bytes.IndexByte(v, '[') + 1
			for {
				p = pdfSkipTokenSpace(v, p)
				if p >= len(v) {
					return "", false
				}
				if v[p] == ']' {
					break
				}
				ke, ok := pdfSkipValue(v, p)
				if !ok {
					return "", false
				}
				vs := pdfSkipTokenSpace(v, ke)
				ve, ok := pdfSkipValue(v, vs)
				if !ok {
					return "", false
				}
				key, ok := pdfDecodeString(v[p:ke])
				if !ok {
					return "", false
				}
				if n, _, ok := pdfRefGenAt(v, vs, ve); ok && pdfIsC2PAFilespec(objs, n) || string(key) == "Content Credentials" {
					p = ve
					continue
				}
				pairs = append(pairs, pair{key: key, raw: v[p:ke], val: v[vs:ve]})
				p = ve
			}
		default:
			other.WriteString(" /" + e.key + " ")
			other.Write(v)
		}
	}
	pairs = append(pairs, pair{key: []byte("Content Credentials"), raw: []byte("(Content Credentials)"), val: []byte(ref)})
	sort.SliceStable(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].key, pairs[j].key) < 0 })
	var out bytes.Buffer
	out.WriteString("<<")
	out.Write(other.Bytes())
	out.WriteString(" /Names [")
	for i, p := range pairs {
		if i > 0 {
			out.WriteByte(' ')
		}
		out.Write(p.raw)
		out.WriteByte(' ')
		out.Write(p.val)
	}
	out.WriteString("] >>")
	return out.String(), true
}

func (pdfEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	if !bytes.Contains(asset[:min(len(asset), maxPDFHeaderSearch)], []byte("%PDF-")) {
		return nil, nil, fmt.Errorf("%w: not a PDF", errCarrierMalformed)
	}
	objs := indexPDFObjects(ctx, asset)
	objs.indexObjectStreams(ctx)
	wc, err := pdfResolveForWrite(ctx, asset, objs)
	if err != nil {
		return nil, nil, err
	}
	if wc.encrypted {
		return nil, nil, fmt.Errorf("%w: encrypted PDF", errCarrierUnsupported)
	}
	catalog := objs.catalog(wc.rootNum, wc.loc, true)
	if catalog == nil {
		return nil, nil, fmt.Errorf("%w: PDF catalog did not resolve", errCarrierUnsupported)
	}
	gen := wc.rootGen
	if wc.loc.offset > 0 {
		// The definition's own header is authoritative for the generation.
		if _, g, ok := pdfObjHeaderGen(asset, wc.loc.offset); ok {
			gen = g
		}
	}
	size := wc.size
	for _, ob := range objs.order {
		size = max(size, ob.num+1)
	}
	size = max(size, wc.rootNum+1)
	spec, file, xrefObj := size, size+1, size+2
	newCatalog, err := pdfRewriteCatalog(objs, catalog, spec)
	if err != nil {
		return nil, nil, err
	}

	out := append(make([]byte, 0, len(asset)+len(store)+1024), asset...)
	if c := out[len(out)-1]; c != '\n' && c != '\r' {
		out = append(out, '\n')
	}
	offFile := len(out)
	out = append(out, fmt.Sprintf("%d 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length %d >>\nstream\n", file, len(store))...)
	payloadAt := len(out)
	out = append(out, store...)
	out = append(out, "\nendstream\nendobj\n"...)
	offSpec := len(out)
	out = append(out, fmt.Sprintf("%d 0 obj\n<< /Type /Filespec /F (Content Credentials) /UF (Content Credentials) /Desc (Content Credentials)"+
		" /AFRelationship /C2PA_Manifest /EF << /F %d 0 R >> >>\nendobj\n", spec, file)...)
	offRoot := len(out)
	out = append(out, fmt.Sprintf("%d %d obj\n", wc.rootNum, gen)...)
	out = append(out, newCatalog...)
	out = append(out, "\nendobj\n"...)

	var trailer bytes.Buffer
	fmt.Fprintf(&trailer, "/Root %d %d R /Prev %d", wc.rootNum, gen, wc.xrefOffset)
	if wc.info != nil {
		trailer.WriteString(" /Info ")
		trailer.Write(wc.info)
	}
	if wc.id != nil {
		trailer.WriteString(" /ID ")
		trailer.Write(wc.id)
	}
	offXref := len(out)
	if !wc.stream {
		out = append(out, fmt.Sprintf("xref\n%d 1\n%010d %05d n \n%d 2\n%010d 00000 n \n%010d 00000 n \n",
			wc.rootNum, offRoot, gen, spec, offSpec, offFile)...)
		out = append(out, fmt.Sprintf("trailer\n<< /Size %d %s >>\n", file+1, trailer.String())...)
	} else {
		var rows []byte
		for _, r := range []struct{ off, gen int }{{offRoot, gen}, {offSpec, 0}, {offFile, 0}, {offXref, 0}} {
			rows = append(rows, 1)
			rows = binary.BigEndian.AppendUint32(rows, uint32(r.off))
			rows = binary.BigEndian.AppendUint16(rows, uint16(r.gen))
		}
		out = append(out, fmt.Sprintf("%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Index [%d 1 %d 3] %s /Length %d >>\nstream\n",
			xrefObj, xrefObj+1, wc.rootNum, spec, trailer.String(), len(rows))...)
		out = append(out, rows...)
		out = append(out, "\nendstream\nendobj\n"...)
	}
	out = append(out, fmt.Sprintf("startxref\n%d\n%%%%EOF\n", offXref)...)
	return out, []byteRange{{start: payloadAt, length: len(store)}}, nil
}

// pdfObjHeaderGen parses `N G obj` starting at hdr.
func pdfObjHeaderGen(data []byte, hdr int) (num, gen int, ok bool) {
	num, p, ok := pdfUint(data, hdr, len(data))
	if !ok {
		return 0, 0, false
	}
	gen, p, ok = pdfUint(data, pdfSkipSpace(data, p), len(data))
	if !ok {
		return 0, 0, false
	}
	p = pdfSkipSpace(data, p)
	if !bytes.HasPrefix(data[p:], []byte("obj")) {
		return 0, 0, false
	}
	return num, gen, true
}
