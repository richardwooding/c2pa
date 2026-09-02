package c2pa

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"encoding/binary"
	"io"
	"slices"
	"strconv"
)

// PDF container support: the manifest store sits in neither a marker segment
// nor a box of its own. Per C2PA spec §A.4.1 it is an embedded file stream
// (ISO 32000 §7.11.4) whose file specification carries /AFRelationship
// /C2PA_Manifest, and per §A.4.2.1 the document catalog's /AF array holds an
// indirect reference to the specification containing the active manifest. The
// stream payload is the raw JUMBF store.

// Objects are found lexically — the `N G obj … endobj` definitions visible in
// the bytes — and the document is then resolved the way a reader resolves it:
// cross-reference tables and streams place the objects, object streams are
// inflated to index what they hold. PDF 32000-1 §7.5.7 forbids a stream object
// inside an object stream but permits the file specification dictionary
// carrying the §A.4.1 markers, so the chain is what identifies the store.

// Incremental updates append rather than rewrite, so §A.4.2.1 makes the store
// in the most recent update section the active manifest: here the newest
// cross-reference section that places a /Root names the current catalog, and
// the last definition of an object number supersedes the ones before it.
// §A.4.2.1 also asks a consumer to process the stores of ALL update sections as
// one; that is not done — see pdfMarkedStore for how a superseded store surfaces.

// The names §A.4.1 gives the C2PA embedded file. The /Subtype is accepted but
// never required: the spec puts it on the file specification dictionary while
// ISO 32000 defines it on the stream dictionary, and the official C2PA test PDF
// carries it on neither.
const (
	pdfC2PARelationship = "C2PA_Manifest"
	pdfC2PAMediaType    = "application/c2pa"
)

// maxPDFObjects caps the object index. Indexed bodies are subslices of the
// input, so the cost is the index itself; a file of nothing but `0 0 obj`
// markers would otherwise index one entry per 8 bytes of input.
const maxPDFObjects = 1 << 18

// maxPDFAssociatedFiles caps how many /AF entries are followed. Real documents
// attach a handful of associated files, one of them the C2PA manifest.
const maxPDFAssociatedFiles = 64

// maxPDFInflate bounds the inflated bytes one extraction keeps: the stores and
// object-stream payloads it goes on to use. A manifest store is orders of
// magnitude smaller than this even with embedded thumbnails.
const maxPDFInflate = MaxScan

// maxPDFStreamInflate bounds one stream on its own. The budget above is charged
// only for inflated bytes that are kept, so a candidate that decodes to
// something that is not a store cannot spend another candidate's allowance —
// a single pool the first candidate can drain suppresses every later one.
const maxPDFStreamInflate = 8 << 20

// maxPDFHeaderSearch bounds the %PDF- header search. Readers tolerate leading
// junk before the header; requiring it somewhere near the front keeps the
// scanner off input that is not a PDF at all.
const maxPDFHeaderSearch = 1024

// maxPDFDictScan bounds how far into an object body a key lookup reads. The
// dictionary comes first and the ones these lookups care about run to a few
// hundred bytes; without a bound, a file of overlapping unterminated objects
// would cost a full scan per object.
const maxPDFDictScan = 2048

// maxPDFStoreAttempts caps how many candidate streams are decoded before the
// marker scan gives up, so a file that repeats a marker cannot make it inflate
// the rest of the file once per copy.
const maxPDFStoreAttempts = 32

// maxPDFXrefHops bounds the /Prev chain followed looking for a trailer that
// names /Root. Real documents name it in the newest trailer.
const maxPDFXrefHops = 32

// maxPDFLengthCandidates bounds how many definitions of one indirect /Length are
// tried. A conforming document defines it once; a run of them is a payload
// fabricating headers, and trying every one turns N streams naming N definitions
// into N² attempts.
const maxPDFLengthCandidates = 8

// maxPDFEndObjScan bounds the search for the `endobj` closing a repaired stream
// object. It sits just past an `endstream` the extent already verified, so a
// few bytes of whitespace is the real distance. Scanning to end of file instead
// made the repair pass quadratic: one full scan per repaired object, which a
// document that simply omits the keyword turns into minutes of CPU.
const maxPDFEndObjScan = 2048

// maxPDFXrefStarts bounds how many startxref keywords are tried, newest first,
// looking for one whose section places a /Root. A conforming document needs the
// first; the rest are for one with junk appended after %%EOF.
const maxPDFXrefStarts = 8

// maxPDFObjectStreams caps how many object streams are inflated to index what
// they hold, so a document full of them cannot spend the whole decompression
// budget on the object index alone.
const maxPDFObjectStreams = 16

// pdfObject is one `N G obj … endobj` definition. body is a subslice of the
// asset bytes running from just past the `obj` keyword to `endobj`, so a
// stream's payload stays addressable. hdr is where the definition starts and
// start where its body does, which is what re-cutting a body needs; for one
// recovered from an object stream, stm and idx say which stream held it and
// where. A cross-reference entry names one or the other.
type pdfObject struct {
	num   int
	hdr   int
	start int
	stm   int
	idx   int
	body  []byte
}

// pdfXrefLoc is where a cross-reference section says an object's current
// definition lives: at a byte offset (a type 1 entry), or at an index inside an
// object stream (type 2).
type pdfXrefLoc struct {
	offset int
	stm    int
	idx    int
}

// found reports whether the section actually placed the object.
func (l pdfXrefLoc) found() bool { return l.offset > 0 || l.stm > 0 }

// pdfObjects is the indexed object graph: every definition in file order, plus
// a lookup that resolves an object number to its newest definition.
type pdfObjects struct {
	order   []pdfObject
	newest  map[int]int   // object number → index into order
	byNum   map[int][]int // object number → every index, built on demand
	inflate int           // decompression budget left for this extraction
}

// body returns the newest visible definition of an object number, falling back
// to one recovered from an object stream. Visible wins because newest holds only
// definitions this scan can place, and a compressed definition it cannot place
// must not displace one an incremental update appended. The cost is fidelity the
// other way — an update that compresses an object the base section wrote plainly
// — which the catalog avoids by going through the cross-reference section.
func (o *pdfObjects) body(num int) []byte {
	if i, ok := o.newest[num]; ok {
		return o.order[i].body
	}
	for i := len(o.order) - 1; i >= 0; i-- {
		if o.order[i].num == num && o.order[i].stm > 0 {
			return o.order[i].body
		}
	}
	return nil
}

// catalog returns the document catalog's body. When a cross-reference section
// placed it, that placement is the only thing consulted: lexical order is what
// an appended decoy or a phantom `N G obj` in a content stream exploits, so a
// placement that does not resolve fails closed rather than guessing. Only a
// document with no usable section at all falls back to the newest definition.
func (o *pdfObjects) catalog(num int, loc pdfXrefLoc, placed bool) []byte {
	if placed {
		if !loc.found() {
			return nil
		}
		for i := range o.order {
			ob := o.order[i]
			if ob.num != num {
				continue
			}
			if (loc.stm > 0 && ob.stm == loc.stm && ob.idx == loc.idx) ||
				(loc.offset > 0 && ob.hdr == loc.offset) {
				return pdfIfCatalog(ob.body)
			}
		}
		return nil
	}
	// Visible definitions first. An object stream's contents are indexed after
	// every visible object, and file order says nothing about which revision
	// they belong to, so taking the last entry outright lets a stale compressed
	// catalog displace one an incremental update appended in plain sight.
	for _, compressed := range []bool{false, true} {
		for i := len(o.order) - 1; i >= 0; i-- {
			ob := o.order[i]
			if ob.num != num || (ob.stm > 0) != compressed {
				continue
			}
			if body := pdfIfCatalog(ob.body); body != nil {
				return body
			}
		}
	}
	return nil
}

// pdfIfCatalog returns body when it is a document catalog, which ISO 32000
// §7.7.2 requires /Type /Catalog to say.
func pdfIfCatalog(body []byte) []byte {
	if pdfName(pdfDict(body), "Type") == "Catalog" {
		return body
	}
	return nil
}

// pdfStoreSource says how a store was found. §A.4.1's markers are identical on a
// document-level manifest and on the object-level one §A.4.3 describes, so only
// the catalog's /AF reference attributes a store to the document.
type pdfStoreSource int

const (
	pdfStoreNone pdfStoreSource = iota
	// pdfStoreCatalog: reached through the catalog's /AF, so it is the
	// document's active manifest.
	pdfStoreCatalog
	// pdfStoreMarker: found by the markers with no catalog to attribute it, so
	// it may govern an embedded file rather than the document.
	pdfStoreMarker
)

// pdfJUMBF locates the C2PA manifest store in a PDF and returns its raw JUMBF
// bytes. Returns nil when the document carries none.
func pdfJUMBF(ctx context.Context, data []byte) []byte {
	_, store, _ := pdfScan(ctx, data)
	return store
}

// pdfScan locates the store and reports how it was found, returning the object
// index so a caller can ask more of it without indexing the document again.
func pdfScan(ctx context.Context, data []byte) (*pdfObjects, []byte, pdfStoreSource) {
	if !bytes.Contains(data[:min(len(data), maxPDFHeaderSearch)], []byte("%PDF-")) {
		return nil, nil, pdfStoreNone
	}
	objs := indexPDFObjects(ctx, data)
	if len(objs.order) == 0 {
		return objs, nil, pdfStoreNone
	}
	objs.indexObjectStreams(ctx)
	if store := pdfActiveStore(ctx, data, objs); store != nil {
		return objs, store, pdfStoreCatalog
	}
	// Nothing the catalog associates. The markers may still find a store, but
	// they cannot say it is the document's — §A.4.3 puts the same relationship on
	// a manifest describing an embedded file. Reported as unattributed rather
	// than dropped: an attachment carrying provenance is a finding, and silence
	// leaves a caller unable to see it at all.
	if store := pdfMarkedStore(ctx, objs); store != nil {
		return objs, store, pdfStoreMarker
	}
	return objs, nil, pdfStoreNone
}

// indexPDFObjects indexes every visible indirect object definition. A later
// definition of the same object number supersedes an earlier one: that is what
// an incremental update is.
func indexPDFObjects(ctx context.Context, data []byte) *pdfObjects {
	objs := &pdfObjects{newest: map[int]int{}, inflate: maxPDFInflate}
	// endobj advances monotonically: once we know where the next `endobj` is,
	// or that there is none, later headers reuse it. Re-searching per header
	// would cost a full scan each for a file of unterminated objects.
	endobj := -1
	for i := 0; i < len(data) && len(objs.order) < maxPDFObjects; {
		if ctx.Err() != nil {
			return objs
		}
		k := bytes.Index(data[i:], []byte("obj"))
		if k < 0 {
			break
		}
		pos := i + k
		i = pos + len("obj")
		num, hdr, ok := pdfObjNumber(data, pos)
		if !ok {
			continue
		}
		// Search past the stream payload where the dictionary settles its
		// extent: the store is arbitrary binary, so it can spell `endobj`, and
		// ending the body there would lose it. from only ever advances, so the
		// searches stay non-overlapping and the scan stays linear.
		from := max(i, pdfStreamEnd(data, i))
		if endobj < from {
			if e := bytes.Index(data[from:], []byte("endobj")); e >= 0 {
				endobj = from + e
			} else {
				endobj = len(data)
			}
		}
		objs.newest[num] = len(objs.order)
		objs.order = append(objs.order, pdfObject{
			num: num, hdr: hdr, start: i, body: data[i:endobj],
		})
	}
	objs.repairIndirectLengths(ctx, data)
	return objs
}

// repairIndirectLengths re-cuts the stream objects whose extent the forward pass
// could not settle. An indirect /Length names an object that may be defined
// later in the file, so it resolves only once the index is complete; until then
// the object ends at the first `endobj`, and a manifest store is arbitrary
// binary that can spell one. Runs before any object stream is indexed, so every
// entry here is a visible definition whose start addresses the asset bytes.
func (o *pdfObjects) repairIndirectLengths(ctx context.Context, data []byte) {
	var payloads []pdfSpan

	for i := range o.order {
		if ctx.Err() != nil {
			return
		}
		obj := &o.order[i]
		// Scoped to this object's own body, never to data: the keyword search reads maxPDFDictScan
		// bytes ahead, so scanning the whole input lets a short dictionary find the NEXT object's
		// `stream` and its /Length and be re-cut straight through it.
		body := data[obj.start : obj.start+len(obj.body)]
		rel, ok := pdfStreamKeyword(body, 0)
		if !ok {
			continue
		}
		// Only an indirect /Length is unfinished business: a direct one the
		// forward pass either used or rejected as a lie, and re-deciding it here
		// would undo that.
		refs := pdfRefs(body[:rel], "Length", 1)
		if len(refs) == 0 {
			continue
		}
		start := obj.start + rel
		end := o.resolveStreamExtent(ctx, data, refs[0], start)
		if end <= 0 {
			continue
		}
		obj.body = data[obj.start:pdfEndObj(data, end)]
		payloads = append(payloads, pdfSpan{from: start, to: end})
	}
	o.dropIndexedWithin(ctx, payloads)
}

// resolveStreamExtent reads the length object and returns where the payload
// opening at start ends. Definitions are tried in file order rather than newest
// first, because a payload can spell the length object's own header. Two things
// make a candidate: landing on `endstream`, and its own header sitting outside
// the extent it claims — a length object cannot live inside the payload it
// measures, and a phantom that points past itself is exactly what does.
func (o *pdfObjects) resolveStreamExtent(ctx context.Context, data []byte, num, start int) int {
	for tried, i := range o.definitions(num) {
		if tried >= maxPDFLengthCandidates || ctx.Err() != nil {
			return 0
		}
		n, ok := pdfIntBody(o.order[i].body)
		if !ok {
			continue
		}
		end := pdfStreamExtent(data, start, n)
		if end <= 0 {
			continue
		}
		if hdr := o.order[i].hdr; hdr >= start && hdr < end {
			continue
		}
		return end
	}
	return 0
}

// definitions returns every index in order defining an object number, built once
// and reused: resolving each stream by walking the whole index instead would be
// quadratic in a document that repeats one length object's number.
func (o *pdfObjects) definitions(num int) []int {
	if o.byNum == nil {
		o.byNum = make(map[int][]int, len(o.order))
		for i := range o.order {
			o.byNum[o.order[i].num] = append(o.byNum[o.order[i].num], i)
		}
	}
	return o.byNum[num]
}

// pdfSpan is a half-open byte range of the input.
type pdfSpan struct{ from, to int }

// dropIndexedWithin forgets the definitions indexed out of a stream payload, now
// that its real extent is known: while unresolved, the object ended at the
// payload's first `endobj` and the scan carried on through the rest, so
// header-shaped bytes became entries. Both order and the spans ascend by file
// position, so one merged walk replaces a span scan per object — 200k indirect
// streams is 200k spans. Cancelling abandons the prune, index untouched.
func (o *pdfObjects) dropIndexedWithin(ctx context.Context, payloads []pdfSpan) {
	if len(payloads) == 0 || ctx.Err() != nil {
		return
	}
	merged := pdfMergeSpans(payloads)

	kept, next := make([]pdfObject, 0, len(o.order)), 0
	for i := range o.order {
		if i%4096 == 0 && ctx.Err() != nil {
			return
		}
		hdr := o.order[i].hdr
		for next < len(merged) && merged[next].to <= hdr {
			next++
		}
		if next < len(merged) && hdr >= merged[next].from {
			continue
		}
		kept = append(kept, o.order[i])
	}
	o.order = kept
	o.byNum = nil
	o.newest = make(map[int]int, len(kept))
	for i := range kept {
		o.newest[kept[i].num] = i
	}
}

// pdfMergeSpans sorts the spans and coalesces the ones that touch, so a single
// cursor can walk them alongside the objects.
func pdfMergeSpans(spans []pdfSpan) []pdfSpan {
	slices.SortFunc(spans, func(a, b pdfSpan) int { return a.from - b.from })

	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.from <= last.to {
			last.to = max(last.to, s.to)
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// pdfIntBody reads the integer an object body holds on its own, which is what an
// indirect /Length points at.
func pdfIntBody(body []byte) (int, bool) {
	p := pdfSkipSpace(body, 0)
	n, _, ok := pdfUint(body, p, len(body))
	return n, ok
}

// pdfEndObj returns where the `endobj` at or after from starts, searching a
// bounded window. When the keyword is absent the window's end is returned: the
// caller has already established the payload ends before from, so the body
// still contains the whole stream.
func pdfEndObj(data []byte, from int) int {
	limit := min(from+maxPDFEndObjScan, len(data))
	if e := bytes.Index(data[from:limit], []byte("endobj")); e >= 0 {
		return from + e
	}
	return limit
}

// indexObjectStreams adds the objects held inside every visible /Type /ObjStm.
// §7.5.7 forbids a stream object in one, but it permits the file specification
// dictionary that carries the §A.4.1 markers, so a conforming document can hide
// its whole pointer chain there. An object stream is itself a visible stream,
// which is what makes recovering the chain cheap.
func (o *pdfObjects) indexObjectStreams(ctx context.Context) {
	// Snapshot the length: the objects being added are not object streams
	// themselves, since §7.5.7 forbids nesting them.
	visible, streams := len(o.order), 0
	for i := 0; i < visible && streams < maxPDFObjectStreams; i++ {
		if ctx.Err() != nil {
			return
		}
		body := o.order[i].body
		if pdfName(pdfDict(body), "Type") != "ObjStm" {
			continue
		}
		streams++
		o.indexObjStm(o.order[i].num, body)
	}
}

// indexObjStm adds what one object stream holds. Its payload opens with /N pairs
// of object number and offset, each relative to /First, and the bodies follow in
// the same order, so one pair's offset bounds the body before it.
func (o *pdfObjects) indexObjStm(stm int, body []byte) {
	dict, raw := o.streamPayload(body)
	n, okN := pdfInt(dict, "N")
	first, okF := pdfInt(dict, "First")
	if len(raw) == 0 || !okN || !okF || n <= 0 || n > maxPDFObjects || first < 0 {
		return
	}
	payload, inflated := o.decodeStream(dict, raw)
	if first > len(payload) {
		return
	}
	nums, offs, p := make([]int, 0, n), make([]int, 0, n), 0
	for i := 0; i < n; i++ {
		num, q, ok := pdfUint(payload, pdfSkipSpace(payload, p), first)
		if !ok {
			break
		}
		off, q, ok := pdfUint(payload, pdfSkipSpace(payload, q), first)
		if !ok {
			break
		}
		nums, offs, p = append(nums, num), append(offs, off), q
	}
	if len(nums) == 0 {
		// Nothing was indexed, so nothing of this payload is kept and the shared
		// budget must not be charged for it — two decoys that decode to garbage
		// would otherwise spend it all and starve the stream holding the chain.
		return
	}
	if inflated {
		o.inflate -= len(payload)
	}
	for i := range nums {
		if len(o.order) >= maxPDFObjects {
			return
		}
		start, end := first+offs[i], len(payload)
		if i+1 < len(offs) {
			end = min(end, first+offs[i+1])
		}
		if start < first || start > end {
			continue
		}
		// newest is deliberately not updated: file order says nothing about which
		// revision an object stream belongs to, so a stale compressed definition
		// must not displace a visible one an incremental update appended. The
		// cross-reference section is what places these, via stm and idx.
		o.order = append(o.order, pdfObject{
			num: nums[i], stm: stm, idx: i, body: payload[start:end],
		})
	}
}

// pdfStreamEnd returns the offset just past the stream payload of the object
// whose body starts at i, when the object's own dictionary settles where it
// ends: a direct /Length that lands on `endstream`. Returns 0 otherwise — an
// indirect /Length cannot be resolved while the index is still being built, so
// such an object keeps falling back to the first `endobj`.
func pdfStreamEnd(data []byte, i int) int {
	start, ok := pdfStreamKeyword(data, i)
	if !ok {
		return 0
	}
	n, ok := pdfInt(data[i:start], "Length")
	if !ok || n < 0 {
		return 0
	}
	return pdfStreamExtent(data, start, n)
}

// pdfStreamKeyword finds the `stream` keyword opening the body that starts at i,
// as a whole token so `endstream` cannot pass for one.
func pdfStreamKeyword(data []byte, i int) (int, bool) {
	k := bytes.Index(data[i:min(len(data), i+maxPDFDictScan)], []byte("stream"))
	if k < 0 {
		return 0, false
	}
	start := i + k
	if start > 0 && !pdfIsSpace(data[start-1]) && !pdfIsDelim(data[start-1]) {
		return 0, false
	}
	return start, true
}

// pdfStreamExtent returns the offset just past a payload of n bytes opening at
// the `stream` keyword at start, when n lands on `endstream`. Returns 0 when it
// does not, so a length that lies never decides where the object ends.
func pdfStreamExtent(data []byte, start, n int) int {
	if n < 0 {
		return 0
	}
	p := start + len("stream")
	if p < len(data) && data[p] == '\r' {
		p++
	}
	if p < len(data) && data[p] == '\n' {
		p++
	}
	if p+n < p || p+n > len(data) ||
		!bytes.HasPrefix(bytes.TrimLeft(data[p+n:], "\x00\t\n\f\r "), []byte("endstream")) {
		return 0
	}
	return p + n
}

// pdfObjNumber parses the `N G obj` header whose `obj` keyword starts at pos,
// returning the object number and where the header starts. It insists on the
// whole token shape — digits, space, digits, space, `obj`, delimiter — so
// neither the `obj` inside `endobj` nor a chance occurrence in stream bytes
// indexes a phantom object.
func pdfObjNumber(data []byte, pos int) (num, hdr int, ok bool) {
	if p := pos + len("obj"); p < len(data) && !pdfIsSpace(data[p]) && !pdfIsDelim(data[p]) {
		return 0, 0, false
	}
	i := pdfSkipSpaceBack(data, pos)
	if i == pos {
		return 0, 0, false
	}
	_, i, ok = pdfUintBack(data, i) // generation number
	if !ok {
		return 0, 0, false
	}
	j := pdfSkipSpaceBack(data, i)
	if j == i {
		return 0, 0, false
	}
	num, j, ok = pdfUintBack(data, j)
	if !ok {
		return 0, 0, false
	}
	if j > 0 && !pdfIsSpace(data[j-1]) && !pdfIsDelim(data[j-1]) {
		return 0, 0, false
	}
	return num, j, true
}

// pdfActiveStore returns the active manifest by the route §A.4.2.1 defines: the
// current trailer's /Root names the document catalog, whose /AF array lists the
// associated files, and the one whose /AFRelationship is /C2PA_Manifest carries
// the store in its /EF stream. Returns nil when that chain names no C2PA file,
// which is the only thing that can attribute a store to the document.
func pdfActiveStore(ctx context.Context, data []byte, objs *pdfObjects) []byte {
	root, loc, placed := pdfXrefRoot(ctx, data, objs)
	if !placed {
		var ok bool
		if root, ok = pdfRootLexical(ctx, data); !ok {
			return nil
		}
	}
	catalog := objs.catalog(root, loc, placed)
	if catalog == nil {
		return nil
	}
	for _, ref := range pdfAssociatedFiles(objs, catalog) {
		if ctx.Err() != nil {
			return nil
		}
		filespec := objs.body(ref)
		if filespec == nil || pdfName(pdfDict(filespec), "AFRelationship") != pdfC2PARelationship {
			continue
		}
		if store := pdfEmbeddedStore(ctx, objs, filespec); store != nil {
			return store
		}
	}
	return nil
}

// pdfMarkedStore scans the visible objects, newest first, for a C2PA embedded
// file by the markers §A.4.1 puts on it: a file specification carrying the
// /C2PA_Manifest relationship, or failing that a stream declaring the C2PA
// media type as its /Subtype. It picks up a document whose pointer chain is
// compressed out of sight, and a store from an earlier update section that the
// current catalog no longer associates — §15.5.2.2 keeps those valid.
func pdfMarkedStore(ctx context.Context, objs *pdfObjects) []byte {
	// A store found this way may equally be an object-level manifest (§A.4.3),
	// which describes an embedded image or font rather than the document; the
	// markers are the same and nothing distinguishes them here.
	attempts := 0
	for _, marker := range []struct {
		key, want string
		read      func([]byte, string) string
	}{
		// ISO 32000 defines /AFRelationship as a name, so a literal string is
		// not a spelling of it. Only the C2PA /Subtype media type is written
		// either way.
		{"AFRelationship", pdfC2PARelationship, pdfName},
		{"Subtype", pdfC2PAMediaType, pdfText},
	} {
		for i := len(objs.order) - 1; i >= 0 && attempts < maxPDFStoreAttempts; i-- {
			if ctx.Err() != nil {
				return nil
			}
			body := objs.order[i].body
			if marker.read(pdfDict(body), marker.key) != marker.want {
				continue
			}
			attempts++
			if store := pdfEmbeddedStore(ctx, objs, body); store != nil {
				return store
			}
		}
	}
	return nil
}

// pdfStoreTally counts the manifest stores this document associates with itself.
// perSection is the most any one update section's catalog associates, which is
// what §15.5.2.2 makes invalid. attributed is false when no catalog associated
// anything and the count came from the markers instead.
type pdfStoreTally struct {
	total      int
	perSection int
	attributed bool
}

// pdfTallyStores counts the distinct embedded-file streams the document's own
// catalogs associate as C2PA, per update section. An object-level manifest
// (§A.4.3) is associated from the object it describes rather than from a
// catalog, so an attachment carrying one is not a store of this document.
func pdfTallyStores(ctx context.Context, data []byte, objs *pdfObjects) pdfStoreTally {
	if objs == nil {
		return pdfStoreTally{}
	}
	bounds := pdfSectionBounds(data)
	seen, perSection := map[int]bool{}, map[int]int{}
	for i := range objs.order {
		if ctx.Err() != nil {
			break
		}
		catalog := pdfIfCatalog(objs.order[i].body)
		if catalog == nil {
			continue
		}
		section := pdfSectionOf(bounds, objs.order[i].hdr)
		for _, ref := range pdfAssociatedFiles(objs, catalog) {
			filespec := objs.body(ref)
			if filespec == nil ||
				pdfName(pdfDict(filespec), "AFRelationship") != pdfC2PARelationship {
				continue
			}
			if num, ok := pdfEmbeddedFileRef(filespec); ok && !seen[num] {
				seen[num] = true
				perSection[section]++
			}
		}
	}
	if len(seen) == 0 {
		return pdfStoreTally{total: pdfMarkedCount(ctx, objs)}
	}
	high := 0
	for _, n := range perSection {
		high = max(high, n)
	}
	return pdfStoreTally{total: len(seen), perSection: high, attributed: true}
}

// pdfMarkedCount counts the distinct stores the §A.4.1 markers point at, for a
// document whose catalogs associate none — where the extractor is least sure of
// itself and the count must not go silent.
func pdfMarkedCount(ctx context.Context, objs *pdfObjects) int {
	seen := map[int]bool{}
	for i := range objs.order {
		if ctx.Err() != nil {
			break
		}
		body := objs.order[i].body
		dict := pdfDict(body)
		if pdfName(dict, "AFRelationship") != pdfC2PARelationship &&
			pdfText(dict, "Subtype") != pdfC2PAMediaType {
			continue
		}
		if num, ok := pdfEmbeddedFileRef(body); ok {
			seen[num] = true
			continue
		}
		seen[objs.order[i].num] = true
	}
	return len(seen)
}

// pdfSectionBounds returns where each update section ends. An incremental update
// appends a whole section ending in %%EOF, which is the only revision boundary a
// lexical scan can see.
func pdfSectionBounds(data []byte) []int {
	var out []int
	for i := 0; i < len(data) && len(out) < maxPDFXrefHops; {
		k := bytes.Index(data[i:], []byte("%%EOF"))
		if k < 0 {
			break
		}
		out = append(out, i+k)
		i += k + len("%%EOF")
	}
	return out
}

// pdfSectionOf reports which update section a byte offset falls in. An object
// recovered from an object stream has no offset of its own and counts as the
// first section.
func pdfSectionOf(bounds []int, off int) int {
	for i, end := range bounds {
		if off <= end {
			return i
		}
	}
	return len(bounds)
}

// pdfAssociatedFiles returns the object numbers in a catalog's /AF, stepping
// through an indirect reference to the array.
func pdfAssociatedFiles(objs *pdfObjects, catalog []byte) []int {
	refs := pdfRefs(catalog, "AF", maxPDFAssociatedFiles)
	if len(refs) == 1 {
		if b := objs.body(refs[0]); pdfPeek(b) == '[' {
			return pdfRefList(b, maxPDFAssociatedFiles)
		}
	}
	return refs
}

// pdfEmbeddedStore resolves a file specification to its embedded-file stream
// and returns the JUMBF store inside it. The relationship and media type also
// appear on the stream object itself in some producers' output, so a body that
// has no /EF is retried as the stream.
func pdfEmbeddedStore(ctx context.Context, objs *pdfObjects, filespec []byte) []byte {
	if num, ok := pdfEmbeddedFileRef(filespec); ok {
		if store := objs.streamStore(ctx, objs.body(num)); store != nil {
			return store
		}
	}
	return objs.streamStore(ctx, filespec)
}

// pdfEmbeddedFileRef returns the object number of a file specification's
// embedded-file stream: the /EF dictionary's /F entry, falling back to the
// Unicode and platform-specific keys.
func pdfEmbeddedFileRef(filespec []byte) (int, bool) {
	dict := pdfDict(filespec)
	p := pdfFindName(dict, "EF", 0)
	if p < 0 {
		return 0, false
	}
	for _, key := range []string{"F", "UF", "DOS", "Mac", "Unix"} {
		if refs := pdfRefs(dict[p:], key, 1); len(refs) == 1 {
			return refs[0], true
		}
	}
	return 0, false
}

// streamStore decodes an object's stream and returns the JUMBF manifest store
// it holds, trimmed to the superbox's own length (the stream may be padded).
// Returns nil unless the decoded bytes really are a JUMBF superbox, which is
// what keeps a lexical mis-hit harmless.
func (o *pdfObjects) streamStore(ctx context.Context, body []byte) []byte {
	if ctx.Err() != nil || len(body) == 0 {
		return nil
	}
	dict, raw := o.streamPayload(body)
	if len(raw) == 0 {
		return nil
	}
	store, inflated := o.decodeStream(dict, raw)
	if !looksLikeJUMBF(store, 0, len(store)) {
		return nil
	}
	if inflated {
		o.inflate -= len(store)
	}
	return store[:binary.BigEndian.Uint32(store[:4])]
}

// streamPayload returns the still-encoded bytes between an object's `stream`
// keyword and its `endstream`. /Length is verified against `endstream` before
// use, so one that lies cannot slice past the object and the keyword search
// bounds the payload instead; an indirect one is resolved through the index,
// which is what reaches a payload whose own bytes spell `endstream`. Trailing
// bytes are left on: an uncompressed store is trimmed by its superbox length.
func (o *pdfObjects) streamPayload(body []byte) (dict, payload []byte) {
	for pos := 0; pos < len(body); {
		k := bytes.Index(body[pos:], []byte("stream"))
		if k < 0 {
			return nil, nil
		}
		start := pos + k
		pos = start + len("stream")
		if start > 0 && !pdfIsSpace(body[start-1]) && !pdfIsDelim(body[start-1]) {
			continue // part of a longer token, e.g. `endstream`
		}
		dict, p := body[:start], pos
		// ISO 32000 §7.3.8.1 allows only CRLF or LF after the keyword, never a
		// bare CR. A bare CR is read anyway: producers emit it, and refusing it
		// would lose the store over a byte no reader objects to.
		if p >= len(body) || (body[p] != '\r' && body[p] != '\n') {
			continue
		}
		if body[p] == '\r' {
			p++
		}
		if p < len(body) && body[p] == '\n' {
			p++
		}
		n, ok := pdfInt(dict, "Length")
		if !ok {
			if refs := pdfRefs(dict, "Length", 1); len(refs) == 1 {
				n, ok = pdfIntBody(o.body(refs[0]))
			}
		}
		if ok && n >= 0 && p+n <= len(body) &&
			bytes.HasPrefix(bytes.TrimLeft(body[p+n:], "\x00\t\n\f\r "), []byte("endstream")) {
			return dict, body[p : p+n]
		}
		e := bytes.Index(body[p:], []byte("endstream"))
		if e < 0 {
			return nil, nil
		}
		return dict, body[p : p+e]
	}
	return nil, nil
}

// decodeStream applies the stream's /Filter. The spec says nothing about
// filters on this stream — §A.4.1 covers only encryption, where the crypt
// filter must be Identity, hence the /Crypt pass-through — so both an
// unfiltered store and a /FlateDecode one are read. Any other filter is left
// undecoded: the caller then sees non-JUMBF bytes and reports no manifest
// rather than guessing.
// inflated reports whether the bytes came out of a decompressor, so the caller
// can charge the shared budget once it decides to keep them.
func (o *pdfObjects) decodeStream(dict, raw []byte) (out []byte, inflated bool) {
	filters := pdfNames(dict, "Filter", 3)
	if len(filters) > 0 && filters[0] == "Crypt" {
		filters = filters[1:]
	}
	switch {
	case len(filters) == 0:
		return raw, false
	case len(filters) == 1 && (filters[0] == "FlateDecode" || filters[0] == "Fl"):
		return pdfInflate(raw, min(o.inflate, maxPDFStreamInflate)), true
	default:
		return nil, false
	}
}

// pdfInflate decompresses a /FlateDecode stream, up to limit bytes. PDF's
// FlateDecode is zlib-wrapped; a raw deflate payload (which some producers
// emit) is retried without the wrapper. Whatever decoded before an error is
// kept, so a truncated stream still yields the store when the store came first.
func pdfInflate(raw []byte, limit int) []byte {
	if limit <= 0 {
		return nil
	}
	if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
		out := pdfDrain(zr, limit)
		_ = zr.Close()
		if len(out) > 0 {
			return out
		}
	}
	fr := flate.NewReader(bytes.NewReader(raw))
	out := pdfDrain(fr, limit)
	_ = fr.Close()
	return out
}

func pdfDrain(r io.Reader, limit int) []byte {
	out, _ := io.ReadAll(io.LimitReader(r, int64(limit)))
	return out
}

// pdfXrefRoot resolves the catalog the way a conforming reader does: a startxref
// gives the offset of a cross-reference section, whose trailer names /Root. The
// last one is tried first and an earlier one only when its section places no
// /Root at all, so junk appended after %%EOF cannot hide the genuine table by
// bringing a startxref of its own. loc is where that section says the catalog
// lives, zero when it does not place it.
func pdfXrefRoot(
	ctx context.Context,
	data []byte,
	objs *pdfObjects,
) (root int, loc pdfXrefLoc, ok bool) {
	end, named := len(data), 0
	for tries := 0; tries < maxPDFXrefStarts; tries++ {
		p := bytes.LastIndex(data[:end], []byte("startxref"))
		if p < 0 {
			break
		}
		end = p
		pos, _, spelled := pdfUint(data, pdfSkipSpace(data, p+len("startxref")), len(data))
		if !spelled {
			continue
		}
		candidate, at, placed := pdfXrefChain(ctx, data, objs, pos)
		// An in-use entry is not a resolution: the offset it carries has to land on the catalog it
		// names. One placing /Root at offset 1 would otherwise take the document and leave the
		// genuine earlier startxref untried.
		if placed && objs.catalog(candidate, at, true) != nil {
			return candidate, at, true
		}
		if candidate > 0 && named == 0 {
			named = candidate
		}
	}
	if named > 0 {
		// Some section named a catalog and no section placed it. Reported as placed with nowhere to
		// look, so the caller fails closed rather than falling back to lexical order, which is the
		// thing an appended decoy exploits.
		return named, pdfXrefLoc{}, true
	}
	return 0, pdfXrefLoc{}, false
}

// pdfXrefChain walks the /Prev chain from the section at pos and returns the
// /Root it names, root being non-zero once some trailer named one and placed
// reporting whether the chain also placed that object. The whole chain is
// walked: an object the newest update did not touch is placed by an older
// section. Earlier sections never overwrite what a newer one already said, and
// each candidate startxref gets its own placements so a decoy cannot seed them.
func pdfXrefChain(
	ctx context.Context,
	data []byte,
	objs *pdfObjects,
	pos int,
) (root int, loc pdfXrefLoc, placed bool) {
	locs, found := map[int]pdfXrefLoc{}, false
	for hop := 0; hop < maxPDFXrefHops; hop++ {
		if ctx.Err() != nil || pos <= 0 || pos >= len(data) {
			break
		}
		trailer := pdfXrefSection(data, pos, objs, locs)
		if trailer == nil {
			break
		}
		if !found {
			if refs := pdfRefs(trailer, "Root", 1); len(refs) == 1 {
				root, found = refs[0], true
			}
		}
		prev, hasPrev := pdfInt(trailer, "Prev")
		if !hasPrev {
			break
		}
		pos = prev
	}
	if !found {
		return 0, pdfXrefLoc{}, false
	}
	// A trailer naming /Root is not the same as a section placing it: an appended decoy needs only
	// the name, so the placement is what earns this candidate the document.
	loc = locs[root]
	return root, loc, loc.found()
}

// pdfXrefSection returns the trailer dictionary of the cross-reference section
// at pos and places the objects it lists into locs, which an earlier section
// never overwrites.
func pdfXrefSection(data []byte, pos int, objs *pdfObjects, locs map[int]pdfXrefLoc) []byte {
	p := pdfSkipSpace(data, pos)
	if bytes.HasPrefix(data[p:], []byte("xref")) {
		return pdfClassicXref(data, p+len("xref"), locs)
	}
	return pdfXrefStream(data, p, objs, locs)
}

// place records where an object lives, unless a newer section already did.
func pdfPlace(locs map[int]pdfXrefLoc, num int, loc pdfXrefLoc) {
	if len(locs) <= maxPDFObjects {
		if _, seen := locs[num]; !seen {
			locs[num] = loc
		}
	}
}

// pdfClassicXref reads a cross-reference table's subsections and the trailer
// that follows them, placing every in-use entry at its byte offset.
func pdfClassicXref(data []byte, p int, locs map[int]pdfXrefLoc) []byte {
	for rows := 0; rows <= maxPDFObjects; {
		p = pdfSkipSpace(data, p)
		if bytes.HasPrefix(data[p:], []byte("trailer")) {
			return pdfDict(data[p+len("trailer"):])
		}
		first, q, ok := pdfUint(data, p, len(data))
		if !ok {
			return nil
		}
		count, q, ok := pdfUint(data, pdfSkipSpace(data, q), len(data))
		if !ok || count > maxPDFObjects {
			return nil
		}
		for i := 0; i < count; i++ {
			var entry int
			if entry, q, ok = pdfUint(data, pdfSkipSpace(data, q), len(data)); !ok {
				return nil
			}
			if _, q, ok = pdfUint(data, pdfSkipSpace(data, q), len(data)); !ok {
				return nil
			}
			if q = pdfSkipSpace(data, q); q >= len(data) {
				return nil
			}
			if data[q] == 'n' {
				pdfPlace(locs, first+i, pdfXrefLoc{offset: entry})
			}
			q++
			rows++
		}
		p = q
	}
	return nil
}

// pdfXrefStream reads a cross-reference stream: an ordinary object whose own
// dictionary carries the trailer entries, and whose payload is fixed-width rows
// of /W bytes covering the object ranges /Index names. Without decoding it the
// catalog has no location, and lexical order is exactly what an appended decoy
// exploits.
func pdfXrefStream(data []byte, p int, objs *pdfObjects, locs map[int]pdfXrefLoc) []byte {
	k := bytes.Index(data[p:min(len(data), p+maxPDFDictScan)], []byte("obj"))
	if k < 0 {
		return nil
	}
	body := data[p+k+len("obj"):]
	dict := pdfDict(body)

	w := pdfIntList(dict, "W", 3)
	_, raw := objs.streamPayload(body)
	if len(w) != 3 || len(raw) == 0 {
		return dict // not a decodable xref stream; the trailer entries still stand
	}
	row := w[0] + w[1] + w[2]
	if row <= 0 || row > 32 {
		return dict
	}
	payload, inflated := objs.decodeStream(dict, raw)
	if inflated {
		objs.inflate -= len(payload)
	}
	index := pdfIntList(dict, "Index", 2*maxPDFXrefHops)
	if len(index) < 2 {
		size, ok := pdfInt(dict, "Size")
		if !ok {
			return dict
		}
		index = []int{0, size}
	}

	at := 0
	field := func(off, n int) int {
		v := 0
		for _, b := range payload[off : off+n] {
			v = v<<8 | int(b)
		}
		return v
	}
	for i := 0; i+1 < len(index); i += 2 {
		first, count := index[i], index[i+1]
		for j := 0; j < count && at+row <= len(payload); j++ {
			kind := 1 // /W[0] of zero means every entry is type 1
			if w[0] > 0 {
				kind = field(at, w[0])
			}
			switch kind {
			case 1:
				pdfPlace(locs, first+j, pdfXrefLoc{offset: field(at+w[0], w[1])})
			case 2:
				pdfPlace(locs, first+j, pdfXrefLoc{
					stm: field(at+w[0], w[1]),
					idx: field(at+w[0]+w[1], w[2]),
				})
			}
			at += row
		}
	}
	return dict
}

// pdfIntList reads /key as an array of direct integers.
func pdfIntList(b []byte, key string, max int) []int {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return nil
	}
	if p = pdfSkipSpace(b, p); p >= len(b) || b[p] != '[' {
		return nil
	}
	p++
	end := pdfArrayEnd(b, p)
	var out []int
	for len(out) < max {
		v, next, ok := pdfUint(b, pdfSkipSpace(b, p), end)
		if !ok {
			break
		}
		out, p = append(out, v), next
	}
	return out
}

// pdfRootLexical returns the object number of the document catalog by scanning
// for /Root. Both a classic `trailer` dictionary and an xref stream's dictionary
// spell it out in plain bytes, and an incremental update appends a fresh one, so
// the search runs backwards from the end and takes the first that resolves: the
// current trailer is at the tail, which makes the common case O(1).
func pdfRootLexical(ctx context.Context, data []byte) (int, bool) {
	for i := len(data); i > 0; {
		if ctx.Err() != nil {
			return 0, false
		}
		p := pdfFindNameBack(data, "Root", i)
		if p < 0 {
			return 0, false
		}
		i = p - 1
		if refs := pdfRefList(data[p:], 1); len(refs) == 1 {
			return refs[0], true
		}
	}
	return 0, false
}

// pdfFindNameBack is pdfFindName in reverse: the offset just past the last name
// token /key ending at or before limit, or -1.
func pdfFindNameBack(b []byte, key string, limit int) int {
	tok := []byte("/" + key)
	for i := min(limit, len(b)); i >= len(tok); {
		k := bytes.LastIndex(b[:i], tok)
		if k < 0 {
			return -1
		}
		e := k + len(tok)
		if e >= len(b) || pdfIsSpace(b[e]) || pdfIsDelim(b[e]) {
			return e
		}
		i = e - 1
	}
	return -1
}

// pdfDict returns the leading window of an object body that a key lookup reads:
// the dictionary, which precedes any stream payload.
func pdfDict(body []byte) []byte {
	return body[:min(len(body), maxPDFDictScan)]
}

// pdfFindName returns the offset just past the name token /key in b, at or
// after from, or -1. The token must end at a delimiter, so a lookup of /AF does
// not match /AFRelationship. The search is lexical — a nested dictionary using
// the same name can shadow the outer one — but every offset it yields is
// length-checked and the result must still parse as a JUMBF store, so a wrong
// hit costs a nil return rather than a bad read.
func pdfFindName(b []byte, key string, from int) int {
	tok := "/" + key
	for i := from; i >= 0 && i < len(b); {
		k := bytes.Index(b[i:], []byte(tok))
		if k < 0 {
			return -1
		}
		e := i + k + len(tok)
		if e >= len(b) || pdfIsSpace(b[e]) || pdfIsDelim(b[e]) {
			return e
		}
		i = e
	}
	return -1
}

// pdfArrayEnd returns where an array opened just before p ends: its `]`, or the
// window bound when there is none. `[` is a delimiter, so `/Root[` matches the
// name token and opens an array that may never close; searching the rest of the
// buffer for the `]` would cost a full scan for every occurrence of the key.
func pdfArrayEnd(b []byte, p int) int {
	end := min(len(b), p+maxPDFDictScan)
	if e := bytes.IndexByte(b[p:end], ']'); e >= 0 {
		return p + e
	}
	return end
}

// pdfNames reads the value of /key as name objects, accepting both a bare name
// (/FlateDecode) and an array of them ([/FlateDecode]), with #XX escapes
// resolved and the leading slash dropped.
func pdfNames(b []byte, key string, max int) []string {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return nil
	}
	p, end := pdfSkipSpace(b, p), len(b)
	if p < end && b[p] == '[' {
		p++
		end = pdfArrayEnd(b, p)
	} else {
		max = 1 // a bare value is one name; the next one belongs to another key
	}
	var out []string
	for len(out) < max {
		p = pdfSkipSpace(b, p)
		if p >= end || b[p] != '/' {
			break
		}
		p++
		s := p
		for p < end && !pdfIsSpace(b[p]) && !pdfIsDelim(b[p]) {
			p++
		}
		out = append(out, pdfUnescapeName(b[s:p]))
	}
	return out
}

// pdfName reads /key as a single name object, "" when absent or not a name.
func pdfName(b []byte, key string) string {
	if names := pdfNames(b, key, 1); len(names) == 1 {
		return names[0]
	}
	return ""
}

// pdfText reads /key as either a name (/application#2Fc2pa) or a literal string
// ((application/c2pa)). The C2PA /Subtype is a media type and the spec never
// shows which of the two a producer writes it as.
func pdfText(b []byte, key string) string {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return ""
	}
	if p = pdfSkipSpace(b, p); p < len(b) && b[p] == '(' {
		// Bounded for the same reason as pdfArrayEnd: an unterminated literal
		// string must not cost a scan of the rest of the buffer.
		if e := bytes.IndexByte(b[p:min(len(b), p+maxPDFDictScan)], ')'); e > 0 {
			return string(b[p+1 : p+e])
		}
		return ""
	}
	return pdfName(b, key)
}

// pdfUnescapeName resolves a PDF name's #XX hex escapes, which is how the C2PA
// media type's slash is written: `application#2Fc2pa`.
func pdfUnescapeName(b []byte) string {
	if !bytes.ContainsRune(b, '#') {
		return string(b)
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '#' && i+2 < len(b) {
			hi, okHi := pdfHexDigit(b[i+1])
			lo, okLo := pdfHexDigit(b[i+2])
			if okHi && okLo {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, b[i])
	}
	return string(out)
}

// pdfInt reads /key as a direct integer. An indirect reference (`/Length 9 0 R`)
// reports absent rather than its object number, so a caller cannot read 9 as the
// value; the callers all have a fallback for absent.
func pdfInt(b []byte, key string) (int, bool) {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return 0, false
	}
	if _, _, ok := pdfRefAt(b, p, len(b)); ok {
		return 0, false
	}
	v, _, ok := pdfUint(b, pdfSkipSpace(b, p), len(b))
	return v, ok
}

// pdfRefs collects the indirect references in the value of /key, capped at max.
func pdfRefs(b []byte, key string, max int) []int {
	p := pdfFindName(b, key, 0)
	if p < 0 {
		return nil
	}
	return pdfRefList(b[p:], max)
}

// pdfRefList parses indirect references (`N G R`) from the start of b, stepping
// into a leading array. It stops at the first token that is not a reference.
func pdfRefList(b []byte, max int) []int {
	p, end := pdfSkipSpace(b, 0), len(b)
	if p < end && b[p] == '[' {
		p++
		end = pdfArrayEnd(b, p)
	} else {
		max = 1 // a bare value is one reference, not the start of a run
	}
	var out []int
	for len(out) < max {
		num, next, ok := pdfRefAt(b, p, end)
		if !ok {
			break
		}
		out = append(out, num)
		p = next
	}
	return out
}

// pdfRefAt parses one `N G R` indirect reference in b[p:end].
func pdfRefAt(b []byte, p, end int) (num, next int, ok bool) {
	p = pdfSkipSpace(b, p)
	num, p, ok = pdfUint(b, p, end)
	if !ok {
		return 0, 0, false
	}
	q := pdfSkipSpace(b, p)
	if q == p {
		return 0, 0, false
	}
	if _, p, ok = pdfUint(b, q, end); !ok {
		return 0, 0, false
	}
	q = pdfSkipSpace(b, p)
	if q == p || q >= end || b[q] != 'R' {
		return 0, 0, false
	}
	return num, q + 1, true
}

// pdfUint reads decimal digits at b[p:end], returning the value and the offset
// past them. The digit run is capped so the accumulator cannot overflow.
func pdfUint(b []byte, p, end int) (int, int, bool) {
	if end > len(b) {
		end = len(b)
	}
	i := p
	for i < end && b[i] >= '0' && b[i] <= '9' && i-p < 10 {
		i++
	}
	if i == p {
		return 0, p, false
	}
	v, err := strconv.Atoi(string(b[p:i]))
	if err != nil {
		return 0, p, false
	}
	return v, i, true
}

// pdfUintBack reads decimal digits backwards from b[i-1], returning the value
// and the offset of its first digit. Capped like pdfUint.
func pdfUintBack(b []byte, i int) (int, int, bool) {
	end := i
	for i > 0 && b[i-1] >= '0' && b[i-1] <= '9' && end-i < 10 {
		i--
	}
	if i == end {
		return 0, i, false
	}
	v, err := strconv.Atoi(string(b[i:end]))
	if err != nil {
		return 0, i, false
	}
	return v, i, true
}

func pdfSkipSpace(b []byte, i int) int {
	for i < len(b) && pdfIsSpace(b[i]) {
		i++
	}
	return i
}

func pdfSkipSpaceBack(b []byte, i int) int {
	for i > 0 && pdfIsSpace(b[i-1]) {
		i--
	}
	return i
}

// pdfPeek returns the first non-whitespace byte of b, or 0 when there is none.
func pdfPeek(b []byte) byte {
	if i := pdfSkipSpace(b, 0); i < len(b) {
		return b[i]
	}
	return 0
}

// pdfIsSpace reports the six PDF whitespace characters (32000-1 §7.2.2).
func pdfIsSpace(c byte) bool {
	return c == 0x00 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

// pdfIsDelim reports the PDF delimiter characters (32000-1 §7.2.2).
func pdfIsDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func pdfHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
