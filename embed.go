package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
)

// Embedding a manifest store into an existing asset (spec Annex A). Each
// container's embedder knows where its store lives and what bytes the
// c2pa.hash.data exclusion must cover; the signing pipeline knows nothing
// about containers beyond this contract.

var (
	errStoreInvalid       = errors.New("manifest store is not a c2pa JUMBF superbox")
	errCarrierMalformed   = errors.New("asset does not parse as the named container")
	errCarrierUnsupported = errors.New("asset has a feature this signer does not write into")
)

// maxEmbedStore caps a manifest store at 64 MiB — far above any real store and
// far below the 4 GiB at which JUMBF would need an XLBox, which the reader
// rejects.
const maxEmbedStore = 64 << 20

// embedder writes a manifest store into one carrier format. Implementations
// are stateless values.
type embedder interface {
	// embed returns asset with EVERY existing C2PA store removed and store
	// inserted where Annex A puts it — always the canonical position, not the
	// old store's, so the result is deterministic — plus the byte ranges of
	// out that a c2pa.hash.data assertion must exclude. It is a pure function
	// of (asset, store), and out depends on store only through its length and
	// through the bytes inside excl: that is what lets the signer converge a
	// layout with a placeholder store and then write the real one without
	// moving anything else.
	embed(ctx context.Context, asset, store []byte) (out []byte, excl []byteRange, err error)
}

// embedderFor returns the embedder for a container, if it has one.
func embedderFor(c Container) (embedder, bool) {
	switch c {
	case JPEG:
		return jpegEmbedder{}, true
	case PNG:
		return pngEmbedder{}, true
	case GIF:
		return gifEmbedder{}, true
	case RIFF:
		return riffEmbedder{}, true
	case TIFF:
		return tiffEmbedder{}, true
	case MP3:
		return mp3Embedder{}, true
	case SVG:
		return svgEmbedder{}, true
	case BMFF:
		return bmffEmbedder{}, true
	}
	return nil, false
}

// checkStore refuses anything that is not a "c2pa" JUMBF superbox of a size
// every carrier can hold. The first four bytes of the type UUID must read
// "c2pa": that is how c2pa-rs (and this package's JPEG box map) recognise the
// store inside an APP11 segment.
func checkStore(store []byte) error {
	switch {
	case len(store) < 28:
		return fmt.Errorf("%w: %d bytes", errStoreInvalid, len(store))
	case len(store) > maxEmbedStore:
		return fmt.Errorf("%w: %d bytes exceeds %d", errStoreInvalid, len(store), maxEmbedStore)
	case int(binary.BigEndian.Uint32(store[:4])) != len(store), string(store[4:8]) != "jumb",
		string(store[12:16]) != "jumd", string(store[16:20]) != "c2pa":
		return errStoreInvalid
	}
	return nil
}

// embedStore is what the signer calls: check the store, dispatch, then confirm
// the package's own reader gets exactly the store back — an embedder whose
// output this package cannot read is a bug, not an output.
func embedStore(ctx context.Context, c Container, asset, store []byte) ([]byte, []byteRange, error) {
	if err := checkStore(store); err != nil {
		return nil, nil, err
	}
	e, ok := embedderFor(c)
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", errCarrierUnsupported, string(c))
	}
	out, excl, err := e.embed(ctx, asset, store)
	if err != nil {
		return nil, nil, err
	}
	if got := extractJUMBF(ctx, c, out); !bytes.Equal(got, store) {
		return nil, nil, fmt.Errorf("%w: embedded store does not read back", errCarrierMalformed)
	}
	for i, r := range excl {
		if r.start < 0 || r.length < 0 || r.start+r.length > len(out) || (i > 0 && r.start < excl[i-1].start+excl[i-1].length) {
			return nil, nil, fmt.Errorf("%w: exclusion %v is out of order or out of bounds", errCarrierMalformed, r)
		}
	}
	return out, excl, nil
}

// edit replaces asset[at:at+remove] with insert. Edits are applied together
// so no offset has to be re-derived after an earlier splice.
type edit struct {
	at, remove int
	insert     []byte
}

// applyEdits applies edits (any order; removals must not overlap) and returns
// the result, the output offset at which each edit's insert landed (indexed
// like edits), and remap, which carries an offset of asset that lies outside
// every removed span to its offset in out. An insertion at the same offset as
// a removal is placed before the removed bytes.
func applyEdits(asset []byte, edits []edit) (out []byte, placed []int, remap func(int) (int, bool), err error) {
	idx := make([]int, len(edits))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ea, eb := edits[idx[a]], edits[idx[b]]
		if ea.at != eb.at {
			return ea.at < eb.at
		}
		return ea.remove == 0 && eb.remove != 0
	})
	prevEnd, delta := 0, 0
	for _, i := range idx {
		e := edits[i]
		if e.at < 0 || e.remove < 0 || e.at > len(asset) || e.remove > len(asset)-e.at || e.at < prevEnd {
			return nil, nil, nil, fmt.Errorf("%w: edits overlap or fall outside the asset", errCarrierMalformed)
		}
		if end := e.at + e.remove; end > prevEnd {
			prevEnd = end
		}
		delta += len(e.insert) - e.remove
	}
	out = make([]byte, 0, len(asset)+delta)
	placed = make([]int, len(edits))
	cur := 0
	for _, i := range idx {
		e := edits[i]
		out = append(out, asset[cur:e.at]...)
		placed[i] = len(out)
		out = append(out, e.insert...)
		cur = e.at + e.remove
	}
	out = append(out, asset[cur:]...)
	sorted := make([]edit, len(idx))
	for k, i := range idx {
		sorted[k] = edits[i]
	}
	remap = func(off int) (int, bool) {
		shift := 0
		for _, e := range sorted {
			if off < e.at {
				break
			}
			if e.remove > 0 && off < e.at+e.remove {
				return 0, false
			}
			shift += len(e.insert) - e.remove
		}
		return off + shift, true
	}
	return out, placed, remap, nil
}

// --- JPEG ---------------------------------------------------------------------

// jpegEmbedder writes the store as a run of APP11 segments (ISO 19566-5 D.2,
// spec §A.3.1) immediately after the last APP0 — or right after SOI when there
// is none — which is where c2pa-rs puts it and what the signed fixture shows.
type jpegEmbedder struct{}

// jpegSeg is one marker segment before start-of-scan.
type jpegSeg struct {
	marker                   byte
	start, payloadStart, end int
}

// jpegSegmentsBeforeSOS walks the marker segments from SOI up to, not
// including, SOS or EOI, returning them and the offset where the walk stopped.
// A file with neither is not one a store can be written into.
func jpegSegmentsBeforeSOS(ctx context.Context, data []byte) ([]jpegSeg, int, error) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, 0, fmt.Errorf("%w: not a JPEG", errCarrierMalformed)
	}
	var segs []jpegSeg
	i := 2
	for i < len(data) {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if data[i] != 0xFF {
			return nil, 0, fmt.Errorf("%w: expected a marker at offset %d", errCarrierMalformed, i)
		}
		j := i
		for j < len(data) && data[j] == 0xFF { // fill bytes precede a marker
			j++
		}
		if j >= len(data) {
			break
		}
		m := data[j]
		switch {
		case m == 0xDA || m == 0xD9: // SOS / EOI: the header is over
			return segs, i, nil
		case m == 0xD8 || (m >= 0xD0 && m <= 0xD7) || m == 0x01: // standalone markers
			i = j + 1
			continue
		}
		if j+3 > len(data) {
			break
		}
		ln := int(binary.BigEndian.Uint16(data[j+1 : j+3]))
		if ln < 2 || j+1+ln > len(data) {
			break
		}
		segs = append(segs, jpegSeg{marker: m, start: i, payloadStart: j + 3, end: j + 1 + ln})
		i = j + 1 + ln
	}
	return nil, 0, fmt.Errorf("%w: JPEG has no start of scan", errCarrierMalformed)
}

// jpegPlan finds every existing C2PA APP11 segment to remove and where the new
// run goes. A run starts at a segment whose payload reads "c2pa" at bytes
// 24..28 (the store's type UUID); its continuations share the En field. A
// continuation left behind would be concatenated into the next reader's store,
// so it is removed wherever it sits.
func jpegPlan(ctx context.Context, data []byte) (cuts []edit, insertAt int, err error) {
	segs, _, err := jpegSegmentsBeforeSOS(ctx, data)
	if err != nil {
		return nil, 0, err
	}
	insertAt = 2
	runs := map[[2]byte]bool{}
	for _, s := range segs {
		switch s.marker {
		case 0xE0:
			insertAt = s.end
		case 0xEB:
			p := data[s.payloadStart:s.end]
			if len(p) < 8 || p[0] != 'J' || p[1] != 'P' {
				continue
			}
			en := [2]byte{p[2], p[3]}
			if len(p) >= 28 && string(p[24:28]) == "c2pa" {
				runs[en] = true
			} else if !runs[en] {
				continue
			}
			cuts = append(cuts, edit{at: s.start, remove: s.end - s.start})
		}
	}
	return cuts, insertAt, nil
}

func (jpegEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	cuts, insertAt, err := jpegPlan(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	run := jpegAPP11Run(store)
	edits := append(cuts, edit{at: insertAt, insert: run})
	out, placed, _, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	return out, []byteRange{{start: placed[len(edits)-1], length: len(run)}}, nil
}

// jpegAPP11Run splits a JUMBF box across APP11 segments the way c2pa-rs does:
// 64000 store bytes per segment, CI "JP", En 0x0211, Z counting from 1, and
// the box's 8-byte LBox+TBox repeated in every continuation segment (the
// reader skips those copies). The segment length field Le counts itself but
// not the marker.
func jpegAPP11Run(store []byte) []byte {
	const chunk = 64000
	var out []byte
	for i, z := 0, uint32(1); i < len(store); z++ {
		n := min(chunk, len(store)-i)
		var prefix []byte
		if z > 1 {
			prefix = store[:8]
		}
		out = append(out, 0xFF, 0xEB)
		out = binary.BigEndian.AppendUint16(out, uint16(2+8+len(prefix)+n))
		out = append(out, 0x4A, 0x50, 0x02, 0x11)
		out = binary.BigEndian.AppendUint32(out, z)
		out = append(out, prefix...)
		out = append(out, store[i:i+n]...)
		i += n
	}
	return out
}

// --- PNG ----------------------------------------------------------------------

// pngEmbedder writes the store as one caBX chunk immediately after IHDR (spec
// §A.3.2 recommends before IDAT; c2pa-rs puts it right after IHDR).
type pngEmbedder struct{}

var pngFileSignature = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

// pngChunkPos is one chunk: [start, end) covers length, type, data and CRC.
type pngChunkPos struct {
	typ        string
	start, end int
}

// pngChunkList walks the chunks up to and including IEND. A truncated chunk
// or a file that does not open with IHDR is not one a store can be written
// into; bytes after IEND are preserved untouched.
func pngChunkList(ctx context.Context, data []byte) ([]pngChunkPos, error) {
	if len(data) < 8 || !bytes.Equal(data[:8], pngFileSignature) {
		return nil, fmt.Errorf("%w: not a PNG", errCarrierMalformed)
	}
	var chunks []pngChunkPos
	i := 8
	for i+8 <= len(data) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ln := int(binary.BigEndian.Uint32(data[i : i+4]))
		if ln < 0 || ln > len(data)-i-12 {
			return nil, fmt.Errorf("%w: truncated PNG chunk at offset %d", errCarrierMalformed, i)
		}
		typ := string(data[i+4 : i+8])
		chunks = append(chunks, pngChunkPos{typ: typ, start: i, end: i + 12 + ln})
		i += 12 + ln
		if typ == "IEND" {
			break
		}
	}
	if len(chunks) == 0 || chunks[0].typ != "IHDR" {
		return nil, fmt.Errorf("%w: PNG does not open with IHDR", errCarrierMalformed)
	}
	return chunks, nil
}

func (pngEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	chunks, err := pngChunkList(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	var edits []edit
	for _, c := range chunks {
		if c.typ == "caBX" {
			edits = append(edits, edit{at: c.start, remove: c.end - c.start})
		}
	}
	chunk := pngChunk("caBX", store)
	edits = append(edits, edit{at: chunks[0].end, insert: chunk})
	out, placed, _, err := applyEdits(asset, edits)
	if err != nil {
		return nil, nil, err
	}
	return out, []byteRange{{start: placed[len(edits)-1], length: len(chunk)}}, nil
}

// pngChunk frames data as a PNG chunk: big-endian length, type, data, and a
// CRC-32 over type and data.
func pngChunk(typ string, data []byte) []byte {
	out := make([]byte, 0, 12+len(data))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	out = append(out, typ...)
	out = append(out, data...)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	return binary.BigEndian.AppendUint32(out, crc.Sum32())
}
