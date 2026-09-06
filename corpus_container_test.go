package c2pa

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

var (
	jpegTrailer = []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0xFF, 0xD9}
	pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
)

// pngCaBX splits the store across caBX chunks; the reader concatenates them, so
// the split point is arbitrary and deliberately uneven here to exercise it.
func pngCaBX(boxData []byte) []byte {
	if len(boxData) < 64 {
		return pngChunk("caBX", boxData)
	}
	cut := len(boxData) / 3
	return append(pngChunk("caBX", boxData[:cut]), pngChunk("caBX", boxData[cut:])...)
}

// assetFraming wraps a manifest store in container bytes and reports the byte
// range the manifest occupies, which is what the data-hash exclusion must cover.
type assetFraming func(store []byte) (asset []byte, exclStart, exclLen int)

// assembleAsset is the framing each container's positive cases use.
func assembleAsset(container Container, store []byte) (asset []byte, exclStart, exclLen int) {
	switch container {
	case JPEG:
		asset = append(asset, 0xFF, 0xD8)
		asset = append(asset, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
			0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00)
		exclStart = len(asset)
		asset = append(asset, jpegAPP11Run(store)...)
		exclLen = len(asset) - exclStart
		asset = append(asset, jpegTrailer...)
	case PNG:
		asset = append(asset, pngSignature...)
		asset = append(asset, pngChunk("IHDR", []byte{
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00})...)
		exclStart = len(asset)
		asset = append(asset, pngCaBX(store)...)
		exclLen = len(asset) - exclStart
		asset = append(asset, pngChunk("IDAT", []byte{0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01})...)
		asset = append(asset, pngChunk("IEND", nil)...)
	case RIFF:
		// A WebP: RIFF/WEBP with the store in a top-level C2PA chunk. The
		// exclusion covers the chunk body only, so its 8-byte header and
		// declared size stay hashed.
		body := []byte("WEBP")
		body = append(body, riffChunk("VP8L", []byte{0x2f, 0x00, 0x00, 0x00, 0x00})...)
		hdr := len("RIFF") + 4 // the store's offset is past RIFF+size, then form+chunks
		exclStart = hdr + len(body) + 8
		body = append(body, riffChunk(riffC2PAChunk, store)...)
		exclLen = len(store)
		asset = append(asset, "RIFF"...)
		asset = binary.LittleEndian.AppendUint32(asset, uint32(len(body)))
		asset = append(asset, body...)
	case TIFF:
		// Little-endian classic TIFF: header, one IFD holding the C2PA tag, then
		// the store. The exclusion covers the store bytes only, so the IFD entry
		// that points at them stays hashed.
		const hdr, ifd = 8, 8 + 2 + 12 + 4 // header, then count + one entry + next-IFD
		asset = append(asset, 'I', 'I', 42, 0)
		asset = binary.LittleEndian.AppendUint32(asset, hdr)
		asset = binary.LittleEndian.AppendUint16(asset, 1) // one entry
		asset = binary.LittleEndian.AppendUint16(asset, tiffC2PATag)
		asset = binary.LittleEndian.AppendUint16(asset, tiffUndefined)
		asset = binary.LittleEndian.AppendUint32(asset, uint32(len(store)))
		asset = binary.LittleEndian.AppendUint32(asset, ifd)
		asset = binary.LittleEndian.AppendUint32(asset, 0) // no next IFD
		exclStart = ifd
		asset = append(asset, store...)
		exclLen = len(store)
	case GIF:
		// GIF89a, no global colour table, then the C2PA application extension.
		// The exclusion covers the whole extension — introducer through
		// terminator — since its sub-block framing is part of the inserted bytes.
		asset = append(asset, "GIF89a"...)
		asset = append(asset, 1, 0, 1, 0, 0, 0, 0) // logical screen descriptor
		exclStart = len(asset)
		asset = append(asset, gifExtensionIntroducer, gifApplicationLabel, byte(len(gifC2PAIdentifier)))
		asset = append(asset, gifC2PAIdentifier...)
		asset = append(asset, gifSubBlockChain(store)...)
		exclLen = len(asset) - exclStart
		asset = append(asset, gifTrailer)
	case MP3:
		// ID3v2.4 tag holding one GEOB frame, then a token frame of audio. The
		// exclusion covers the store bytes inside the frame body.
		geob := []byte{0} // ISO-8859-1 text encoding
		geob = append(geob, id3C2PAMime...)
		geob = append(geob, 0, 'c', '2', 'p', 'a', 0) // filename
		geob = append(geob, 0)                        // empty description
		hdrLen := 10 + 10 + len(geob)
		tagSize := 10 + len(geob) + len(store)
		asset = append(asset, "ID3"...)
		asset = append(asset, 4, 0, 0)
		asset = append(asset, id3AppendSynchsafe(tagSize)...)
		asset = append(asset, "GEOB"...)
		asset = append(asset, id3AppendSynchsafe(len(geob)+len(store))...)
		asset = append(asset, 0, 0)
		asset = append(asset, geob...)
		exclStart = hdrLen
		asset = append(asset, store...)
		exclLen = len(store)
		asset = append(asset, 0xFF, 0xFB, 0x90, 0x00) // a plausible frame header
	case SVG:
		// The store is base64 inside <c2pa:manifest>, so the exclusion covers
		// the encoded text rather than the raw bytes.
		encoded := base64.StdEncoding.EncodeToString(store)
		prefix := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:c2pa="` + svgManifestNS +
			`"><metadata><c2pa:manifest>`
		asset = append(asset, prefix...)
		exclStart = len(asset)
		asset = append(asset, encoded...)
		exclLen = len(encoded)
		asset = append(asset, `</c2pa:manifest></metadata><rect width="1" height="1"/></svg>`...)
	case PDF:
		// Catalog /AF → file specification → embedded file stream (spec §A.4).
		// The exclusion covers exactly the stream payload, as Adobe's reference
		// PDF does: the stream dictionary and its /Length stay hashed, so the
		// store cannot be resized after signing.
		asset = append(asset, "%PDF-1.7\n"...)
		asset = append(asset, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AF [3 0 R] >>\nendobj\n"...)
		asset = append(asset, "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"...)
		asset = append(asset, "3 0 obj\n<< /Type /Filespec /F (c2pa.c2pa) /UF (c2pa.c2pa)"+
			" /AFRelationship /C2PA_Manifest /EF << /F 4 0 R >> >>\nendobj\n"...)
		asset = append(asset, fmt.Sprintf("4 0 obj\n<< /Type /EmbeddedFile"+
			" /Subtype /application#2Fc2pa /Length %d >>\nstream\n", len(store))...)
		exclStart = len(asset)
		asset = append(asset, store...)
		exclLen = len(asset) - exclStart
		asset = append(asset, "\nendstream\nendobj\n"...)
		asset = append(asset, "trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"...)
	}
	return asset, exclStart, exclLen
}

// pdfProducerFraming frames the store the way an observed producer's output
// does: a catalog at generation 1 (`5 1 obj`, `/Root 5 1 R`), /Type /FileSpec
// rather than /Filespec, a literal-string /Subtype, and the manifest added by an
// incremental update. Without the chain no catalog is written at all, which is
// what an object stream does to one, leaving the literal /Subtype on the stream
// as the only marker: the markers are only consulted when nothing resolves.
func pdfProducerFraming(chain bool) assetFraming {
	return func(store []byte) (asset []byte, exclStart, exclLen int) {
		asset = append(asset, "%PDF-1.7\n"...)
		asset = append(asset, "7 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"...)
		if chain {
			asset = append(asset,
				"5 1 obj\n<< /PageMode /UseNone /Pages 7 0 R /Type /Catalog >>\nendobj\n"...)
		}
		// /Prev names the base section's xref, an offset the store cannot move,
		// so it stays length-stable across the exclusion fixpoint's passes.
		prev := len(asset)
		asset = append(asset, "trailer\n<< /Size 8 /Root 5 1 R >>\nstartxref\n0\n%%EOF\n"...)

		asset = append(asset, fmt.Sprintf("9 0 obj\n<< /Length %d"+
			" /F << /Subtype (application/c2pa) /Length %d >> >>\nstream\n", len(store), len(store))...)
		exclStart = len(asset)
		asset = append(asset, store...)
		exclLen = len(asset) - exclStart
		asset = append(asset, "\nendstream\nendobj\n"...)
		if chain {
			asset = append(asset, "10 0 obj\n<< /AFRelationship /C2PA_Manifest /Desc (Content Credentials)"+
				" /F (Content Credentials) /EF << /F 9 0 R >> /Subtype (application/c2pa)"+
				" /Type /FileSpec /UF (Content Credentials) >>\nendobj\n"...)
			asset = append(asset, "5 1 obj\n<< /PageMode /UseNone /Pages 7 0 R /Type /Catalog /AF [10 0 R]"+
				" /Names << /EmbeddedFiles << /Names [(Content Credentials) 10 0 R] >> >> >>\nendobj\n"...)
		}
		asset = append(asset, fmt.Sprintf("trailer\n<< /Size 11 /Root 5 1 R /Prev %d >>"+
			"\nstartxref\n0\n%%%%EOF\n", prev)...)
		return asset, exclStart, exclLen
	}
}

// buildAsset builds a signed asset in the container's own framing.
func buildAsset(t testing.TB, container Container, spec manifestSpec) []byte {
	t.Helper()
	return buildFramedAsset(t, func(store []byte) ([]byte, int, int) {
		return assembleAsset(container, store)
	}, spec)
}

// buildFramedAsset resolves the circular dependency between the exclusion
// offsets and the manifest size (CBOR integers are variable-width, so writing
// the offsets changes the size that determines them) by iterating to a fixpoint,
// then does one final pass to write the real digest. The digest lives inside the
// excluded range, so writing it cannot invalidate it.
func buildFramedAsset(t testing.TB, frame assetFraming, spec manifestSpec) []byte {
	t.Helper()
	alg := spec.dataHashAlg
	if alg == "" {
		alg = "sha256"
	}
	digestLen := len(hashOf(t, alg, nil))
	placeholder := make([]byte, digestLen)

	assemble := func(start, length int, digest []byte) ([]byte, int, int) {
		withHash := spec
		var binding []assertionSpec
		if !spec.noHardBinding {
			binding = append(binding, assertionSpec{
				label: "c2pa.hash.data",
				value: map[string]any{
					"exclusions": []any{map[string]any{"start": start, "length": length}},
					"name":       "jumbf manifest",
					"alg":        alg,
					"hash":       digest,
				},
			})
		}
		if spec.extraBinding != nil {
			binding = append(binding, *spec.extraBinding)
		}
		withHash.assertions = append(binding, spec.assertions...)
		manifests := [][]byte{buildManifest(t, withHash)}
		if spec.updateOverlay != nil {
			// Last in the store is the active manifest, so the overlay goes
			// after the one it updates. It carries no hard binding, so its size
			// is constant and the exclusion fixpoint still settles.
			manifests = append(manifests, buildManifest(t, *spec.updateOverlay))
		}
		return frame(storeBox(manifests...))
	}

	start, length := 0, 0
	for i := 0; i < 8; i++ {
		_, s, l := assemble(start, length, placeholder)
		if s == start && l == length {
			break
		}
		start, length = s, l
	}

	asset, s, l := assemble(start, length, placeholder)
	if s != start || l != length {
		t.Fatalf("exclusion offsets did not converge: got (%d,%d) want (%d,%d)", s, l, start, length)
	}

	h, _ := hashByName(alg)
	hashWithExclusions(asset, h, []byteRange{{start: start, length: length}})
	final, _, _ := assemble(start, length, h.Sum(nil))
	return final
}

// riffChunk frames payload as a RIFF chunk: FourCC, little-endian size, body,
// then a pad byte when the size is odd.
func riffChunk(id string, payload []byte) []byte {
	out := append([]byte(id), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(payload)))
	out = append(out, payload...)
	if len(payload)%2 == 1 {
		out = append(out, 0)
	}
	return out
}

// gifSubBlockChain splits payload into GIF data sub-blocks of at most 255
// bytes, terminated by an empty block.
func gifSubBlockChain(payload []byte) []byte {
	var out []byte
	for len(payload) > 0 {
		n := min(len(payload), 255)
		out = append(out, byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return append(out, 0)
}

// id3AppendSynchsafe encodes n as ID3's 7-bits-per-byte integer.
func id3AppendSynchsafe(n int) []byte {
	return []byte{
		byte(n >> 21 & 0x7F), byte(n >> 14 & 0x7F), byte(n >> 7 & 0x7F), byte(n & 0x7F),
	}
}
