package c2pa

import (
	"context"
	"fmt"
	"testing"
)

var (
	jpegTrailer = []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0xFF, 0xD9}
	pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
)

// assetFraming wraps a manifest store in container bytes and reports the byte
// ranges the manifest occupies, which is what the data-hash exclusion must
// cover. TIFF reports two (the IFD entry's count field and the store).
type assetFraming func(store []byte) (asset []byte, excl []byteRange)

// assembleAsset is the framing each container's positive cases use: the
// production embedder writing the store into a minimal unsigned asset, so the
// corpus exercises insertion into an existing file rather than a synthetic
// frame. PDF keeps its hand-built frame until it has an embedder. A nil store
// returns the unsigned asset.
func assembleAsset(container Container, store []byte) (asset []byte, excl []byteRange) {
	if container != PDF {
		base := unsignedCorpusAsset(container)
		if store == nil {
			return base, nil
		}
		out, excl, err := embedStore(context.Background(), container, base, store)
		if err != nil {
			panic("assembleAsset: " + err.Error()) // a test builder, not a code path
		}
		return out, excl
	}
	var exclStart, exclLen int
	switch container {
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
	return asset, []byteRange{{start: exclStart, length: exclLen}}
}

// unsignedCorpusAsset is the smallest asset of each container the embedders
// accept: enough structure for the reader and the box map, nothing more.
func unsignedCorpusAsset(container Container) []byte {
	switch container {
	case JPEG:
		asset := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
			0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}
		return append(asset, jpegTrailer...)
	case PNG:
		asset := append([]byte{}, pngSignature...)
		asset = append(asset, pngChunk("IHDR", []byte{
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00})...)
		asset = append(asset, pngChunk("IDAT", []byte{0x78, 0x9C, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01})...)
		return append(asset, pngChunk("IEND", nil)...)
	case GIF:
		return gifFile(gifImage([]byte{0x44, 0x01}))
	case RIFF:
		return riffFile("WEBP", riffChunk("VP8L", []byte{0x2f, 0x00, 0x00, 0x00, 0x00}))
	case TIFF:
		return unsignedTIFF(false)
	case MP3:
		return append(id3Tag(4, 0, nil), 0xFF, 0xFB, 0x90, 0x00)
	case SVG:
		return []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`)
	}
	return nil
}

// pdfProducerFraming frames the store the way an observed producer's output
// does: a catalog at generation 1 (`5 1 obj`, `/Root 5 1 R`), /Type /FileSpec
// rather than /Filespec, a literal-string /Subtype, and the manifest added by an
// incremental update. Without the chain no catalog is written at all, which is
// what an object stream does to one, leaving the literal /Subtype on the stream
// as the only marker: the markers are only consulted when nothing resolves.
func pdfProducerFraming(chain bool) assetFraming {
	return func(store []byte) (asset []byte, excl []byteRange) {
		var exclStart, exclLen int
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
		return asset, []byteRange{{start: exclStart, length: exclLen}}
	}
}

// buildAsset builds a signed asset in the container's own framing.
func buildAsset(t testing.TB, container Container, spec manifestSpec) []byte {
	t.Helper()
	return buildFramedAsset(t, func(store []byte) ([]byte, []byteRange) {
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

	assemble := func(excl []byteRange, digest []byte) ([]byte, []byteRange) {
		withHash := spec
		var binding []assertionSpec
		if !spec.noHardBinding {
			exclusions := make([]any, 0, len(excl))
			for _, r := range excl {
				exclusions = append(exclusions, map[string]any{"start": r.start, "length": r.length})
			}
			binding = append(binding, assertionSpec{
				label: "c2pa.hash.data",
				value: map[string]any{
					"exclusions": exclusions,
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

	excl := []byteRange{{start: 0, length: 0}}
	for i := 0; i < 8; i++ {
		_, next := assemble(excl, placeholder)
		if sameRanges(next, excl) {
			break
		}
		excl = next
	}

	asset, next := assemble(excl, placeholder)
	if !sameRanges(next, excl) {
		t.Fatalf("exclusion offsets did not converge: got %v want %v", next, excl)
	}

	h, _ := hashByName(alg)
	hashWithExclusions(asset, h, excl)
	final, _ := assemble(excl, h.Sum(nil))
	return final
}
