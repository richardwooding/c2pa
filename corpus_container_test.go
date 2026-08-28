package c2pa

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

var (
	jpegTrailer = []byte{0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0xFF, 0xD9}
	pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
)

// jpegAPP11 splits a JUMBF box across APP11 segments. Continuation segments
// repeat the box's 8-byte LBox+TBox header, which the reader skips — only the
// Z==1 segment contributes it.
func jpegAPP11(boxData []byte) []byte {
	const maxPayload = 65533
	var out []byte
	z := uint32(1)
	for i := 0; i < len(boxData); {
		var prefix []byte
		room := maxPayload - 8
		if z > 1 {
			prefix = boxData[:8]
			room -= 8
		}
		n := room
		if i+n > len(boxData) {
			n = len(boxData) - i
		}
		payload := make([]byte, 0, 8+len(prefix)+n)
		payload = append(payload, 0x4A, 0x50, 0x00, 0x01)
		var zb [4]byte
		binary.BigEndian.PutUint32(zb[:], z)
		payload = append(payload, zb[:]...)
		payload = append(payload, prefix...)
		payload = append(payload, boxData[i:i+n]...)

		var ln [2]byte
		binary.BigEndian.PutUint16(ln[:], uint16(2+len(payload)))
		out = append(out, 0xFF, 0xEB)
		out = append(out, ln[:]...)
		out = append(out, payload...)

		i += n
		z++
	}
	return out
}

func pngChunk(typ string, data []byte) []byte {
	var out []byte
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(data)))
	out = append(out, ln[:]...)
	out = append(out, typ...)
	out = append(out, data...)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], crc.Sum32())
	return append(out, cb[:]...)
}

// pngCaBX splits the store across caBX chunks; the reader concatenates them, so
// the split point is arbitrary and deliberately uneven here to exercise it.
func pngCaBX(boxData []byte) []byte {
	if len(boxData) < 64 {
		return pngChunk("caBX", boxData)
	}
	cut := len(boxData) / 3
	return append(pngChunk("caBX", boxData[:cut]), pngChunk("caBX", boxData[cut:])...)
}

// assembleAsset wraps a manifest store in a container and reports the byte range
// the manifest occupies, which is what the data-hash exclusion must cover.
func assembleAsset(container Container, store []byte) (asset []byte, exclStart, exclLen int) {
	switch container {
	case JPEG:
		asset = append(asset, 0xFF, 0xD8)
		asset = append(asset, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00,
			0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00)
		exclStart = len(asset)
		asset = append(asset, jpegAPP11(store)...)
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
	}
	return asset, exclStart, exclLen
}

// buildAsset resolves the circular dependency between the exclusion offsets and
// the manifest size (CBOR integers are variable-width, so writing the offsets
// changes the size that determines them) by iterating to a fixpoint, then does
// one final pass to write the real digest. The digest lives inside the excluded
// range, so writing it cannot invalidate it.
func buildAsset(t testing.TB, container Container, spec manifestSpec) []byte {
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
		return assembleAsset(container, storeBox(buildManifest(t, withHash)))
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
