package c2pa

import "encoding/binary"

// JUMBF box writers (ISO 19566-5), the inverse of boxes.go's parser. The
// generated test corpus has always built its assets from these, and Sign builds
// its manifest store from the same functions — so the verifier's own fixtures
// and the signer's output share one definition of a box, and a store the
// package writes is by construction one the package reads.
//
// Every LBox is a 32-bit length. The reader rejects XLBox (boxes.go:48), so a
// store that would need one is refused upstream (maxEmbedStore) rather than
// written and then found unreadable.

// jumbfUUID returns the JUMBF type UUID whose first four bytes are the ASCII
// tag — the C2PA convention (spec §11.1.4): "c2pa", "c2ma", "c2as", "c2cl",
// "c2cs", "c2um", "cbor", "json" all share the suffix 0011-0010-8000-00AA00389B71.
func jumbfUUID(tag string) [16]byte {
	var u [16]byte
	copy(u[:], tag)
	copy(u[4:], []byte{0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71})
	return u
}

var (
	uuidC2PA = jumbfUUID("c2pa") // the manifest store
	uuidC2MA = jumbfUUID("c2ma") // a standard manifest
	// uuidC2UM is an Update Manifest's superbox type UUID (spec §11.2.3); it is
	// the only thing that distinguishes one from a standard manifest.
	uuidC2UM = jumbfUUID("c2um")
	uuidC2AS = jumbfUUID("c2as") // the assertion store
	uuidC2CL = jumbfUUID("c2cl") // the claim
	uuidC2CS = jumbfUUID("c2cs") // the claim signature
	uuidCBOR = jumbfUUID("cbor") // a CBOR content box
	uuidJSON = jumbfUUID("json") // a JSON content box
)

// boxHeader writes an 8-byte LBox+TBox header. size must fit 32 bits; callers
// enforce that at the store level.
func boxHeader(size int, tbox string) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint32(h[:4], uint32(size))
	copy(h[4:], tbox)
	return h
}

// leafBox frames payload as a content box of type tbox.
func leafBox(tbox string, payload []byte) []byte {
	return append(boxHeader(8+len(payload), tbox), payload...)
}

// jumdBox emits the description box. Toggles bit 1 (0x02) is what makes the
// parser read the label at all; without it the box is anonymous. 0x03 is
// requestable + label present, which is what c2pa-rs writes.
func jumdBox(typeUUID [16]byte, label string) []byte {
	payload := make([]byte, 0, 17+len(label)+1)
	payload = append(payload, typeUUID[:]...)
	payload = append(payload, 0x03)
	payload = append(payload, label...)
	payload = append(payload, 0x00)
	return leafBox("jumd", payload)
}

// superBox frames a jumd description box and its children as a jumb superbox.
func superBox(typeUUID [16]byte, label string, children ...[]byte) []byte {
	content := jumdBox(typeUUID, label)
	for _, c := range children {
		content = append(content, c...)
	}
	return append(boxHeader(8+len(content), "jumb"), content...)
}

// assertionBox frames a CBOR assertion: a superbox of type "cbor" whose one
// child is a cbor content box. Its content (everything after the 8-byte
// superbox header) is what a claim's hashed_uri covers — rawAssertion.boxContent.
func assertionBox(label string, payload []byte) []byte {
	return superBox(uuidCBOR, label, leafBox("cbor", payload))
}

// jsonAssertionBox is assertionBox for a JSON assertion.
func jsonAssertionBox(label string, payload []byte) []byte {
	return superBox(uuidJSON, label, leafBox("json", payload))
}

// storeBox frames manifests as the "c2pa" manifest store superbox. The last
// manifest is the active one (boxes.go active()).
func storeBox(manifests ...[]byte) []byte {
	return superBox(uuidC2PA, "c2pa", manifests...)
}
