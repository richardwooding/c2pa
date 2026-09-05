package c2pa

import (
	"context"
	"encoding/binary"
	"strings"
)

// box is a parsed JUMBF box retaining absolute offsets into and the raw bytes
// of the source buffer. Unlike the WalkBoxes callback (which surfaces only leaf
// payloads), box keeps each superbox's full header+payload bytes — required to
// recompute the SHA hash of a whole assertion for hashed_uri verification.
type box struct {
	label string // jumd label of a superbox; "" for a non-superbox box
	// typeUUID is a superbox's jumd description type UUID, which is what
	// separates a standard manifest from an update manifest — the labels and
	// the box structure are otherwise identical.
	typeUUID [16]byte
	tbox     string // 4-character box type ("jumb", "cbor", "uuid", …)
	start    int    // absolute offset of the box's LBox field in the buffer
	end      int    // start + LBox
	full     []byte // buf[start:end] — full box including the 8-byte header
	content  []byte // payload after the 8-byte LBox+TBox header
	children []*box // child boxes (superboxes only; excludes the leading jumd)
}

// parseBoxTree parses a JUMBF buffer into a tree of boxes, tracking absolute
// offsets. It mirrors walkBoxesDepth's defensive bounds checks and depth cap so
// adversarial input cannot index out of range or exhaust the stack; ctx is
// honoured at the top of every iteration.
func parseBoxTree(ctx context.Context, jumbf []byte) []*box {
	return parseBoxes(ctx, jumbf, 0, 0)
}

func parseBoxes(ctx context.Context, buf []byte, base, depth int) []*box {
	if depth > maxJUMBFDepth {
		return nil
	}
	var out []*box
	b := buf
	off := base
	for len(b) >= 8 {
		if ctx.Err() != nil {
			return out
		}
		lbox := int(binary.BigEndian.Uint32(b[:4]))
		tbox := string(b[4:8])
		if lbox < 8 || lbox > len(b) {
			return out
		}
		bx := &box{
			tbox:    tbox,
			start:   off,
			end:     off + lbox,
			full:    b[:lbox],
			content: b[8:lbox],
		}
		if tbox == "jumb" {
			label, typeUUID, restOff, rest := parseJumd(bx.content, off+8)
			bx.label = label
			bx.typeUUID = typeUUID
			bx.children = parseBoxes(ctx, rest, restOff, depth+1)
		}
		out = append(out, bx)
		b = b[lbox:]
		off += lbox
	}
	return out
}

// parseJumd parses the leading jumd description box of a superbox's content and
// returns its label, its 16-byte type UUID, the absolute offset of the
// remaining child boxes, and the remaining child-box bytes. It is the
// offset-aware counterpart of jumdLabel.
func parseJumd(content []byte, contentOff int) (label string, typeUUID [16]byte, restOff int, rest []byte) {
	if len(content) < 8 {
		return "", typeUUID, contentOff, content
	}
	lbox := int(binary.BigEndian.Uint32(content[:4]))
	if string(content[4:8]) != "jumd" || lbox < 8 || lbox > len(content) {
		return "", typeUUID, contentOff, content
	}
	d := content[8:lbox]
	rest = content[lbox:]
	restOff = contentOff + lbox
	if len(d) >= 16 {
		copy(typeUUID[:], d[:16])
	}
	if len(d) >= 17 && d[16]&0x02 != 0 { // toggles bit 1: null-terminated label
		end := 17
		for end < len(d) && d[end] != 0 {
			end++
		}
		label = string(d[17:end])
	}
	return label, typeUUID, restOff, rest
}

// rawAssertion is one assertion from a manifest's assertion store. boxContent
// is the assertion superbox's content (its jumd description box plus the data
// box, excluding the superbox's own 8-byte header) — the exact bytes a claim's
// hashed_uri SHA covers. data is just the data-box payload, for CBOR/JSON decode.
type rawAssertion struct {
	label      string // e.g. "c2pa.hash.data", "c2pa.actions.v2"
	tbox       string // data-box type ("cbor", "json", "uuid", …)
	boxContent []byte // assertion superbox content (jumd + data box) — hashed_uri target
	data       []byte // the data-box payload
}

// parsedManifest is a single C2PA manifest (claim + signature + assertions)
// resolved from the JUMBF tree with the raw bytes each validation step needs.
type parsedManifest struct {
	label      string         // manifest superbox label (its URN)
	claimBytes []byte         // CBOR bytes of the claim box (COSE detached payload)
	claim      map[string]any // decoded claim, nil if undecodable
	signature  []byte         // COSE_Sign1 bytes from the c2pa.signature box
	assertions []rawAssertion
	// multipleClaims records a second claim box in this manifest — the first
	// one stands, and validation reports claim.multiple.
	multipleClaims bool
	// update marks an Update Manifest (spec §11.2.3): a manifest that adds
	// assertions WITHOUT changing the content, so it carries no hard binding of
	// its own and its parentOf ingredient names the manifest that does.
	update bool
}

// parsedStore is the manifest store: one or more manifests, the last of which
// is conventionally the active manifest.
type parsedStore struct {
	manifests []*parsedManifest
}

// active returns the active (last) manifest, or nil if the store is empty.
func (s *parsedStore) active() *parsedManifest {
	if s == nil || len(s.manifests) == 0 {
		return nil
	}
	return s.manifests[len(s.manifests)-1]
}

// parseStore walks the JUMBF tree and resolves every C2PA manifest (a superbox
// holding a c2pa.claim child) into a parsedManifest. It is best-effort: missing
// or undecodable pieces leave the corresponding field zero.
func parseStore(ctx context.Context, jumbf []byte) *parsedStore {
	st := &parsedStore{}
	for _, b := range parseBoxTree(ctx, jumbf) {
		collectManifests(b, st)
	}
	return st
}

func collectManifests(b *box, st *parsedStore) {
	if b.tbox != "jumb" {
		return
	}
	if m := asManifest(b); m != nil {
		st.manifests = append(st.manifests, m)
		return
	}
	for _, c := range b.children {
		collectManifests(c, st)
	}
}

// asManifest interprets a superbox as a manifest if it directly contains a
// c2pa.claim child, returning nil otherwise.
func asManifest(b *box) *parsedManifest {
	hasClaim := false
	for _, c := range b.children {
		if isClaimLabel(c.label) {
			hasClaim = true
			break
		}
	}
	if !hasClaim {
		return nil
	}
	m := &parsedManifest{label: b.label, update: b.typeUUID == updateManifestUUID}
	for _, c := range b.children {
		switch {
		case isClaimLabel(c.label):
			if m.claimBytes != nil {
				// A manifest holds exactly one claim; a second is its own
				// defined failure (claim.multiple) and must not silently
				// replace the one the signature covers.
				m.multipleClaims = true
				continue
			}
			if d := dataChild(c); d != nil {
				m.claimBytes = d.content
				var claim map[string]any
				if decMode.Unmarshal(d.content, &claim) == nil {
					m.claim = claim
				}
			}
		case strings.HasSuffix(c.label, "c2pa.signature"):
			if d := dataChild(c); d != nil {
				m.signature = d.content
			}
		case strings.HasSuffix(c.label, "c2pa.assertions"):
			for _, a := range c.children {
				if d := dataChild(a); d != nil {
					m.assertions = append(m.assertions, rawAssertion{
						label:      a.label,
						tbox:       d.tbox,
						boxContent: a.content,
						data:       d.content,
					})
				}
			}
		}
	}
	return m
}

// updateManifestUUID is the JUMBF type UUID an Update Manifest's superbox
// carries, 6332756D-0011-0010-8000-00AA00389B71 ("c2um"). A standard manifest
// carries a different one; nothing else distinguishes the two, so this is the
// only thing that can tell a validator not to demand a hard binding.
var updateManifestUUID = [16]byte{
	0x63, 0x32, 0x75, 0x6D, 0x00, 0x11, 0x00, 0x10,
	0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
}

// dataChild returns a superbox's first content box (the box after its jumd), or
// nil if it has none.
func dataChild(b *box) *box {
	if len(b.children) == 0 {
		return nil
	}
	return b.children[0]
}

// isClaimLabel reports whether a box label denotes a C2PA claim box, matching
// both v1 ("c2pa.claim") and versioned ("c2pa.claim.v2") spellings.
func isClaimLabel(label string) bool {
	return strings.HasSuffix(label, "c2pa.claim") || strings.Contains(label, "c2pa.claim.v")
}
