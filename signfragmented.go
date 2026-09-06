package c2pa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrFragmentSet is returned by SignFragmented for a fragment set it cannot
// work with: none given, a writer count that differs from the reader count,
// more fragments than a Merkle tree may have leaves, a reader that cannot
// seek back to its start, or a fragment whose bytes changed between passes.
var ErrFragmentSet = errors.New("c2pa: fragment set unusable")

// SignFragmented signs a fragmented BMFF asset — a DASH/CMAF initialization
// segment ('ftyp' and 'moov') and its media fragments ('styp', 'sidx', 'moof',
// 'mdat') as separate files — binding every fragment through a Merkle tree
// (§A.5.4): each fragment gains a C2PA merkle box before its 'moof' with its
// leaf's proof, and the initialization segment gains the manifest, whose
// c2pa.hash.bmff.v3 carries the tree's row and the segment's own hash. The
// counterpart of c2pa-rs's Builder::sign_fragmented_files, and what
// ValidateFragmented verifies.
//
// fragments are ReadSeekers because each is visited more than once — hashed,
// verified in the self-check, written — one at a time, so memory is the
// initialization segment plus one fragment however long the stream is.
// outFragments receive the signed fragments in the same order as fragments
// and must be as many; outInit receives the signed initialization segment.
// Nothing is written until the whole set has passed ValidateFragmented; the
// fragments are then written first and the initialization segment last, so a
// write that fails midway leaves an unsigned segment beside playable fragments
// rather than a signed segment over unsigned ones.
//
// One tree per call (uniqueId and localId 1): sign each rendition separately.
// The 'sidx' first_offset before the insertion, and a 'tfhd' base_data_offset,
// are re-anchored to the moved 'moof' — including the stale ones c2pa-rs
// leaves behind, so its output can be re-signed here. An asset already signed
// keeps its manifest as the new one's parentOf ingredient, exactly as Sign
// does, and its old merkle boxes are replaced. An initialization segment that
// is itself a fragmented file, or a fragment, is refused with
// ErrFragmentedBMFF; a fragment with more than one 'moof' or 'mdat' with
// ErrUnsupportedContainer.
func (s *Signer) SignFragmented(ctx context.Context, init io.Reader, fragments []io.ReadSeeker, outInit io.Writer, outFragments []io.Writer, m Manifest) error {
	if init == nil || outInit == nil {
		return ErrNoInput
	}
	for i, f := range fragments {
		if f == nil {
			return fmt.Errorf("%w: fragment %d reader is nil", ErrNoInput, i)
		}
	}
	for i, w := range outFragments {
		if w == nil {
			return fmt.Errorf("%w: fragment %d writer is nil", ErrNoInput, i)
		}
	}
	switch n := len(fragments); {
	case n == 0:
		return fmt.Errorf("%w: no fragments", ErrFragmentSet)
	case len(outFragments) != n:
		return fmt.Errorf("%w: %d fragments but %d output writers", ErrFragmentSet, n, len(outFragments))
	case n > maxMerkleLeaves:
		return fmt.Errorf("%w: %d fragments exceed the %d-leaf cap", ErrFragmentSet, n, maxMerkleLeaves)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	initData, err := readWholeAsset(init)
	if err != nil {
		return err
	}
	// Refuse a wrong initialization segment before hashing every fragment.
	if err := checkInitSegment(ctx, initData); err != nil {
		return err
	}

	alg := s.cfg.hashAlg
	n := len(fragments)
	rowIndex := merkleRowIndex(n)
	padTo, err := merkleBoxSize(alg, 1, 1, n, rowIndex)
	if err != nil {
		return fmt.Errorf("c2pa: internal: %w", err)
	}
	placeholder, err := merkleBoxBytes(merkleBoxSpec{uniqueID: 1, localID: 1}, padTo)
	if err != nil {
		return fmt.Errorf("c2pa: internal: %w", err)
	}

	// Pass 1: every fragment's leaf, with a placeholder box of the final size
	// in place — the box's bytes are excluded from the hash, its length is not.
	src := &fragmentSource{in: fragments, alg: alg, box: func(int) ([]byte, error) { return placeholder, nil }}
	leaves := make([][]byte, n)
	for i := range fragments {
		if err := ctx.Err(); err != nil {
			return err
		}
		prepared, err := src.prepared(ctx, i)
		if err != nil {
			return err
		}
		if leaves[i], err = bmffHashDigest(ctx, alg, prepared); err != nil {
			return fmt.Errorf("fragment %d: %w: %v", i, ErrMalformedAsset, err)
		}
	}
	layers := merkleLayers(alg, leaves)
	src.leaf = leaves
	src.box = func(location int) ([]byte, error) {
		return merkleBoxBytes(merkleBoxSpec{uniqueID: 1, localID: 1, location: location, hashes: merkleProof(layers, location, rowIndex)}, padTo)
	}

	// The initialization segment goes through the ordinary pipeline; the
	// binding supplies the merkle assertion and validates through
	// ValidateFragmented, regenerating each signed fragment on demand.
	final, err := s.sign(ctx, BMFF, initData, m, &bmffMerkleBinding{alg: alg, count: n, row: layers[rowIndex], frags: src})
	if err != nil {
		if src.err != nil && errors.Is(err, ErrSelfCheckFailed) {
			return src.err // a reader failing mid-check is the real error
		}
		return err
	}

	// Write: fragments first, the segment last.
	for i := range fragments {
		prepared, err := src.prepared(ctx, i)
		if err != nil {
			return err
		}
		if _, err := outFragments[i].Write(prepared); err != nil {
			return fmt.Errorf("c2pa: writing fragment %d: %w", i, err)
		}
	}
	if _, err := outInit.Write(final); err != nil {
		return fmt.Errorf("c2pa: writing signed initialization segment: %w", err)
	}
	return nil
}

// checkInitSegment refuses what cannot be a DASH/CMAF initialization segment:
// a fragmented file or a fragment (top-level 'moof', 'mfra', 'sidx', 'styp' or
// a merkle box — ErrFragmentedBMFF), and a file without 'ftyp' and 'moov' or
// with bytes outside any box (ErrMalformedAsset). A 'sidx' in an initialization
// segment is the single-file SegmentBase style, whose offsets would point
// outside the file once fragments are separate.
func checkInitSegment(ctx context.Context, init []byte) error {
	top := parseBMFFBoxes(ctx, init)
	if len(top) == 0 {
		return fmt.Errorf("%w: initialization segment has no BMFF box structure", ErrMalformedAsset)
	}
	if last := top[len(top)-1]; last.end != len(init) {
		return fmt.Errorf("%w: initialization segment has %d trailing bytes outside any box", ErrMalformedAsset, len(init)-last.end)
	}
	hasFtyp, hasMoov := false, false
	for _, b := range top {
		switch b.typ {
		case "ftyp":
			hasFtyp = true
		case "moov":
			hasMoov = true
		case "moof", "mfra", "sidx", "styp":
			return fmt.Errorf("%w: initialization segment carries a top-level '%s' box — a fragmented file or a fragment, not an initialization segment", ErrFragmentedBMFF, b.typ)
		case "uuid":
			if b.usertype == c2paBoxUUID {
				if purpose, _, ok := c2paBoxPurpose(init, b); ok && purpose == "merkle" {
					return fmt.Errorf("%w: initialization segment carries a merkle box — a fragment, not an initialization segment", ErrFragmentedBMFF)
				}
			}
		}
	}
	if !hasFtyp {
		return fmt.Errorf("%w: initialization segment has no 'ftyp' box", ErrMalformedAsset)
	}
	if !hasMoov {
		return fmt.Errorf("%w: initialization segment has no 'moov' box", ErrMalformedAsset)
	}
	return nil
}

// fragmentSource reads the caller's fragments one at a time and produces each
// one's prepared form — the fragment with its merkle box in place — on demand.
// box says which merkle box: the placeholder during pass 1, the real one after
// the tree is built. Once leaf is set, every regeneration must reproduce the
// pass-1 leaf, or the source changed under the signer and is refused.
type fragmentSource struct {
	in   []io.ReadSeeker
	alg  string
	box  func(location int) ([]byte, error)
	leaf [][]byte
	err  error // the first error a lazy reader hit, surfaced in place of a self-check failure
}

// read seeks fragment i back to its start and reads it under the scan cap.
func (f *fragmentSource) read(i int) ([]byte, error) {
	if _, err := f.in[i].Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: fragment %d: seek: %v", ErrFragmentSet, i, err)
	}
	data, err := io.ReadAll(io.LimitReader(f.in[i], int64(ValidateMaxScan)))
	if err != nil {
		return nil, fmt.Errorf("fragment %d: %w: %v", i, ErrMalformedAsset, err)
	}
	if len(data) >= ValidateMaxScan {
		return nil, fmt.Errorf("fragment %d: %w", i, ErrAssetTooLarge)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("fragment %d: %w: empty input", i, ErrMalformedAsset)
	}
	return data, nil
}

// prepared is fragment i with its merkle box in place.
func (f *fragmentSource) prepared(ctx context.Context, i int) ([]byte, error) {
	data, err := f.read(i)
	if err != nil {
		return nil, err
	}
	box, err := f.box(i)
	if err != nil {
		return nil, fmt.Errorf("c2pa: internal: %w", err)
	}
	out, err := prepareFragment(ctx, data, box)
	if err != nil {
		return nil, fmt.Errorf("fragment %d: %w", i, embedError(err))
	}
	if f.leaf != nil {
		leaf, err := bmffHashDigest(ctx, f.alg, out)
		if err != nil || !bytes.Equal(leaf, f.leaf[i]) {
			return nil, fmt.Errorf("%w: fragment %d changed between passes", ErrFragmentSet, i)
		}
	}
	return out, nil
}

// originals are the fragments as given, for validating the asset as found.
func (f *fragmentSource) originals() []io.Reader {
	out := make([]io.Reader, len(f.in))
	for i := range f.in {
		out[i] = &lazyReader{src: f, gen: func() ([]byte, error) { return f.read(i) }}
	}
	return out
}

// signed are the fragments with their merkle boxes, for the self-check.
func (f *fragmentSource) signed(ctx context.Context) []io.Reader {
	out := make([]io.Reader, len(f.in))
	for i := range f.in {
		out[i] = &lazyReader{src: f, gen: func() ([]byte, error) { return f.prepared(ctx, i) }}
	}
	return out
}

// lazyReader materialises its fragment on the first Read and drops it at EOF,
// so ValidateFragmented — which reads its fragments one after another — holds
// one at a time. An error is remembered on the source.
type lazyReader struct {
	src  *fragmentSource
	gen  func() ([]byte, error)
	r    *bytes.Reader
	done bool
}

func (l *lazyReader) Read(p []byte) (int, error) {
	if l.done {
		return 0, io.EOF
	}
	if l.r == nil {
		data, err := l.gen()
		if err != nil {
			l.done = true
			if l.src.err == nil {
				l.src.err = err
			}
			return 0, err
		}
		l.r = bytes.NewReader(data)
	}
	n, err := l.r.Read(p)
	if err == io.EOF {
		l.done, l.r = true, nil
	}
	return n, err
}

// bmffMerkleBinding is the fragmented c2pa.hash.bmff.v3: the merkle assertion
// in place of a flat hash, the initialization segment's own offset-marker hash
// as initHash, and ValidateFragmented — over the signed fragments regenerated
// on demand — in place of Validate, which cannot see fragments in other files.
type bmffMerkleBinding struct {
	alg   string
	count int
	row   [][]byte
	frags *fragmentSource
}

func (bmffMerkleBinding) label() string         { return "c2pa.hash.bmff.v3" }
func (bmffMerkleBinding) matchCode() StatusCode { return StatusAssertionBMFFHashMatch }
func (b *bmffMerkleBinding) payload(_ []byteRange, digest []byte) ([]byte, error) {
	return bmffMerkleAssertion(b.alg, []merkleMapSpec{{uniqueID: 1, localID: 1, count: b.count, alg: b.alg, initHash: digest, hashes: b.row}})
}
func (b *bmffMerkleBinding) digest(ctx context.Context, layout []byte, _ []byteRange) ([]byte, error) {
	return bmffHashDigest(ctx, b.alg, layout)
}
func (bmffMerkleBinding) compareRanges(ctx context.Context, layout []byte, _ []byteRange) ([]byteRange, error) {
	seg, err := bmffStandardSegment(ctx, layout)
	if err != nil {
		return nil, err
	}
	return seg.ranges, nil
}
func (b *bmffMerkleBinding) validatePrior(ctx context.Context, asset []byte) ValidationResult {
	return ValidateFragmented(ctx, bytes.NewReader(asset), b.frags.originals(), WithOnlineRevocation(false))
}
func (b *bmffMerkleBinding) validateOutput(ctx context.Context, final []byte, opts []ValidateOption) ValidationResult {
	return ValidateFragmented(ctx, bytes.NewReader(final), b.frags.signed(ctx), opts...)
}
