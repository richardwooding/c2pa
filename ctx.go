package c2pa

import (
	"context"
	"hash"
	"io"
)

// Cancellation helpers. The package promise is that a cancelled or expired
// context stops the work promptly and is reported as such — never as a
// mismatch, a malformed asset or a partial result presented as complete. The
// loops that walk boxes, objects and segments check ctx.Err() themselves; what
// these helpers cover is the work that happens between checks: hashing a large
// buffer and reading a large input.

// hashChunk is how many bytes hashWrite feeds a hash between context checks —
// about a millisecond of SHA-256, so a 256 MiB hash surrenders in a millisecond
// rather than a quarter of a second.
const hashChunk = 1 << 20

// readChunk is how many bytes readAllCtx reads between context checks.
const readChunk = 1 << 20

// hashWrite writes b to h in hashChunk slices, checking the context between
// them. It returns the context's error when it stops early; h then holds a
// truncated state that must not be compared with anything.
func hashWrite(ctx context.Context, h hash.Hash, b []byte) error {
	for len(b) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(b), hashChunk)
		h.Write(b[:n])
		b = b[n:]
	}
	return nil
}

// readAllCtx reads r to EOF or to limit bytes, whichever comes first, checking
// the context between reads of readChunk bytes. It returns the context's error
// when cancelled mid-read — with whatever was read so far, which callers must
// treat as nothing — and r's error otherwise. It is io.ReadAll(io.LimitReader(r,
// limit)) with a context.
func readAllCtx(ctx context.Context, r io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	var out []byte
	for len(out) < limit {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		want := min(limit-len(out), readChunk)
		if cap(out)-len(out) < want {
			// Grow geometrically, as io.ReadAll does, so a large read costs
			// O(n) copying rather than one copy per chunk.
			grown := make([]byte, len(out), min(limit, max(2*cap(out), len(out)+want)))
			copy(grown, out)
			out = grown
		}
		n, err := r.Read(out[len(out) : len(out)+want])
		out = out[:len(out)+n]
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
