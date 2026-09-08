package c2pa

// BindingState says what the active manifest's hard binding proved about the
// bytes this call evaluated — the question "were these the signed bytes?",
// answered without reading status codes. It is recorded at the decision point
// rather than derived from Statuses afterwards: an update manifest's binding
// statuses carry the PARENT manifest's label, and general.unsupported is used
// for several unrelated things, so no reading of Statuses reconstructs it.
//
// Valid is a different question. A manifest whose claim signature fails can
// still have BindingVerified (the bytes are the ones that manifest signed), and
// a manifest with a rejected timestamp is not Valid though its binding held.
type BindingState int

const (
	// BindingNone: nothing bound the asset — no manifest, no usable hard
	// binding (a v1 c2pa.hash.bmff only, a BMFF binding on a non-BMFF asset, a
	// manifest without one), or an update manifest rejected before the parent
	// manifest that binds the content was reached (hardBinding.missing).
	BindingNone BindingState = iota
	// BindingVerified: a hard binding covered these bytes and held —
	// assertion.dataHash.match, assertion.boxesHash.match or, over a whole
	// file or a complete fragment set, assertion.bmffHash.match.
	BindingVerified
	// BindingFailed: a hard binding covered these bytes and did not hold — a
	// mismatch, or a binding too malformed or too weakly hashed to check
	// (*.mismatch, *.malformed, *.unknownBox, algorithm.unsupported).
	BindingFailed
	// BindingUnevaluated: a hard binding exists but this call did not evaluate
	// it against these bytes — an object-level PDF manifest whose subject is an
	// embedded object (§A.4.3), an asset past the scan cap, a fragmented asset
	// with fragments missing or unreadable, an initialization segment read on
	// its own, a container with no box map for c2pa.hash.boxes, merkle maps
	// that do not fit the file, or a cancelled call. Neither failed nor passed:
	// ask a different question, or supply the fragments.
	BindingUnevaluated
)

// String returns "none", "verified", "failed" or "unevaluated".
func (s BindingState) String() string {
	switch s {
	case BindingNone:
		return "none"
	case BindingVerified:
		return "verified"
	case BindingFailed:
		return "failed"
	case BindingUnevaluated:
		return "unevaluated"
	}
	return "unknown"
}

// bindHook, when set (tests only), sees every second attempt to record a
// binding state that differs from the first — a double decision the
// first-wins rule would otherwise hide.
var bindHook func(prev, next BindingState)

// bind records the binding verdict, first-wins: the hard binding is decided
// once per call, and the sites that decide it are the only callers.
func (v *validator) bind(state BindingState) {
	if v.bindingSet {
		if state != v.binding && bindHook != nil {
			bindHook(v.binding, state)
		}
		return
	}
	v.binding, v.bindingSet = state, true
}

// bindFromStep records the verdict of one hard-binding step from the statuses
// it added (from index start): any failure other than a cancellation is
// BindingFailed; the step's match code is BindingVerified; an informational
// general.unsupported, or a cancellation, is BindingUnevaluated. A step that
// recorded nothing leaves the decision to whoever comes next.
func (v *validator) bindFromStep(start int, match StatusCode) {
	state, decided := BindingUnevaluated, false
	for i := start; i < len(v.res.Statuses); i++ {
		s := v.res.Statuses[i]
		switch {
		case s.Code == StatusGeneralError:
			decided = true // cancelled or unreadable: nothing was proved either way
		case s.Severity == SeverityFailure:
			v.bind(BindingFailed)
			return
		case s.Code == match:
			state, decided = BindingVerified, true
		case s.Code == StatusUnsupported:
			decided = true
		}
	}
	if decided {
		v.bind(state)
	}
}
