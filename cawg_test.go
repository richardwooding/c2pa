package c2pa

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// identityBuild is what identityAssertionBytes writes; identityOpts mutate it
// so one builder covers the positive case and every defect the validator must
// name.
type identityBuild struct {
	sigType         string
	roles           []string
	extraRefs       []string // further labels to reference, from the boxes
	explicitRefs    []identityHashedURI
	noRefs          bool
	skipHardBinding bool
	dupRef          bool
	selfRef         bool
	tamperHash      bool
	absoluteLabel   string // reference with absolute URLs naming this manifest
	pad1, pad2      []byte
	pad2Set         bool
	omitPad1        bool
	sigNotBstr      bool
	dupKey          bool
	payloadNotMap   bool
	extraTop        map[string]any
	extraPayload    map[string]any
	sortedPayload   bool
	badSig          bool
	attachSelf      bool
	attachOther     bool
	tsKind          int // 0 none, 1 sigTst, 2 sigTst2, 3 both
	tsa             *testTSA
	tsGenTime       time.Time
}

type identityOpt func(*identityBuild)

func idSigType(s string) identityOpt      { return func(b *identityBuild) { b.sigType = s } }
func idRoles(r ...string) identityOpt     { return func(b *identityBuild) { b.roles = r } }
func idRefs(labels ...string) identityOpt { return func(b *identityBuild) { b.extraRefs = labels } }
func idExplicitRefs(r ...identityHashedURI) identityOpt {
	return func(b *identityBuild) { b.explicitRefs = r }
}
func idNoRefs() identityOpt                   { return func(b *identityBuild) { b.noRefs = true } }
func idSkipHardBinding() identityOpt          { return func(b *identityBuild) { b.skipHardBinding = true } }
func idDupRef() identityOpt                   { return func(b *identityBuild) { b.dupRef = true } }
func idSelfRef() identityOpt                  { return func(b *identityBuild) { b.selfRef = true } }
func idTamperHash() identityOpt               { return func(b *identityBuild) { b.tamperHash = true } }
func idAbsolute(label string) identityOpt     { return func(b *identityBuild) { b.absoluteLabel = label } }
func idPad1(p []byte) identityOpt             { return func(b *identityBuild) { b.pad1 = p } }
func idPad2(p []byte) identityOpt             { return func(b *identityBuild) { b.pad2, b.pad2Set = p, true } }
func idOmitPad1() identityOpt                 { return func(b *identityBuild) { b.omitPad1 = true } }
func idSigNotBstr() identityOpt               { return func(b *identityBuild) { b.sigNotBstr = true } }
func idDupKey() identityOpt                   { return func(b *identityBuild) { b.dupKey = true } }
func idPayloadNotMap() identityOpt            { return func(b *identityBuild) { b.payloadNotMap = true } }
func idExtraTop(m map[string]any) identityOpt { return func(b *identityBuild) { b.extraTop = m } }
func idExtraPayload(m map[string]any) identityOpt {
	return func(b *identityBuild) { b.extraPayload = m }
}
func idSortedPayload() identityOpt { return func(b *identityBuild) { b.sortedPayload = true } }
func idBadSig() identityOpt        { return func(b *identityBuild) { b.badSig = true } }
func idAttachSelf() identityOpt    { return func(b *identityBuild) { b.attachSelf = true } }
func idAttachOther() identityOpt   { return func(b *identityBuild) { b.attachOther = true } }
func idTimestamp(kind int, ta *testTSA) identityOpt {
	return func(b *identityBuild) { b.tsKind, b.tsa = kind, ta }
}
func idTimestampAt(kind int, ta *testTSA, at time.Time) identityOpt {
	return func(b *identityBuild) { b.tsKind, b.tsa, b.tsGenTime = kind, ta, at }
}

// identityAssertionBytes signs a signer_payload over the given boxes with the
// bundle's key and assembles a cawg.identity assertion around it, in c2pa-rs's
// field order unless an option says otherwise. alg is the claim's hash
// algorithm, which the references share.
func identityAssertionBytes(t testing.TB, sb *signerBundle, boxes []namedBox, alg string, opts ...identityOpt) []byte {
	t.Helper()
	b := &identityBuild{sigType: identitySigTypeX509, pad1: []byte{}}
	for _, o := range opts {
		o(b)
	}
	url := func(label string) string {
		if b.absoluteLabel != "" {
			return "self#jumbf=/c2pa/" + b.absoluteLabel + "/c2pa.assertions/" + label
		}
		return assertionURL(label)
	}
	refFor := func(label string) identityHashedURI {
		for _, nb := range boxes {
			if nb.label == label {
				return identityHashedURI{URL: url(label), Hash: hashOf(t, alg, nb.box[8:])}
			}
		}
		t.Fatalf("no boxed assertion %q to reference", label)
		return identityHashedURI{}
	}
	refs := b.explicitRefs
	if b.noRefs {
		refs = []identityHashedURI{}
	} else if refs == nil {
		if !b.skipHardBinding {
			for _, nb := range boxes {
				if len(nb.label) > 10 && nb.label[:10] == "c2pa.hash." {
					refs = append(refs, refFor(nb.label))
				}
			}
		}
		for _, l := range b.extraRefs {
			refs = append(refs, refFor(l))
		}
	}
	if b.tamperHash && len(refs) > 0 {
		refs[0].Hash = append([]byte{}, refs[0].Hash...)
		refs[0].Hash[0] ^= 0xFF
	}
	if b.dupRef && len(refs) > 0 {
		refs = append(refs, refs[0])
	}
	if b.selfRef {
		refs = append(refs, identityHashedURI{URL: url(identityLabel), Hash: make([]byte, 32)})
	}
	sp := identitySignerPayload{ReferencedAssertions: refs, SigType: b.sigType, Roles: b.roles}

	var payload []byte
	var err error
	switch {
	case b.payloadNotMap:
		payload, err = identityEncMode.Marshal(7)
	case b.extraPayload != nil || b.sortedPayload:
		m := map[string]any{"referenced_assertions": refs, "sig_type": b.sigType}
		if len(b.roles) > 0 {
			m["role"] = b.roles
		}
		for k, v := range b.extraPayload {
			m[k] = v
		}
		payload, err = encMode.Marshal(m)
	default:
		payload, err = identityEncMode.Marshal(sp)
	}
	if err != nil {
		t.Fatalf("encode signer_payload: %v", err)
	}

	msg, err := newSign1(rand.Reader, sb.key, sb.alg, sb.chainD, payload)
	if err != nil {
		t.Fatalf("sign identity payload: %v", err)
	}
	if b.badSig {
		msg.Signature[0] ^= 0xFF
	}
	if b.attachSelf {
		msg.Payload = payload
	}
	if b.attachOther {
		msg.Payload = []byte("not the signer_payload")
	}
	if b.tsKind != 0 {
		env, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		protected, signature, ok := coseParts(env)
		if !ok {
			t.Fatal("coseParts failed on a fresh envelope")
		}
		var tsOpts []tsTokenOpt
		if !b.tsGenTime.IsZero() {
			tsOpts = append(tsOpts, tsGenTime(b.tsGenTime))
		}
		if b.tsKind == 1 || b.tsKind == 3 {
			der := mintTSToken(t, b.tsa, coseCountersignData(payload, protected), tsOpts...)
			msg.Headers.Unprotected["sigTst"] = sigTstHeader(der)
		}
		if b.tsKind == 2 || b.tsKind == 3 {
			counter, _ := cbor.Marshal(signature)
			der := mintTSToken(t, b.tsa, coseCountersignData(counter, protected), tsOpts...)
			msg.Headers.Unprotected["sigTst2"] = sigTstHeader(der)
		}
		msg.Headers.RawUnprotected = nil
	}
	env, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	// The common case takes the production encoder; the structural defects
	// need a hand-built map.
	if !b.omitPad1 && !b.sigNotBstr && !b.dupKey && b.extraTop == nil {
		ia := identityAssertion{SignerPayload: payload, Signature: env, Pad1: b.pad1}
		if b.pad2Set {
			ia.Pad2 = b.pad2
			if ia.Pad2 == nil {
				ia.Pad2 = []byte{}
			}
		}
		out, err := identityEncMode.Marshal(ia)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	pairs := [][2]any{{"signer_payload", cbor.RawMessage(payload)}}
	if b.dupKey {
		pairs = append(pairs, [2]any{"signer_payload", cbor.RawMessage(payload)})
	}
	if b.sigNotBstr {
		pairs = append(pairs, [2]any{"signature", "not bytes"})
	} else {
		pairs = append(pairs, [2]any{"signature", env})
	}
	if !b.omitPad1 {
		pairs = append(pairs, [2]any{"pad1", b.pad1})
	}
	if b.pad2Set {
		pairs = append(pairs, [2]any{"pad2", b.pad2})
	}
	for k, v := range b.extraTop {
		pairs = append(pairs, [2]any{k, v})
	}
	return cborMapBytes(t, pairs)
}

// cborMapBytes hand-assembles a definite-length CBOR map from ordered pairs,
// duplicates and all — what no encoder will produce and the decoder must cope
// with.
func cborMapBytes(t testing.TB, pairs [][2]any) []byte {
	t.Helper()
	if len(pairs) >= 24 {
		t.Fatalf("cborMapBytes: %d pairs", len(pairs))
	}
	out := []byte{0xa0 | byte(len(pairs))}
	for _, kv := range pairs {
		k, err := identityEncMode.Marshal(kv[0])
		if err != nil {
			t.Fatal(err)
		}
		v, err := identityEncMode.Marshal(kv[1])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, k...)
		out = append(out, v...)
	}
	return out
}

const corpusManifestLabel = "urn:uuid:00000000-0000-4000-8000-000000000001"

// identityAsset builds a JPEG whose claim (signed by claimSB) carries the
// marker assertion and one cawg.identity assertion signed by idSB over the hard
// binding and whatever the options add.
func identityAsset(t testing.TB, claimSB, idSB *signerBundle, opts ...identityOpt) []byte {
	t.Helper()
	return buildAsset(t, JPEG, manifestSpec{
		signer:     claimSB,
		claimV2:    true,
		assertions: []assertionSpec{markerAssertion()},
		derived: func(t testing.TB, boxes []namedBox) []assertionSpec {
			return []assertionSpec{{label: identityLabel, raw: identityAssertionBytes(t, idSB, boxes, "sha256", opts...)}}
		},
	})
}

// identityURI is where the corpus manifest's identity statuses land.
const identityURI = corpusManifestLabel + "/" + identityLabel

func identitySigners(t testing.TB) (claimSB, idSB *signerBundle) {
	t.Helper()
	return newCorpusSigner(t, cose.AlgorithmES256), newCorpusSigner(t, cose.AlgorithmEdDSA)
}

func TestIdentityWellFormedAndTrusted(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	asset := identityAsset(t, claimSB, idSB, idRefs("com.example.marker"), idRoles("cawg.creator", "cawg.editor"))

	res := runCorpus(t, JPEG, asset, claimSB)
	if !res.Valid {
		t.Fatalf("expected valid: %v", codes(res))
	}
	if len(res.Identities) != 1 {
		t.Fatalf("identities = %d", len(res.Identities))
	}
	id := res.Identities[0]
	switch {
	case id.Label != identityLabel, id.URI != identityURI, id.SigType != identitySigTypeX509:
		t.Errorf("identity header = %+v", id)
	case !equalStrings(id.Roles, []string{"cawg.creator", "cawg.editor"}):
		t.Errorf("roles = %v", id.Roles)
	case !equalStrings(id.Referenced, []string{"c2pa.hash.data", "com.example.marker"}):
		t.Errorf("referenced = %v", id.Referenced)
	case !id.Valid, id.Trusted, id.Name() != "", len(id.Chain) != 2, !id.SignedAt.IsZero():
		t.Errorf("verdict = valid %v trusted %v name %q chain %d signedAt %v", id.Valid, id.Trusted, id.Name(), len(id.Chain), id.SignedAt)
	}
	for _, want := range []StatusCode{StatusClaimSignatureValidated, StatusTimeStampMissing, StatusRevocationUnknown, StatusIdentityWellFormed} {
		if !hasAt(res, want, identityURI) {
			t.Errorf("missing %s at the identity URI: %v", want, codes(res))
		}
	}
	if hasAt(res, StatusSigningCredentialUntrusted, identityURI) || hasAt(res, StatusIdentityTrusted, identityURI) {
		t.Errorf("unanchored identity must be well-formed only: %v", codes(res))
	}
	// The claim's own verdict is untouched by identity statuses.
	if res.VerifiedSigner() != "c2pa corpus signer" {
		t.Errorf("VerifiedSigner = %q", res.VerifiedSigner())
	}

	res = runCorpus(t, JPEG, asset, claimSB, WithIdentityTrust(idSB.roots))
	if !res.Valid || len(res.Identities) != 1 {
		t.Fatalf("anchored: valid=%v identities=%d %v", res.Valid, len(res.Identities), codes(res))
	}
	id = res.Identities[0]
	if !id.Valid || !id.Trusted || id.Name() != "c2pa corpus signer" {
		t.Errorf("anchored identity = valid %v trusted %v name %q", id.Valid, id.Trusted, id.Name())
	}
	if !hasAt(res, StatusIdentityTrusted, identityURI) || !hasAt(res, StatusSigningCredentialTrusted, identityURI) || hasAt(res, StatusIdentityWellFormed, identityURI) {
		t.Errorf("anchored statuses: %v", codes(res))
	}

	// Anchors that do not include the identity's CA leave it well-formed, with
	// the other explanation.
	res = runCorpus(t, JPEG, asset, claimSB, WithIdentityTrust(emptyPool()))
	if !hasAt(res, StatusIdentityWellFormed, identityURI) || res.Identities[0].Trusted {
		t.Errorf("empty anchors: %v", codes(res))
	}
}

func TestIdentityDefects(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	cases := []struct {
		name    string
		opts    []identityOpt
		want    StatusCode // recorded at the identity URI
		valid   bool       // the asset's verdict
		payload bool       // identity decoded far enough to carry a SigType
	}{
		{"pad1 non-zero", []identityOpt{idPad1([]byte{0, 1})}, StatusIdentityPadInvalid, false, true},
		{"pad2 non-zero", []identityOpt{idPad2([]byte{1})}, StatusIdentityPadInvalid, false, true},
		{"pad1 missing", []identityOpt{idOmitPad1()}, StatusIdentityCBORInvalid, false, false},
		{"signature not a byte string", []identityOpt{idSigNotBstr()}, StatusIdentityCBORInvalid, false, false},
		{"duplicate map key", []identityOpt{idDupKey()}, StatusIdentityCBORInvalid, false, false},
		{"signer_payload not a map", []identityOpt{idPayloadNotMap()}, StatusIdentityCBORInvalid, false, false},
		{"no references", []identityOpt{idNoRefs()}, StatusIdentityCBORInvalid, false, false},
		{"reference without hash", []identityOpt{idExplicitRefs(identityHashedURI{URL: assertionURL("c2pa.hash.data")})}, StatusIdentityCBORInvalid, false, false},
		{"duplicate reference", []identityOpt{idDupRef()}, StatusIdentityAssertionDuplicate, false, true},
		{"reference not in claim", []identityOpt{idExplicitRefs(identityHashedURI{URL: assertionURL("com.example.absent"), Hash: make([]byte, 32)})}, StatusIdentityAssertionMismatch, false, true},
		{"reference hash differs", []identityOpt{idTamperHash()}, StatusIdentityAssertionMismatch, false, true},
		{"foreign manifest absolute url", []identityOpt{idAbsolute("urn:uuid:ffffffff-0000-4000-8000-000000000009")}, StatusIdentityAssertionMismatch, false, true},
		{"no hard binding", []identityOpt{idSkipHardBinding(), idRefs("com.example.marker")}, StatusIdentityHardBindingMissing, false, true},
		{"self reference", []identityOpt{idSelfRef()}, StatusIdentityAssertionMismatch, false, true},
		{"unknown sig_type", []identityOpt{idSigType("com.example.magic")}, StatusIdentitySigTypeUnknown, false, true},
		{"bad signature", []identityOpt{idBadSig()}, StatusClaimSignatureMismatch, false, true},
		{"attached foreign payload", []identityOpt{idAttachOther()}, StatusClaimSignatureMismatch, false, true},
		{"v1 timestamp", []identityOpt{idTimestamp(1, newTestTSA(t))}, StatusTimeStampMismatch, false, true},
		{"v1 and v2 timestamps", []identityOpt{idTimestamp(3, newTestTSA(t))}, StatusTimeStampMismatch, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := identityAsset(t, claimSB, idSB, tc.opts...)
			res := runCorpus(t, JPEG, asset, claimSB, WithIdentityTrust(idSB.roots))
			if !hasAt(res, tc.want, identityURI) {
				t.Fatalf("missing %s at %s: %v", tc.want, identityURI, codes(res))
			}
			if res.Valid != tc.valid {
				t.Errorf("valid = %v, want %v: %v", res.Valid, tc.valid, codes(res))
			}
			if hasAt(res, StatusIdentityWellFormed, identityURI) || hasAt(res, StatusIdentityTrusted, identityURI) {
				t.Errorf("a defective identity must carry no success code: %v", codes(res))
			}
			if len(res.Identities) != 1 {
				t.Fatalf("identities = %d", len(res.Identities))
			}
			id := res.Identities[0]
			if id.Valid || id.Trusted || id.Name() != "" {
				t.Errorf("identity verdict = %+v", id)
			}
			if tc.payload && id.SigType == "" || !tc.payload && id.SigType != "" {
				t.Errorf("sigType %q, decoded=%v", id.SigType, tc.payload)
			}
			// The claim signer is judged on its own.
			if res.VerifiedSigner() != "c2pa corpus signer" {
				t.Errorf("VerifiedSigner = %q", res.VerifiedSigner())
			}
		})
	}
}

func TestIdentityToleratedShapes(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	cases := []struct {
		name string
		opts []identityOpt
	}{
		{"extra top-level key", []identityOpt{idExtraTop(map[string]any{"com.example.note": "hi"})}},
		{"extra payload key", []identityOpt{idExtraPayload(map[string]any{"com.example.note": 1})}},
		{"sorted payload order", []identityOpt{idSortedPayload()}},
		{"attached matching payload", []identityOpt{idAttachSelf()}},
		{"absolute urls naming this manifest", []identityOpt{idAbsolute(corpusManifestLabel)}},
		{"empty pad2", []identityOpt{idPad2(nil)}},
		{"long zero pads", []identityOpt{idPad1(make([]byte, 300)), idPad2(make([]byte, 30))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asset := identityAsset(t, claimSB, idSB, tc.opts...)
			res := runCorpus(t, JPEG, asset, claimSB, WithIdentityTrust(idSB.roots))
			if !res.Valid || !hasAt(res, StatusIdentityTrusted, identityURI) {
				t.Fatalf("valid=%v %v", res.Valid, codes(res))
			}
			if len(res.Identities) != 1 || !res.Identities[0].Trusted {
				t.Errorf("identities = %+v", res.Identities)
			}
		})
	}
}

func TestIdentityUnevaluatedFields(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	asset := identityAsset(t, claimSB, idSB, idExtraPayload(map[string]any{
		"expected_partial_claim": map[string]any{"alg": "sha256", "hash": make([]byte, 32)},
	}))
	res := runCorpus(t, JPEG, asset, claimSB)
	if !res.Valid || !hasAt(res, StatusIdentityWellFormed, identityURI) {
		t.Fatalf("valid=%v %v", res.Valid, codes(res))
	}
	if !hasAt(res, StatusUnsupported, identityURI) {
		t.Errorf("an unevaluated expected_* field must be reported: %v", codes(res))
	}
}

func TestIdentityClaimsAggregationRecognised(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	asset := identityAsset(t, claimSB, idSB, idSigType(identitySigTypeICA))
	res := runCorpus(t, JPEG, asset, claimSB, WithIdentityTrust(idSB.roots))
	if !res.Valid {
		t.Fatalf("an unevaluated credential is informational, not a failure: %v", codes(res))
	}
	if !hasAt(res, StatusUnsupported, identityURI) || hasAt(res, StatusIdentityWellFormed, identityURI) || hasAt(res, StatusIdentitySigTypeUnknown, identityURI) {
		t.Errorf("statuses: %v", codes(res))
	}
	if len(res.Identities) != 1 || res.Identities[0].Valid || res.Identities[0].SigType != identitySigTypeICA || len(res.Identities[0].Chain) != 0 {
		t.Errorf("identities = %+v", res.Identities)
	}
}

func TestIdentityTimestamp(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	ta := newTestTSA(t)
	asset := identityAsset(t, claimSB, idSB, idTimestamp(2, ta))

	res := runCorpus(t, JPEG, asset, claimSB, WithTimestampTrust(ta.pool()), WithIdentityTrust(idSB.roots))
	if !res.Valid || !hasAt(res, StatusTimeStampValidated, identityURI) || !hasAt(res, StatusIdentityTrusted, identityURI) {
		t.Fatalf("valid=%v %v", res.Valid, codes(res))
	}
	if got := res.Identities[0].SignedAt; !got.Equal(corpusEpoch) {
		t.Errorf("identity SignedAt = %v, want %v", got, corpusEpoch)
	}
	// The claim has no timestamp: its SignedAt stays zero and its own
	// timeStamp.missing stands, whatever the identity carries.
	if !res.SignedAt.IsZero() || !hasAt(res, StatusTimeStampMissing, corpusManifestLabel) {
		t.Errorf("claim SignedAt = %v; %v", res.SignedAt, codes(res))
	}

	// An unanchored TSA: the token still pins the identity certificate's
	// validity window but is a failure, and SignedAt stays zero.
	res = runCorpus(t, JPEG, asset, claimSB, WithTimestampTrust(emptyPool()), WithIdentityTrust(idSB.roots))
	if res.Valid || !hasAt(res, StatusTimeStampUntrusted, identityURI) || res.Identities[0].Valid || !res.Identities[0].SignedAt.IsZero() {
		t.Errorf("untrusted TSA: valid=%v id=%+v %v", res.Valid, res.Identities[0], codes(res))
	}

	// A genTime outside the identity certificate's validity is its own failure.
	asset = identityAsset(t, claimSB, idSB, idTimestampAt(2, ta, corpusEpoch.Add(3*365*24*time.Hour)))
	res = runCorpus(t, JPEG, asset, claimSB, WithTimestampTrust(ta.pool()), WithIdentityTrust(idSB.roots))
	if res.Valid || !hasAt(res, StatusTimeStampOutsideValidity, identityURI) {
		t.Errorf("genTime outside validity: valid=%v %v", res.Valid, codes(res))
	}
}

// TestIdentityCertificateProfile: the C2PA certificate profile binds an
// identity credential even when no anchor vouches for it, and the validity
// window is checked with or without anchors.
func TestIdentityCertificateProfile(t *testing.T) {
	claimSB := newCorpusSigner(t, cose.AlgorithmES256)
	cases := []struct {
		name string
		opts []certOpt
		want StatusCode
	}{
		{"expired leaf", []certOpt{certExpired()}, StatusSigningCredentialExpired},
		{"leaf is a CA", []certOpt{certIsCA()}, StatusSigningCredentialInvalid},
		{"no EKU", []certOpt{certNoEKU()}, StatusSigningCredentialInvalid},
		{"anyExtendedKeyUsage", []certOpt{certAnyEKU()}, StatusSigningCredentialInvalid},
		{"SHA-1 in chain", []certOpt{certSHA1()}, StatusSigningCredentialInvalid},
	}
	for _, tc := range cases {
		for _, anchored := range []bool{false, true} {
			name := tc.name + "/unanchored"
			if anchored {
				name = tc.name + "/anchored"
			}
			t.Run(name, func(t *testing.T) {
				idSB := newCorpusSigner(t, cose.AlgorithmEdDSA, tc.opts...)
				asset := identityAsset(t, claimSB, idSB)
				var extra []ValidateOption
				if anchored {
					extra = append(extra, WithIdentityTrust(idSB.roots))
				}
				res := runCorpus(t, JPEG, asset, claimSB, extra...)
				if !hasAt(res, tc.want, identityURI) {
					t.Fatalf("missing %s: %v", tc.want, codes(res))
				}
				if res.Valid || res.Identities[0].Valid || hasAt(res, StatusIdentityWellFormed, identityURI) || hasAt(res, StatusIdentityTrusted, identityURI) {
					t.Errorf("valid=%v id=%+v %v", res.Valid, res.Identities[0], codes(res))
				}
			})
		}
	}
}

func TestIdentityMultiple(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	second := newCorpusSigner(t, cose.AlgorithmPS256)
	asset := buildAsset(t, JPEG, manifestSpec{
		signer:     claimSB,
		claimV2:    true,
		assertions: []assertionSpec{markerAssertion()},
		derived: func(t testing.TB, boxes []namedBox) []assertionSpec {
			return []assertionSpec{
				{label: identityLabel, raw: identityAssertionBytes(t, idSB, boxes, "sha256", idRoles("cawg.creator"))},
				{label: identityLabel + "__1", raw: identityAssertionBytes(t, second, boxes, "sha256", idRoles("cawg.publisher"), idPad1([]byte{9}))},
			}
		},
	})
	res := runCorpus(t, JPEG, asset, claimSB, WithIdentityTrust(idSB.roots))
	if res.Valid {
		t.Fatalf("the second identity's pad is invalid: %v", codes(res))
	}
	if len(res.Identities) != 2 {
		t.Fatalf("identities = %d", len(res.Identities))
	}
	a, b := res.Identities[0], res.Identities[1]
	if a.Label != identityLabel || !a.Trusted || a.URI != identityURI {
		t.Errorf("first = %+v", a)
	}
	if b.Label != identityLabel+"__1" || b.Valid || b.URI != identityURI+"__1" || !hasAt(res, StatusIdentityPadInvalid, identityURI+"__1") {
		t.Errorf("second = %+v %v", b, codes(res))
	}
	if !hasAt(res, StatusIdentityTrusted, identityURI) || hasAt(res, StatusIdentityTrusted, identityURI+"__1") {
		t.Errorf("statuses: %v", codes(res))
	}
}

// TestIdentityInIngredientNotListed: identities in a manifest reached through
// the ingredient walk are validated at their own URIs but are not the asset's.
func TestIdentityInIngredientNotListed(t *testing.T) {
	claimSB, idSB := identitySigners(t)
	const parent = "urn:uuid:00000000-0000-4000-8000-0000000000aa"
	asset := buildAsset(t, JPEG, manifestSpec{
		label:      parent,
		signer:     claimSB,
		claimV2:    true,
		assertions: []assertionSpec{markerAssertion()},
		derived: func(t testing.TB, boxes []namedBox) []assertionSpec {
			return []assertionSpec{{label: identityLabel, raw: identityAssertionBytes(t, idSB, boxes, "sha256")}}
		},
		updateOverlay: &manifestSpec{
			signer:         claimSB,
			label:          "urn:uuid:00000000-0000-4000-8000-0000000000bb",
			claimV2:        true,
			updateManifest: true,
			noHardBinding:  true,
			assertions:     []assertionSpec{parentOfAssertion(t, parent)},
		},
	})
	res := runCorpus(t, JPEG, asset, claimSB)
	if len(res.Identities) != 0 {
		t.Errorf("an ingredient's identity is not the asset's: %+v", res.Identities)
	}
	if !hasAt(res, StatusIdentityWellFormed, parent+"/"+identityLabel) {
		t.Errorf("the ingredient's identity is still validated at its URI: %v", codes(res))
	}
}

func TestDecodeIdentityAssertionRejects(t *testing.T) {
	good := identityAssertion{
		SignerPayload: must(identityEncMode.Marshal(identitySignerPayload{
			ReferencedAssertions: []identityHashedURI{{URL: assertionURL("c2pa.hash.data"), Hash: make([]byte, 32)}},
			SigType:              identitySigTypeX509,
		})),
		Signature: []byte{1},
		Pad1:      []byte{},
	}
	if _, _, _, err := decodeIdentityAssertion(must(identityEncMode.Marshal(good))); err != nil {
		t.Fatalf("good assertion rejected: %v", err)
	}
	bad := map[string][]byte{
		"not a map":        {0x01},
		"empty":            {},
		"indefinite junk":  {0xbf, 0xff, 0xff},
		"role not strings": must(identityEncMode.Marshal(map[string]any{"signer_payload": map[string]any{"referenced_assertions": []any{map[string]any{"url": "x", "hash": []byte{1}}}, "sig_type": "t", "role": []any{1}}, "signature": []byte{1}, "pad1": []byte{}})),
		"empty role":       must(identityEncMode.Marshal(map[string]any{"signer_payload": map[string]any{"referenced_assertions": []any{map[string]any{"url": "x", "hash": []byte{1}}}, "sig_type": "t", "role": []any{""}}, "signature": []byte{1}, "pad1": []byte{}})),
		"sig_type number":  must(identityEncMode.Marshal(map[string]any{"signer_payload": map[string]any{"referenced_assertions": []any{map[string]any{"url": "x", "hash": []byte{1}}}, "sig_type": 5}, "signature": []byte{1}, "pad1": []byte{}})),
		"sig_type missing": must(identityEncMode.Marshal(map[string]any{"signer_payload": map[string]any{"referenced_assertions": []any{map[string]any{"url": "x", "hash": []byte{1}}}}, "signature": []byte{1}, "pad1": []byte{}})),
		"pad2 text":        must(identityEncMode.Marshal(map[string]any{"signer_payload": map[string]any{"referenced_assertions": []any{map[string]any{"url": "x", "hash": []byte{1}}}, "sig_type": "t"}, "signature": []byte{1}, "pad1": []byte{}, "pad2": "zz"})),
	}
	for name, data := range bad {
		if _, _, _, err := decodeIdentityAssertion(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestIdentityReferenceLabel(t *testing.T) {
	const m = "urn:c2pa:0000"
	cases := []struct {
		url   string
		label string
		ok    bool
	}{
		{"self#jumbf=c2pa.assertions/c2pa.hash.data", "c2pa.hash.data", true},
		{"self#jumbf=/c2pa/urn:c2pa:0000/c2pa.assertions/c2pa.hash.data", "c2pa.hash.data", true},
		{"self#jumbf=/c2pa/urn:c2pa:0001/c2pa.assertions/c2pa.hash.data", "", false},
		{"self#jumbf=c2pa.assertions/", "", false},
		{"self#jumbf=c2pa.assertions/a/b", "a/b", false},
		{"c2pa.hash.data", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		label, ok := identityReferenceLabel(tc.url, m)
		if ok != tc.ok || (ok && label != tc.label) {
			t.Errorf("%q → %q,%v; want %q,%v", tc.url, label, ok, tc.label, tc.ok)
		}
	}
}
