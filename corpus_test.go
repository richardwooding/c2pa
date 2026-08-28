package c2pa

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

const corpusMarker = "CORPUSMARKERXYZ"

func corpusClock() func() time.Time {
	return func() time.Time { return corpusEpoch }
}

func markerAssertion() assertionSpec {
	return assertionSpec{
		label: "com.example.marker",
		value: map[string]any{"marker": corpusMarker},
	}
}

func emptyPool() *x509.CertPool { return x509.NewCertPool() }

func runCorpus(t *testing.T, container Container, asset []byte, sb *signerBundle, extra ...ValidateOption) ValidationResult {
	t.Helper()
	opts := []ValidateOption{
		WithSigningTrust(sb.roots),
		WithClock(corpusClock()),
		WithOnlineRevocation(false),
	}
	return Validate(context.Background(), container, bytes.NewReader(asset), append(opts, extra...)...)
}

func TestCorpusPositiveMatrix(t *testing.T) {
	containers := []struct {
		name string
		c    Container
	}{{"jpeg", JPEG}, {"png", PNG}}
	algs := []struct {
		name string
		alg  cose.Algorithm
	}{
		{"es256", cose.AlgorithmES256},
		{"es384", cose.AlgorithmES384},
		{"eddsa", cose.AlgorithmEdDSA},
		{"ps256", cose.AlgorithmPS256},
	}
	claims := []struct {
		name string
		v2   bool
	}{{"claimv1", false}, {"claimv2", true}}

	for _, ct := range containers {
		for _, a := range algs {
			for _, cl := range claims {
				t.Run(ct.name+"/"+a.name+"/"+cl.name, func(t *testing.T) {
					sb := newCorpusSigner(t, a.alg)
					asset := buildAsset(t, ct.c, manifestSpec{
						signer:     sb,
						claimV2:    cl.v2,
						assertions: []assertionSpec{markerAssertion()},
					})
					res := runCorpus(t, ct.c, asset, sb)
					if !res.Valid {
						t.Fatalf("expected valid, got %v", codes(res))
					}
					for _, want := range []StatusCode{
						StatusClaimSignatureValidated,
						StatusSigningCredentialTrusted,
						StatusAssertionHashedURIMatch,
						StatusAssertionDataHashMatch,
					} {
						if !res.Has(want) {
							t.Errorf("missing %s; got %v", want, codes(res))
						}
					}
				})
			}
		}
	}
}

func TestCorpusNegatives(t *testing.T) {
	tests := []struct {
		name      string
		container Container
		spec      func(sb *signerBundle) manifestSpec
		certOpts  []certOpt
		mutate    func([]byte) []byte
		opts      func(sb *signerBundle) []ValidateOption
		want      StatusCode
		wantValid bool
	}{
		{
			name:      "data hash mismatch on trailing bytes",
			container: JPEG,
			mutate: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[len(out)-3] ^= 0xFF
				return out
			},
			want: StatusAssertionDataHashMismatch,
		},
		{
			name:      "assertion hash mismatch",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{signer: sb, assertions: []assertionSpec{markerAssertion()}}
			},
			mutate: func(b []byte) []byte {
				i := bytes.Index(b, []byte(corpusMarker))
				if i < 0 {
					return b
				}
				out := append([]byte(nil), b...)
				out[i] = 'X'
				return out
			},
			want: StatusAssertionHashedURIMismatch,
		},
		{
			name:      "corrupt cose signature",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{signer: sb, corruptSig: true}
			},
			want: StatusClaimSignatureMismatch,
		},
		{
			name:      "no x5chain",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{signer: sb, omitX5Chain: true}
			},
			want: StatusSigningCredentialInvalid,
		},
		{
			name:      "untrusted signer",
			container: JPEG,
			opts: func(sb *signerBundle) []ValidateOption {
				return []ValidateOption{WithSigningTrust(emptyPool())}
			},
			want: StatusSigningCredentialUntrusted,
		},
		{
			name:      "expired certificate",
			container: JPEG,
			certOpts:  []certOpt{certExpired()},
			want:      StatusSigningCredentialExpired,
		},
		{
			name:      "leaf without digitalSignature",
			container: JPEG,
			certOpts:  []certOpt{certNoDigitalSignature()},
			want:      StatusSigningCredentialInvalid,
		},
		{
			name:      "leaf with anyExtendedKeyUsage",
			container: JPEG,
			certOpts:  []certOpt{certAnyEKU()},
			want:      StatusSigningCredentialInvalid,
		},
		{
			name:      "leaf without EKU",
			container: JPEG,
			certOpts:  []certOpt{certNoEKU()},
			want:      StatusSigningCredentialInvalid,
		},
		{
			name:      "sha-1 signature in the chain",
			container: JPEG,
			certOpts:  []certOpt{certSHA1()},
			want:      StatusSigningCredentialInvalid,
		},
		{
			name:      "leaf is a CA",
			container: JPEG,
			certOpts:  []certOpt{certIsCA()},
			want:      StatusSigningCredentialInvalid,
		},
		{
			name:      "no hard binding",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{signer: sb, noHardBinding: true, assertions: []assertionSpec{markerAssertion()}}
			},
			want: StatusHardBindingMissing,
		},
		{
			name:      "bmff binding on a jpeg",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{
					signer:        sb,
					noHardBinding: true,
					extraBinding: &assertionSpec{
						label: "c2pa.hash.bmff.v2",
						value: map[string]any{"alg": "sha256", "hash": make([]byte, 32)},
					},
				}
			},
			want: StatusHardBindingMissing,
		},
		{
			name:      "claim references a missing assertion",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{
					signer: sb,
					claimExtra: map[string]any{
						"assertions": []any{map[string]any{
							"url":  "self#jumbf=c2pa.assertions/c2pa.absent",
							"hash": make([]byte, 32),
						}},
					},
				}
			},
			want: StatusAssertionMissing,
		},
		{
			name:      "manifest without a signature",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{signer: sb, omitSig: true}
			},
			want: StatusClaimSignatureMissing,
		},
		{
			name:      "claim box without data",
			container: JPEG,
			spec: func(sb *signerBundle) manifestSpec {
				return manifestSpec{signer: sb, emptyClaim: true}
			},
			want: StatusClaimRequiredMissing,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256, tc.certOpts...)
			spec := manifestSpec{signer: sb}
			if tc.spec != nil {
				spec = tc.spec(sb)
			}
			asset := buildAsset(t, tc.container, spec)
			if tc.mutate != nil {
				asset = tc.mutate(asset)
			}
			var extra []ValidateOption
			if tc.opts != nil {
				extra = tc.opts(sb)
			}
			res := runCorpus(t, tc.container, asset, sb, extra...)
			if !res.Has(tc.want) {
				t.Fatalf("want %s; got %v", tc.want, codes(res))
			}
			if res.Valid != tc.wantValid {
				t.Errorf("Valid = %v, want %v (statuses %v)", res.Valid, tc.wantValid, codes(res))
			}
		})
	}
}

func TestCorpusNoManifest(t *testing.T) {
	asset, _, _ := assembleAsset(JPEG, nil)
	res := Validate(context.Background(), JPEG, bytes.NewReader(asset), WithClock(corpusClock()))
	if !res.Has(StatusClaimMissing) {
		t.Fatalf("want %s; got %v", StatusClaimMissing, codes(res))
	}
	if info := Read(context.Background(), JPEG, bytes.NewReader(asset)); info.Present {
		t.Errorf("Read reported a manifest in an unsigned asset")
	}
}

// TestCorpusAttachedPayloadSubstitution pins the guard against substituting a
// signed payload for the claim box: verifyCOSE injects the claim bytes when the
// payload is detached (which is what real C2PA signers emit), so an ATTACHED
// payload must equal the claim box or the signature proves nothing about the
// claim that is actually parsed and reported.
func TestCorpusAttachedPayloadSubstitution(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)

	foreign := mustMarshalCBOR(t, map[string]any{
		"alg":             "sha256",
		"signature":       "self#jumbf=c2pa.signature",
		"assertions":      []any{},
		"dc:title":        "attacker chosen",
		"claim_generator": "not-the-real-generator/9.9",
	})

	asset := buildAsset(t, JPEG, manifestSpec{signer: sb, attachPayload: foreign})
	res := runCorpus(t, JPEG, asset, sb)

	info := Read(context.Background(), JPEG, bytes.NewReader(asset))
	if info.ClaimGenerator == "not-the-real-generator/9.9" {
		t.Fatalf("test setup wrong: Read saw the attacker payload, not the claim box")
	}

	if !res.Has(StatusClaimSignatureMismatch) {
		t.Errorf("want %s for a substituted payload; got %v", StatusClaimSignatureMismatch, codes(res))
	}
	if res.Has(StatusClaimSignatureValidated) {
		t.Errorf("signature must not validate over bytes that are not the claim; got %v", codes(res))
	}
	if res.Valid {
		t.Errorf("Valid = true for a manifest whose signature does not cover its claim")
	}
}

// TestCorpusAttachedPayloadMatchingClaim keeps the guard narrow: an attached
// payload that IS the claim box stays valid.
func TestCorpusAttachedPayloadMatchingClaim(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	asset := buildAsset(t, JPEG, manifestSpec{signer: sb, attachSelf: true})
	res := runCorpus(t, JPEG, asset, sb)
	if !res.Valid {
		t.Fatalf("attached payload equal to the claim should validate; got %v", codes(res))
	}
	if !res.Has(StatusClaimSignatureValidated) {
		t.Errorf("missing %s; got %v", StatusClaimSignatureValidated, codes(res))
	}
}
