package c2pa

import (
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

func TestCorpusTimestampPositive(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind int
		opts []tsTokenOpt
	}{
		{"sigTst bare ContentInfo", 1, nil},
		{"sigTst TimeStampResp", 1, []tsTokenOpt{tsWrapInResp()}},
		{"sigTst2 bare ContentInfo", 2, nil},
		{"sigTst2 TimeStampResp", 2, []tsTokenOpt{tsWrapInResp()}},
		{"sigTst by subjectKeyIdentifier", 1, []tsTokenOpt{tsSubjectKeyID()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			ta := newTestTSA(t)
			asset := buildAsset(t, JPEG, manifestSpec{
				signer: sb, tsKind: tc.kind, tsa: ta, tsOpts: tc.opts,
			})
			res := runCorpus(t, JPEG, asset, sb, WithTimestampTrust(ta.pool()))
			if !res.Has(StatusTimeStampValidated) {
				t.Fatalf("want %s; got %v", StatusTimeStampValidated, codes(res))
			}
			if !res.Valid {
				t.Errorf("expected valid; got %v", codes(res))
			}
			if !res.SignedAt.Equal(corpusEpoch) {
				t.Errorf("SignedAt = %v, want %v", res.SignedAt, corpusEpoch)
			}
		})
	}
}

func TestCorpusTimestampNegatives(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind int
		opts []tsTokenOpt
		tsa  []tsaOpt
		want StatusCode
	}{
		{"imprint over the wrong bytes", 1, []tsTokenOpt{tsWrongImprint()}, nil, StatusTimeStampMismatch},
		{"sha-1 messageImprint algorithm", 1, []tsTokenOpt{tsSHA1Imprint()}, nil, StatusTimeStampMismatch},
		{"no signed attributes", 1, []tsTokenOpt{tsOmitSignedAttrs()}, nil, StatusTimeStampMismatch},
		{"signedAttrs left as a universal SET", 1, []tsTokenOpt{tsUniversalAttrs()}, nil, StatusTimeStampMismatch},
		{"messageDigest over other content", 1, []tsTokenOpt{tsBadMessageDigest()}, nil, StatusTimeStampMismatch},
		{"contentType is not id-ct-TSTInfo", 1, []tsTokenOpt{tsBadContentType()}, nil, StatusTimeStampMismatch},
		{"corrupt CMS signature", 1, []tsTokenOpt{tsCorruptSignature()}, nil, StatusTimeStampMismatch},
		{"two signers", 1, []tsTokenOpt{tsTwoSigners()}, nil, StatusTimeStampMismatch},
		{"signer certificate absent", 1, []tsTokenOpt{tsOmitCerts()}, nil, StatusTimeStampUntrusted},
		{"TSA leaf with anyExtendedKeyUsage", 1, nil, []tsaOpt{tsaAnyEKU()}, StatusTimeStampUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := newCorpusSigner(t, cose.AlgorithmES256)
			ta := newTestTSA(t, tc.tsa...)
			asset := buildAsset(t, JPEG, manifestSpec{
				signer: sb, tsKind: tc.kind, tsa: ta, tsOpts: tc.opts,
			})
			res := runCorpus(t, JPEG, asset, sb, WithTimestampTrust(ta.pool()))
			if !res.Has(tc.want) {
				t.Fatalf("want %s; got %v", tc.want, codes(res))
			}
			if res.Valid {
				t.Errorf("expected invalid; got %v", codes(res))
			}
		})
	}
}

// TestCorpusTimestampUntrustedPool covers the anchor, separately from token
// defects: a well-formed token from a TSA outside the pool.
func TestCorpusTimestampUntrustedPool(t *testing.T) {
	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ta := newTestTSA(t)
	asset := buildAsset(t, JPEG, manifestSpec{signer: sb, tsKind: 1, tsa: ta})
	res := runCorpus(t, JPEG, asset, sb, WithTimestampTrust(emptyPool()))
	if !res.Has(StatusTimeStampUntrusted) {
		t.Fatalf("want %s; got %v", StatusTimeStampUntrusted, codes(res))
	}
}

// TestCorpusTimestampPinsSigningWindow is the case the whole writer exists for:
// a signing certificate that has expired by wall-clock time but was valid at a
// trusted genTime must still be trusted, because verifyTime becomes the
// timestamp's genTime rather than the clock.
func TestCorpusTimestampPinsSigningWindow(t *testing.T) {
	signedAt := corpusEpoch
	longAfter := corpusEpoch.Add(3 * 365 * 24 * time.Hour)

	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ta := newTestTSA(t, tsaValidity(corpusEpoch.Add(-24*time.Hour), longAfter.Add(24*time.Hour)))
	asset := buildAsset(t, JPEG, manifestSpec{
		signer: sb, tsKind: 1, tsa: ta, tsOpts: []tsTokenOpt{tsGenTime(signedAt)},
	})

	withTS := runCorpus(t, JPEG, asset, sb,
		WithTimestampTrust(ta.pool()),
		WithClock(func() time.Time { return longAfter }))
	if !withTS.Has(StatusTimeStampValidated) {
		t.Fatalf("want %s; got %v", StatusTimeStampValidated, codes(withTS))
	}
	if withTS.Has(StatusSigningCredentialExpired) {
		t.Errorf("a trusted timestamp should pin the cert window; got %v", codes(withTS))
	}
	if !withTS.Valid {
		t.Errorf("expected valid; got %v", codes(withTS))
	}

	// An UNTRUSTED TSA still pins the window: the token is cryptographically
	// bound to this signature, so the signing time is attested even though the
	// authority does not anchor. The trust failure stands and keeps the asset
	// from ever being Valid — but it must not be compounded into a manufactured
	// signingCredential.expired, which would misfile a legitimately old file as
	// structurally broken rather than merely unanchored.
	noTS := runCorpus(t, JPEG, asset, sb,
		WithTimestampTrust(emptyPool()),
		WithClock(func() time.Time { return longAfter }))
	if noTS.Has(StatusSigningCredentialExpired) {
		t.Errorf("an attested genTime must pin the cert window even when the TSA is untrusted; got %v", codes(noTS))
	}
	if !noTS.Has(StatusTimeStampUntrusted) {
		t.Errorf("the trust failure must stand; got %v", codes(noTS))
	}
	if noTS.Valid {
		t.Error("an untrusted timestamp can never yield Valid")
	}
	if !noTS.SignedAt.IsZero() {
		t.Errorf("SignedAt is trusted-only; got %v from an untrusted TSA", noTS.SignedAt)
	}
}

// TestCorpusTimestampOutsideValidity: a genTime that falls outside the signing
// certificate's own validity window is its own defined failure — the
// certificate could not have signed anything at the time the token attests.
func TestCorpusTimestampOutsideValidity(t *testing.T) {
	// The token attests a time well before the signing certificate existed.
	beforeCert := corpusEpoch.Add(-2 * 365 * 24 * time.Hour)

	sb := newCorpusSigner(t, cose.AlgorithmES256)
	ta := newTestTSA(t, tsaValidity(beforeCert.Add(-24*time.Hour), corpusEpoch.Add(24*time.Hour)))
	asset := buildAsset(t, JPEG, manifestSpec{
		signer: sb, tsKind: 1, tsa: ta, tsOpts: []tsTokenOpt{tsGenTime(beforeCert)},
	})

	res := runCorpus(t, JPEG, asset, sb, WithTimestampTrust(ta.pool()))
	if !res.Has(StatusTimeStampOutsideValidity) {
		t.Fatalf("want %s; got %v", StatusTimeStampOutsideValidity, codes(res))
	}
	if res.Valid {
		t.Error("a timestamp outside the certificate's validity cannot be Valid")
	}
}
