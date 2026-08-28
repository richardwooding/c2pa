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

	// Without a trusted TSA the clock applies again, so the same asset expires.
	noTS := runCorpus(t, JPEG, asset, sb,
		WithTimestampTrust(emptyPool()),
		WithClock(func() time.Time { return longAfter }))
	if !noTS.Has(StatusSigningCredentialExpired) {
		t.Errorf("want %s once the timestamp is untrusted; got %v",
			StatusSigningCredentialExpired, codes(noTS))
	}
}
