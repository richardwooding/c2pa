package c2pa

// StatusCode is a C2PA validation status code. The string values mirror the
// codes defined in the C2PA Technical Specification §15 (e.g.
// "claimSignature.validated", "signingCredential.untrusted") so a caller can
// match against them directly.
type StatusCode string

// Severity classifies a StatusCode as success, informational, or failure. Only
// failures flip ValidationResult.Valid to false.
type Severity int

const (
	// SeverityInformational is advisory: the step ran but its outcome neither
	// proves nor disproves validity (e.g. revocation status unknown, an
	// unsupported-but-not-fatal feature, an absent optional timestamp).
	SeverityInformational Severity = iota
	// SeveritySuccess records a validation step that passed.
	SeveritySuccess
	// SeverityFailure records a validation step that failed. Any failure makes
	// the manifest invalid.
	SeverityFailure
)

// Success status codes.
const (
	StatusClaimSignatureValidated     StatusCode = "claimSignature.validated"
	StatusSigningCredentialTrusted    StatusCode = "signingCredential.trusted"
	StatusTimeStampValidated          StatusCode = "timeStamp.validated"
	StatusAssertionHashedURIMatch     StatusCode = "assertion.hashedURI.match"
	StatusAssertionDataHashMatch      StatusCode = "assertion.dataHash.match"
	StatusAssertionBoxesHashMatch     StatusCode = "assertion.boxesHash.match"
	StatusAssertionBMFFHashMatch      StatusCode = "assertion.bmffHash.match"
	StatusIngredientManifestValidated StatusCode = "ingredient.manifest.validated"
	// StatusIdentityTrusted reports a CAWG identity assertion (cawg.identity)
	// whose signature, references and padding all check and whose signing
	// credential reaches an identity trust anchor (WithIdentityTrust). The named
	// actor is proven. Recorded at "<manifest label>/<assertion label>".
	StatusIdentityTrusted StatusCode = "cawg.identity.trusted"
	// StatusICACredentialValid reports an identity claims aggregation
	// credential (CAWG §8.1) that passed every check this validator makes;
	// StatusICATimeStampValidated its verified sigTst2 time-stamp.
	StatusICACredentialValid    StatusCode = "cawg.ica.credential_valid"
	StatusICATimeStampValidated StatusCode = "cawg.ica.time_stamp.validated"
	// StatusIdentityWellFormed reports a CAWG identity assertion that checks in
	// every way except that no identity trust anchor vouches for its credential
	// (CAWG spec §7.2.1): the signature is genuine, the actor is unproven.
	StatusIdentityWellFormed StatusCode = "cawg.identity.well-formed"
)

// Failure status codes.
const (
	StatusClaimMissing         StatusCode = "claim.missing"
	StatusClaimRequiredMissing StatusCode = "claim.required.missing"
	StatusClaimMultiple        StatusCode = "claim.multiple"
	// StatusManifestUpdateInvalid reports an Update Manifest carrying something
	// §11.2.3 forbids it: a hard binding, a thumbnail, or an action outside the
	// four that do not change the content. Rejecting an update manifest also
	// leaves the asset unbound, so StatusHardBindingMissing is recorded with it.
	StatusManifestUpdateInvalid StatusCode = "manifest.update.invalid"
	// StatusManifestUpdateWrongParents reports an Update Manifest with zero or
	// more than one parentOf ingredient. Exactly one is required: it names the
	// manifest being updated, and so the hard binding that covers the content.
	// Recorded with StatusHardBindingMissing, since without that one parent
	// nothing hashed the asset.
	StatusManifestUpdateWrongParents StatusCode = "manifest.update.wrongParents"
	// StatusManifestMultipleParents reports a manifest with more than one
	// parentOf ingredient, which leaves the asset's lineage ambiguous.
	StatusManifestMultipleParents    StatusCode = "manifest.multipleParents"
	StatusClaimSignatureMissing      StatusCode = "claimSignature.missing"
	StatusClaimSignatureMismatch     StatusCode = "claimSignature.mismatch"
	StatusSigningCredentialUntrusted StatusCode = "signingCredential.untrusted"
	StatusSigningCredentialInvalid   StatusCode = "signingCredential.invalid"
	StatusSigningCredentialRevoked   StatusCode = "signingCredential.revoked"
	StatusSigningCredentialExpired   StatusCode = "signingCredential.expired"
	StatusTimeStampMismatch          StatusCode = "timeStamp.mismatch"
	StatusTimeStampUntrusted         StatusCode = "timeStamp.untrusted"
	StatusTimeStampOutsideValidity   StatusCode = "timeStamp.outsideValidity"
	StatusAssertionHashedURIMismatch StatusCode = "assertion.hashedURI.mismatch"
	StatusAssertionDataHashMismatch  StatusCode = "assertion.dataHash.mismatch"
	StatusAssertionBoxesHashMismatch StatusCode = "assertion.boxesHash.mismatch"
	// StatusAssertionBoxesHashUnknownBox reports that the asset's box structure
	// does not line up with the boxes[] the assertion describes — a name that
	// does not match the next box in file order, or a box the assertion leaves
	// uncovered. Either way the assertion does not bind the asset as it stands.
	StatusAssertionBoxesHashUnknownBox StatusCode = "assertion.boxesHash.unknownBox"
	StatusAssertionBoxesHashMalformed  StatusCode = "assertion.boxesHash.malformed"
	StatusAssertionBMFFHashMismatch    StatusCode = "assertion.bmffHash.mismatch"
	StatusAssertionBMFFHashMalformed   StatusCode = "assertion.bmffHash.malformed"
	StatusAssertionMissing             StatusCode = "assertion.missing"
	// StatusHardBindingMissing reports that no usable hard binding covered the
	// asset's bytes, so nothing hashed them. Either the manifest carries no
	// binding this container can use, or an update manifest was rejected before
	// the parent manifest that would have bound the content was reached.
	StatusHardBindingMissing         StatusCode = "hardBinding.missing"
	StatusAlgorithmUnsupported       StatusCode = "algorithm.unsupported"
	StatusIngredientManifestMismatch StatusCode = "ingredient.manifest.mismatch"
	StatusGeneralError               StatusCode = "general.error"

	// CAWG identity assertion failures (CAWG Identity Assertion spec §7.2.2),
	// recorded at "<manifest label>/<assertion label>". Codes the C2PA core
	// defines for the signature itself — claimSignature.*, signingCredential.*,
	// timeStamp.*, algorithm.unsupported — are reused at that same URI, as
	// §8.2.2 directs.
	StatusIdentityCBORInvalid        StatusCode = "cawg.identity.cbor.invalid"
	StatusIdentityAssertionMismatch  StatusCode = "cawg.identity.assertion.mismatch"
	StatusIdentityAssertionDuplicate StatusCode = "cawg.identity.assertion.duplicate"
	StatusIdentityHardBindingMissing StatusCode = "cawg.identity.hard_binding_missing"
	StatusIdentitySigTypeUnknown     StatusCode = "cawg.identity.sig_type.unknown"
	StatusIdentityPadInvalid         StatusCode = "cawg.identity.pad.invalid"
	StatusIdentityCredentialRevoked  StatusCode = "cawg.identity.credential_revoked"

	// Soft binding failures (spec §18.10), recorded at
	// "<manifest label>/<assertion label>". Structural only: whether the bytes
	// are a well-formed soft binding is checkable with certainty, whether the
	// content matches is not — that is softBinding.unevaluated, informational.
	// The C2PA specification defines no status codes for soft bindings.
	StatusSoftBindingMalformed  StatusCode = "softBinding.malformed"
	StatusSoftBindingAlgMissing StatusCode = "softBinding.alg.missing"
	StatusSoftBindingPadInvalid StatusCode = "softBinding.pad.invalid"

	// Identity claims aggregation failures (CAWG §8.1.5.6), at the identity
	// assertion's URI. Not declared, having no emission site: did_unavailable
	// (no DID is resolved over the network), untrusted_issuer (no issuer trust
	// list yet), and the revocation codes.
	StatusICAInvalidCOSESign1            StatusCode = "cawg.ica.invalid_cose_sign1"
	StatusICAInvalidAlg                  StatusCode = "cawg.ica.invalid_alg"
	StatusICAInvalidContentType          StatusCode = "cawg.ica.invalid_content_type"
	StatusICAInvalidVerifiableCredential StatusCode = "cawg.ica.invalid_verifiable_credential"
	StatusICAInvalidIssuer               StatusCode = "cawg.ica.invalid_issuer"
	StatusICADIDUnsupportedMethod        StatusCode = "cawg.ica.did_unsupported_method"
	StatusICAInvalidDIDDocument          StatusCode = "cawg.ica.invalid_did_document"
	StatusICASignatureMismatch           StatusCode = "cawg.ica.signature_mismatch"
	StatusICATimeStampInvalid            StatusCode = "cawg.ica.time_stamp.invalid"
	StatusICAValidFromMissing            StatusCode = "cawg.ica.valid_from.missing"
	StatusICAValidFromInvalid            StatusCode = "cawg.ica.valid_from.invalid"
	StatusICAValidUntilInvalid           StatusCode = "cawg.ica.valid_until.invalid"
	StatusICASignerPayloadMismatch       StatusCode = "cawg.ica.signer_payload.mismatch"
	StatusICAVerifiedIdentitiesMissing   StatusCode = "cawg.ica.verified_identities.missing"
	StatusICAVerifiedIdentitiesInvalid   StatusCode = "cawg.ica.verified_identities.invalid"
)

// Informational status codes.
const (
	StatusRevocationUnknown StatusCode = "signingCredential.revocation.unknown"
	StatusTimeStampMissing  StatusCode = "timeStamp.missing"
	StatusUnsupported       StatusCode = "general.unsupported"

	// Soft binding informationals (spec §18.10), at the assertion's URI.
	// softBinding.unevaluated is the verdict on every well-formed soft binding:
	// this library computes no soft binding algorithm, so a match is neither
	// proved nor disproved. It is a code of its own rather than
	// general.unsupported because that code is used for several unrelated
	// things and a caller must be able to find THIS one.
	// softBinding.alg.unlisted is an algorithm absent from the embedded
	// snapshot of the C2PA algorithm list. §9.3.2 requires a listed algorithm,
	// but the list grows by third-party pull request and the specification's own
	// example uses an unregistered identifier, so failing on it would fail
	// correct files — a deliberate divergence, see softbindings/README.md.
	StatusSoftBindingUnevaluated StatusCode = "softBinding.unevaluated"
	StatusSoftBindingAlgUnlisted StatusCode = "softBinding.alg.unlisted"
	// StatusAssertionBoxesHashAdditionalExclusions reports that a box-hash
	// assertion excluded something beyond the C2PA store itself — asset
	// metadata, or a whole non-C2PA box skipped with "excluded": true. Those
	// exclusions are permitted, so this is advisory rather than a failure, but
	// it says the hard binding covers less of the asset than the baseline.
	StatusAssertionBoxesHashAdditionalExclusions StatusCode = "assertion.boxesHash.additionalExclusionsPresent"
)

// statusSeverity maps every known StatusCode to its Severity. Codes absent from
// the table are treated as SeverityInformational by Severity().
var statusSeverity = map[StatusCode]Severity{
	StatusClaimSignatureValidated:     SeveritySuccess,
	StatusSigningCredentialTrusted:    SeveritySuccess,
	StatusTimeStampValidated:          SeveritySuccess,
	StatusAssertionHashedURIMatch:     SeveritySuccess,
	StatusAssertionDataHashMatch:      SeveritySuccess,
	StatusAssertionBoxesHashMatch:     SeveritySuccess,
	StatusAssertionBMFFHashMatch:      SeveritySuccess,
	StatusIngredientManifestValidated: SeveritySuccess,
	StatusIdentityTrusted:             SeveritySuccess,
	StatusIdentityWellFormed:          SeveritySuccess,
	StatusICACredentialValid:          SeveritySuccess,
	StatusICATimeStampValidated:       SeveritySuccess,

	StatusClaimMissing:                   SeverityFailure,
	StatusClaimRequiredMissing:           SeverityFailure,
	StatusClaimMultiple:                  SeverityFailure,
	StatusClaimSignatureMissing:          SeverityFailure,
	StatusClaimSignatureMismatch:         SeverityFailure,
	StatusSigningCredentialUntrusted:     SeverityFailure,
	StatusSigningCredentialInvalid:       SeverityFailure,
	StatusSigningCredentialRevoked:       SeverityFailure,
	StatusSigningCredentialExpired:       SeverityFailure,
	StatusTimeStampMismatch:              SeverityFailure,
	StatusTimeStampUntrusted:             SeverityFailure,
	StatusTimeStampOutsideValidity:       SeverityFailure,
	StatusAssertionHashedURIMismatch:     SeverityFailure,
	StatusAssertionDataHashMismatch:      SeverityFailure,
	StatusAssertionBoxesHashMismatch:     SeverityFailure,
	StatusAssertionBoxesHashUnknownBox:   SeverityFailure,
	StatusAssertionBoxesHashMalformed:    SeverityFailure,
	StatusManifestUpdateInvalid:          SeverityFailure,
	StatusManifestUpdateWrongParents:     SeverityFailure,
	StatusManifestMultipleParents:        SeverityFailure,
	StatusAssertionBMFFHashMismatch:      SeverityFailure,
	StatusAssertionBMFFHashMalformed:     SeverityFailure,
	StatusAssertionMissing:               SeverityFailure,
	StatusHardBindingMissing:             SeverityFailure,
	StatusAlgorithmUnsupported:           SeverityFailure,
	StatusIngredientManifestMismatch:     SeverityFailure,
	StatusGeneralError:                   SeverityFailure,
	StatusIdentityCBORInvalid:            SeverityFailure,
	StatusIdentityAssertionMismatch:      SeverityFailure,
	StatusIdentityAssertionDuplicate:     SeverityFailure,
	StatusIdentityHardBindingMissing:     SeverityFailure,
	StatusIdentitySigTypeUnknown:         SeverityFailure,
	StatusIdentityPadInvalid:             SeverityFailure,
	StatusSoftBindingMalformed:           SeverityFailure,
	StatusSoftBindingAlgMissing:          SeverityFailure,
	StatusSoftBindingPadInvalid:          SeverityFailure,
	StatusIdentityCredentialRevoked:      SeverityFailure,
	StatusICAInvalidCOSESign1:            SeverityFailure,
	StatusICAInvalidAlg:                  SeverityFailure,
	StatusICAInvalidContentType:          SeverityFailure,
	StatusICAInvalidVerifiableCredential: SeverityFailure,
	StatusICAInvalidIssuer:               SeverityFailure,
	StatusICADIDUnsupportedMethod:        SeverityFailure,
	StatusICAInvalidDIDDocument:          SeverityFailure,
	StatusICASignatureMismatch:           SeverityFailure,
	StatusICATimeStampInvalid:            SeverityFailure,
	StatusICAValidFromMissing:            SeverityFailure,
	StatusICAValidFromInvalid:            SeverityFailure,
	StatusICAValidUntilInvalid:           SeverityFailure,
	StatusICASignerPayloadMismatch:       SeverityFailure,
	StatusICAVerifiedIdentitiesMissing:   SeverityFailure,
	StatusICAVerifiedIdentitiesInvalid:   SeverityFailure,

	StatusRevocationUnknown: SeverityInformational,
	StatusTimeStampMissing:  SeverityInformational,
	StatusUnsupported:       SeverityInformational,

	StatusSoftBindingUnevaluated: SeverityInformational,
	StatusSoftBindingAlgUnlisted: SeverityInformational,

	StatusAssertionBoxesHashAdditionalExclusions: SeverityInformational,
}

// Severity returns the StatusCode's severity. Unknown codes are informational.
func (c StatusCode) Severity() Severity {
	return statusSeverity[c]
}
