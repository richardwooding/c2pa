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
)

// Failure status codes.
const (
	StatusClaimMissing               StatusCode = "claim.missing"
	StatusClaimRequiredMissing       StatusCode = "claim.required.missing"
	StatusClaimMultiple              StatusCode = "claim.multiple"
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
	StatusAssertionBMFFHashMismatch  StatusCode = "assertion.bmffHash.mismatch"
	StatusAssertionBMFFHashMalformed StatusCode = "assertion.bmffHash.malformed"
	StatusAssertionMissing           StatusCode = "assertion.missing"
	StatusHardBindingMissing         StatusCode = "hardBinding.missing"
	StatusAlgorithmUnsupported       StatusCode = "algorithm.unsupported"
	StatusIngredientManifestMismatch StatusCode = "ingredient.manifest.mismatch"
	StatusGeneralError               StatusCode = "general.error"
)

// Informational status codes.
const (
	StatusRevocationUnknown StatusCode = "signingCredential.revocation.unknown"
	StatusTimeStampMissing  StatusCode = "timeStamp.missing"
	StatusUnsupported       StatusCode = "general.unsupported"
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

	StatusClaimMissing:               SeverityFailure,
	StatusClaimRequiredMissing:       SeverityFailure,
	StatusClaimMultiple:              SeverityFailure,
	StatusClaimSignatureMissing:      SeverityFailure,
	StatusClaimSignatureMismatch:     SeverityFailure,
	StatusSigningCredentialUntrusted: SeverityFailure,
	StatusSigningCredentialInvalid:   SeverityFailure,
	StatusSigningCredentialRevoked:   SeverityFailure,
	StatusSigningCredentialExpired:   SeverityFailure,
	StatusTimeStampMismatch:          SeverityFailure,
	StatusTimeStampUntrusted:         SeverityFailure,
	StatusTimeStampOutsideValidity:   SeverityFailure,
	StatusAssertionHashedURIMismatch: SeverityFailure,
	StatusAssertionDataHashMismatch:  SeverityFailure,
	StatusAssertionBoxesHashMismatch: SeverityFailure,
	StatusAssertionBMFFHashMismatch:  SeverityFailure,
	StatusAssertionBMFFHashMalformed: SeverityFailure,
	StatusAssertionMissing:           SeverityFailure,
	StatusHardBindingMissing:         SeverityFailure,
	StatusAlgorithmUnsupported:       SeverityFailure,
	StatusIngredientManifestMismatch: SeverityFailure,
	StatusGeneralError:               SeverityFailure,

	StatusRevocationUnknown: SeverityInformational,
	StatusTimeStampMissing:  SeverityInformational,
	StatusUnsupported:       SeverityInformational,
}

// Severity returns the StatusCode's severity. Unknown codes are informational.
func (c StatusCode) Severity() Severity {
	return statusSeverity[c]
}
