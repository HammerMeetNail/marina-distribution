package distribution

import "errors"

// ErrorCode is a string type representing the standard OCI distribution error codes.
type ErrorCode string

// Standard OCI Distribution Error Codes
// See: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#error-codes
const (
	// Blob Errors
	ErrorCodeBlobUnknown       ErrorCode = "BLOB_UNKNOWN"        // blob unknown to registry
	ErrorCodeBlobUploadInvalid ErrorCode = "BLOB_UPLOAD_INVALID" // blob upload invalid
	ErrorCodeBlobUploadUnknown ErrorCode = "BLOB_UPLOAD_UNKNOWN" // blob upload unknown to registry
	ErrorCodeDigestInvalid     ErrorCode = "DIGEST_INVALID"      // provided digest did not match uploaded content
	ErrorCodeSizeInvalid       ErrorCode = "SIZE_INVALID"        // provided length did not match content length

	// Manifest Errors
	ErrorCodeManifestBlobUnknown ErrorCode = "MANIFEST_BLOB_UNKNOWN" // manifest references a manifest or blob unknown to registry
	ErrorCodeManifestInvalid     ErrorCode = "MANIFEST_INVALID"      // manifest invalid
	ErrorCodeManifestUnknown     ErrorCode = "MANIFEST_UNKNOWN"      // manifest unknown to registry
	// ErrorCodeManifestUnverified ErrorCode = "MANIFEST_UNVERIFIED" // Deprecated, but listed in spec

	// Repository/Name Errors
	ErrorCodeNameInvalid ErrorCode = "NAME_INVALID" // invalid repository name
	ErrorCodeNameUnknown ErrorCode = "NAME_UNKNOWN" // repository name not known to registry
	// ErrorCodeTagInvalid      ErrorCode = "TAG_INVALID"      // Deprecated, but listed in spec

	// General Errors
	ErrorCodeUnauthorized    ErrorCode = "UNAUTHORIZED"    // authentication required
	ErrorCodeDenied          ErrorCode = "DENIED"          // requested access to the resource is denied
	ErrorCodeUnsupported     ErrorCode = "UNSUPPORTED"     // the operation is unsupported
	ErrorCodeTooManyRequests ErrorCode = "TOOMANYREQUESTS" // too many requests

	// Internal/Catch-all
	ErrorCodeUnknown ErrorCode = "UNKNOWN" // unknown error
)

// String returns the string representation of the ErrorCode.
func (ec ErrorCode) String() string {
	return string(ec)
}

// Sentinel errors for specific conditions, useful for errors.Is checks.
var (
	ErrManifestUnknown = errors.New(ErrorCodeManifestUnknown.String())
	ErrManifestInvalid = errors.New(ErrorCodeManifestInvalid.String())
	ErrDigestInvalid   = errors.New(ErrorCodeDigestInvalid.String())
	ErrNameInvalid     = errors.New(ErrorCodeNameInvalid.String())
	ErrBlobUnknown     = errors.New(ErrorCodeBlobUnknown.String())
	// Add others as needed
)
