package distribution

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Descriptor describes targeted content.
// Based on OCI Image Spec: https://github.com/opencontainers/image-spec/blob/main/descriptor.md
type Descriptor struct {
	MediaType   string            `json:"mediaType,omitempty"`
	Size        int64             `json:"size"`
	Digest      Digest            `json:"digest"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	// Platform specifies the target platform for the content. (OCI Image Spec specific)
	// Platform *Platform `json:"platform,omitempty"` // Example, define Platform struct if needed
}

// Manifest provides a general structure for OCI manifests.
// Specific manifest types (Image Manifest, Index) will embed or reference this.
// Based on OCI Image Spec: https://github.com/opencontainers/image-spec/blob/main/manifest.md
// and OCI Image Index: https://github.com/opencontainers/image-spec/blob/main/image-index.md
type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType,omitempty"` // Should be present in image manifests/indexes

	// For Image Manifest (application/vnd.oci.image.manifest.v1+json)
	Config *Descriptor  `json:"config,omitempty"`
	Layers []Descriptor `json:"layers,omitempty"`

	// For Image Index (application/vnd.oci.image.index.v1+json)
	Manifests []Descriptor `json:"manifests,omitempty"`

	// For Artifact Manifest (application/vnd.oci.artifact.manifest.v1+json) - experimental
	// Blobs []Descriptor `json:"blobs,omitempty"`

	// Common fields
	Subject     *Descriptor       `json:"subject,omitempty"` // Added in dist-spec v1.1
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Error represents a single error structure returned by the API.
type Error struct {
	Code    string          `json:"code"` // Must be uppercase alphabetic characters and underscores
	Message string          `json:"message,omitempty"`
	Detail  json.RawMessage `json:"detail,omitempty"` // Unstructured JSON data
}

// ErrorResponse represents the overall error response body.
type ErrorResponse struct {
	Errors []Error `json:"errors"`
}

// NewErrorResponse creates a new ErrorResponse.
func NewErrorResponse(errors ...Error) ErrorResponse {
	return ErrorResponse{Errors: errors}
}

// --- Placeholders for other types ---

// Blob represents stored content addressable by digest.
// This might be an interface implemented by storage drivers.
type Blob interface {
	// ReadSeeker? Closer?
	Descriptor() Descriptor
}

// Tag represents a human-readable pointer to a manifest.
type Tag struct {
	Name   string
	Digest Digest
}

// RepositoryName represents the name of a repository.
// Validation according to spec: [a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*
type RepositoryName string

var repositoryNameRegex = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*$`)

// Validate checks if the repository name is valid.
func (n RepositoryName) Validate() error {
	if !repositoryNameRegex.MatchString(string(n)) {
		return fmt.Errorf("invalid repository name format: %s", n)
	}
	// Consider length limits (e.g., 255 chars total including hostname) if needed for compatibility.
	return nil
}

// String returns the string representation.
func (n RepositoryName) String() string {
	return string(n)
}

// Reference can be a Tag or a Digest.
// Tag validation: [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}
type Reference string

var tagRegex = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// IsTag checks if the reference is a valid tag format.
func (r Reference) IsTag() bool {
	return tagRegex.MatchString(string(r))
}

// IsDigest checks if the reference is a valid digest format.
func (r Reference) IsDigest() bool {
	return Digest(r).Validate() == nil
}

// Validate checks if the reference is either a valid tag or a valid digest.
func (r Reference) Validate() error {
	if r.IsTag() || r.IsDigest() {
		return nil
	}
	return fmt.Errorf("invalid reference format: %s", r)
}

// String returns the string representation.
func (r Reference) String() string {
	return string(r)
}
