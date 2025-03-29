package registry

import (
	"context" // Add context import
	"encoding/json"
	"errors"
	"fmt"

	// "fmt" // No longer needed after error handling changes
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/HammerMeetNail/marina-distribution/internal/storage"
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
)

// BaseV2Handler handles requests to the /v2/ endpoint.
// This remains a standalone function as it doesn't need registry state yet.
func BaseV2Handler(w http.ResponseWriter, r *http.Request) {
	// Note: Go 1.22+ ServeMux handles method matching, so this check is less critical
	// if the route is registered with "GET /v2/". Keeping it for robustness.
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		log.Printf("Received non-GET request for /v2/: %s", r.Method)
		return
	}

	// According to the spec, this header is optional and clients SHOULD NOT depend on it.
	// However, it's common practice to include it.
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("")) // Empty body is fine
	log.Println("Handled GET /v2/ request successfully.")
}

// --- Blob Handlers ---

// GetBlobHandler handles GET requests for blobs.
// Pattern: GET /v2/{name}/blobs/{digest}
func (reg *Registry) GetBlobHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	digestStr := r.PathValue("digest")

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	dgst := distribution.Digest(digestStr)
	if err := dgst.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeDigestInvalid, "Invalid digest format", http.StatusBadRequest, err)
		return
	}

	// Retrieve blob info first to get size
	fileInfo, err := reg.driver.Stat(r.Context(), dgst)
	if err != nil {
		if errors.As(err, &storage.PathNotFoundError{}) { // Use errors.As for interface check
			reg.sendError(w, r, distribution.ErrorCodeBlobUnknown, "Blob unknown", http.StatusNotFound, err)
		} else {
			reg.log.Printf("Error stating blob %s in %s: %v", dgst, repoName, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to access blob", http.StatusInternalServerError, err)
		}
		return
	}

	// Retrieve blob content
	reader, err := reg.driver.GetContent(r.Context(), dgst)
	if err != nil {
		// Stat succeeded but GetContent failed - unusual, likely internal error
		reg.log.Printf("Error getting content for blob %s in %s after stat succeeded: %v", dgst, repoName, err)
		reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to retrieve blob content", http.StatusInternalServerError, err)
		return
	}
	defer reader.Close()

	// Set headers
	// Note: OCI spec doesn't mandate Content-Type for blobs, but application/octet-stream is standard.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size, 10))
	w.Header().Set("Docker-Content-Digest", dgst.String()) // OCI spec uses this header name
	w.Header().Set("ETag", dgst.String())                  // ETag is useful for caching

	// TODO: Handle Range requests (RFC 9110) using http.ServeContent or similar

	w.WriteHeader(http.StatusOK)

	// Copy content to response
	_, copyErr := io.Copy(w, reader)
	if copyErr != nil {
		// Hard to send an error response now as headers/status are sent. Log it.
		reg.log.Printf("Error copying blob %s content to response: %v", dgst, copyErr)
	}
	reg.log.Printf("Handled GET blob request for %s/%s", repoName, dgst)
}

// HeadBlobHandler handles HEAD requests for blobs.
// Pattern: HEAD /v2/{name}/blobs/{digest}
func (reg *Registry) HeadBlobHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	digestStr := r.PathValue("digest")

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		// Don't send error body for HEAD, just status code
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dgst := distribution.Digest(digestStr)
	if err := dgst.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Stat the blob
	fileInfo, err := reg.driver.Stat(r.Context(), dgst)
	if err != nil {
		if errors.As(err, &storage.PathNotFoundError{}) { // Use errors.As
			w.WriteHeader(http.StatusNotFound)
		} else {
			reg.log.Printf("Error stating blob %s in %s for HEAD request: %v", dgst, repoName, err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// Set headers (same as GET, but no body)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size, 10))
	w.Header().Set("Docker-Content-Digest", dgst.String())
	w.Header().Set("ETag", dgst.String())
	w.WriteHeader(http.StatusOK) // Success
	reg.log.Printf("Handled HEAD blob request for %s/%s", repoName, dgst)
}

// --- Manifest Handlers ---

// resolveReferenceToDigest attempts to resolve a reference (tag or digest) to a manifest digest.
func (reg *Registry) resolveReferenceToDigest(ctx context.Context, repoName distribution.RepositoryName, reference distribution.Reference) (distribution.Digest, error) {
	if reference.IsDigest() {
		// Already a digest, validate it
		dgst := distribution.Digest(reference)
		if err := dgst.Validate(); err != nil {
			return "", fmt.Errorf("%w: %w", distribution.ErrorCodeDigestInvalid, err)
		}
		return dgst, nil
	} else if reference.IsTag() {
		// It's a tag, resolve it using the storage driver
		dgst, err := reg.driver.ResolveTag(ctx, repoName, reference.String())
		if err != nil {
			if errors.As(err, &storage.TagNotFoundError{}) {
				return "", fmt.Errorf("%w: %w", distribution.ErrorCodeManifestUnknown, err) // Map storage error to API error
			}
			// Other storage error
			return "", fmt.Errorf("%w: failed to resolve tag: %w", distribution.ErrorCodeUnknown, err)
		}
		// Ensure the resolved digest is valid
		if err := dgst.Validate(); err != nil {
			// This indicates an internal issue if the driver stored an invalid digest for a tag
			reg.log.Printf("Error: storage driver resolved tag %s/%s to invalid digest %s: %v", repoName, reference, dgst, err)
			return "", fmt.Errorf("%w: invalid digest resolved from tag", distribution.ErrorCodeUnknown)
		}
		return dgst, nil
	} else {
		// Invalid reference format
		return "", fmt.Errorf("%w: invalid reference format", distribution.ErrorCodeManifestInvalid)
	}
}

// GetManifestHandler handles GET requests for manifests.
// Pattern: GET /v2/{name}/manifests/{reference}
func (reg *Registry) GetManifestHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	referenceStr := r.PathValue("reference")

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	reference := distribution.Reference(referenceStr)
	// Basic validation of reference format (tag or digest)
	if err := reference.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeManifestInvalid, "Invalid reference format", http.StatusBadRequest, err)
		return
	}

	// Resolve the reference (tag or digest) to a digest
	dgst, err := reg.resolveReferenceToDigest(r.Context(), repoName, reference)
	if err != nil {
		// Handle errors from resolveReferenceToDigest, mapping them to appropriate API responses
		var apiErr distribution.ErrorCode
		httpStatus := http.StatusInternalServerError
		message := "Failed to resolve manifest reference"
		// Check against sentinel errors
		if errors.Is(err, distribution.ErrDigestInvalid) || errors.Is(err, distribution.ErrManifestInvalid) {
			apiErr = distribution.ErrorCodeManifestInvalid // Use the corresponding ErrorCode for the response
			httpStatus = http.StatusBadRequest
			message = "Invalid manifest reference format"
		} else if errors.Is(err, distribution.ErrManifestUnknown) {
			apiErr = distribution.ErrorCodeManifestUnknown // Use the corresponding ErrorCode for the response
			httpStatus = http.StatusNotFound
			message = "Manifest unknown"
		} else {
			// Assume internal error for others
			apiErr = distribution.ErrorCodeUnknown
			reg.log.Printf("Internal error resolving reference %s/%s: %v", repoName, reference, err)
		}
		reg.sendError(w, r, apiErr, message, httpStatus, err)
		return
	}

	// Stat the manifest to get size and check existence by digest
	// Note: Even if resolved from tag, we stat by digest for consistency.
	fileInfo, err := reg.driver.StatManifest(r.Context(), dgst)
	if err != nil {
		if errors.As(err, &storage.PathNotFoundError{}) {
			reg.sendError(w, r, distribution.ErrorCodeManifestUnknown, "Manifest unknown", http.StatusNotFound, err)
		} else {
			reg.log.Printf("Error stating manifest %s in %s: %v", dgst, repoName, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to access manifest", http.StatusInternalServerError, err)
		}
		return
	}

	// Retrieve manifest content
	reader, err := reg.driver.GetManifest(r.Context(), dgst)
	if err != nil {
		reg.log.Printf("Error getting content for manifest %s in %s after stat succeeded: %v", dgst, repoName, err)
		reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to retrieve manifest content", http.StatusInternalServerError, err)
		return
	}
	defer reader.Close()

	// TODO: Content Negotiation based on Accept header.
	// For now, assume the stored manifest media type is acceptable.
	// Need to read the manifest content to determine its mediaType if not stored separately.
	// This might require buffering or reading ahead.
	// Let's assume a default for now and refine later.
	manifestMediaType := "application/vnd.oci.image.manifest.v1+json" // Placeholder

	// Set headers
	w.Header().Set("Content-Type", manifestMediaType) // Use negotiated or stored media type
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size, 10))
	w.Header().Set("Docker-Content-Digest", dgst.String())
	w.Header().Set("ETag", dgst.String())

	w.WriteHeader(http.StatusOK)

	// Copy content to response
	_, copyErr := io.Copy(w, reader)
	if copyErr != nil {
		reg.log.Printf("Error copying manifest %s content to response: %v", dgst, copyErr)
	}
	reg.log.Printf("Handled GET manifest request for %s/%s (resolved to %s)", repoName, reference, dgst)
}

// HeadManifestHandler handles HEAD requests for manifests.
// Pattern: HEAD /v2/{name}/manifests/{reference}
func (reg *Registry) HeadManifestHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	referenceStr := r.PathValue("reference")

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reference := distribution.Reference(referenceStr)
	if err := reference.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Resolve the reference to a digest
	dgst, err := reg.resolveReferenceToDigest(r.Context(), repoName, reference)
	if err != nil {
		// Determine status code based on error type using sentinel errors
		httpStatus := http.StatusInternalServerError
		if errors.Is(err, distribution.ErrDigestInvalid) || errors.Is(err, distribution.ErrManifestInvalid) {
			httpStatus = http.StatusBadRequest
		} else if errors.Is(err, distribution.ErrManifestUnknown) {
			httpStatus = http.StatusNotFound
		} else {
			reg.log.Printf("Internal error resolving reference %s/%s for HEAD: %v", repoName, reference, err)
		}
		w.WriteHeader(httpStatus)
		return
	}

	// Stat the manifest by digest
	fileInfo, err := reg.driver.StatManifest(r.Context(), dgst)
	if err != nil {
		if errors.As(err, &storage.PathNotFoundError{}) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			reg.log.Printf("Error stating manifest %s in %s for HEAD request: %v", dgst, repoName, err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// TODO: Determine actual media type for Content-Type header, similar to GET.
	manifestMediaType := "application/vnd.oci.image.manifest.v1+json" // Placeholder

	// Set headers (same as GET, but no body)
	w.Header().Set("Content-Type", manifestMediaType)
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size, 10))
	w.Header().Set("Docker-Content-Digest", dgst.String())
	w.Header().Set("ETag", dgst.String())
	w.WriteHeader(http.StatusOK) // Success
	reg.log.Printf("Handled HEAD manifest request for %s/%s (resolved to %s)", repoName, reference, dgst)
}

// sendError is a helper to format and send API errors according to the spec.
func (reg *Registry) sendError(w http.ResponseWriter, r *http.Request, code distribution.ErrorCode, message string, httpStatus int, detail error) {
	errResp := distribution.NewErrorResponse(distribution.Error{
		Code:    code.String(), // Convert ErrorCode to string
		Message: message,
		// Optionally include detail if needed and safe to expose
		// Detail: json.RawMessage(`{"details": "` + detail.Error() + `"}`),
	})

	// Ensure Content-Type is set before writing header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus) // WriteHeader must be called before writing the body

	// Encode and write the error body
	if encodeErr := json.NewEncoder(w).Encode(errResp); encodeErr != nil {
		// If encoding fails, log it, but we can't change the response anymore.
		reg.log.Printf("Failed to encode error response body: %v (original error: %v)", encodeErr, detail)
	}

	// Log the error details server-side
	if detail != nil {
		reg.log.Printf("API Error: status=%d code=%s message=%q detail=%q request=%s %s", httpStatus, code, message, detail.Error(), r.Method, r.URL.Path)
	} else {
		reg.log.Printf("API Error: status=%d code=%s message=%q request=%s %s", httpStatus, code, message, r.Method, r.URL.Path)
	}
}
