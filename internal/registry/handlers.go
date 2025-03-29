package registry

import (
	"bytes"   // Add bytes import
	"context" // Add context import
	"encoding/json"
	"errors"
	"fmt"
	"strings" // Add strings import

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

// PutManifestHandler handles manifest uploads.
// Pattern: PUT /v2/{name}/manifests/{reference}
func (reg *Registry) PutManifestHandler(w http.ResponseWriter, r *http.Request) {
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

	// Read the manifest body
	manifestBytes, err := io.ReadAll(r.Body)
	if err != nil {
		reg.log.Printf("Error reading manifest body for %s/%s: %v", repoName, reference, err)
		reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to read manifest body", http.StatusInternalServerError, err)
		return
	}
	_ = int64(len(manifestBytes)) // Assign to blank identifier to silence unused error for now

	// TODO: Enforce manifest size limit (e.g., 4MB) - return 413 Payload Too Large
	// if contentLength > 4*1024*1024 { ... }

	// Validate Content-Type header
	contentType := r.Header.Get("Content-Type")
	// TODO: More robust media type parsing/validation might be needed.
	// The spec says clients MUST set Content-Type to the manifest's mediaType if present.
	// We should ideally parse the manifest here to verify this, but that adds complexity.
	// For now, we'll just check if it's provided.
	if contentType == "" {
		reg.sendError(w, r, distribution.ErrorCodeManifestInvalid, "Missing Content-Type header", http.StatusBadRequest, nil)
		return
	}

	// Calculate the digest of the received manifest body.
	// We need a default algorithm if the reference is a tag. SHA256 is standard.
	// If the reference *is* a digest, we should use its algorithm.
	var expectedDigest distribution.Digest
	var algo = distribution.SHA256 // Default algorithm
	isDigestReference := reference.IsDigest()

	if isDigestReference {
		expectedDigest = distribution.Digest(reference)
		algo = expectedDigest.Algorithm() // Use algorithm from the reference digest
		if !algo.Available() {
			reg.sendError(w, r, distribution.ErrorCodeDigestInvalid, "Unsupported digest algorithm in reference", http.StatusBadRequest, fmt.Errorf("unsupported algorithm: %s", algo))
			return
		}
	}

	hashFunc, err := distribution.GetHashFunc(algo)
	if err != nil {
		// Should not happen if algo.Available() passed or default was used
		reg.log.Printf("Internal error getting hash function for %s: %v", algo, err)
		reg.sendError(w, r, distribution.ErrorCodeUnknown, "Internal server error", http.StatusInternalServerError, err)
		return
	}
	hasher := hashFunc.New()
	hasher.Write(manifestBytes) // Hash the manifest content
	calculatedDigest := distribution.NewDigest(algo, hasher)

	// If the reference was a digest, verify it matches the calculated digest
	if isDigestReference && expectedDigest != calculatedDigest {
		err := fmt.Errorf("provided digest %s does not match calculated content digest %s", expectedDigest, calculatedDigest)
		reg.sendError(w, r, distribution.ErrorCodeDigestInvalid, err.Error(), http.StatusBadRequest, err)
		return
	}

	// TODO: Validate manifest content itself (JSON structure, required fields, referenced blob existence)
	// This requires unmarshalling the manifestBytes and checking against OCI Image Spec.
	// If validation fails, return MANIFEST_INVALID or MANIFEST_BLOB_UNKNOWN.

	// Store the manifest using the calculated digest
	_, err = reg.driver.PutManifest(r.Context(), calculatedDigest, bytes.NewReader(manifestBytes)) // Use bytes.NewReader
	if err != nil {
		// Handle potential DigestMismatchError from storage (shouldn't happen here ideally)
		if errors.As(err, &storage.DigestMismatchError{}) {
			reg.log.Printf("Internal Error: Digest mismatch during PutManifest for %s: %v", calculatedDigest, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Internal storage error during manifest put", http.StatusInternalServerError, err)
		} else {
			reg.log.Printf("Error putting manifest %s for %s/%s: %v", calculatedDigest, repoName, reference, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to store manifest", http.StatusInternalServerError, err)
		}
		return
	}

	// If the reference was a tag, associate the tag with the calculated digest
	if reference.IsTag() {
		tagName := reference.String()
		err = reg.driver.TagManifest(r.Context(), repoName, tagName, calculatedDigest)
		if err != nil {
			// Log the error, but the manifest PUT itself was successful.
			// What's the correct response? The spec isn't explicit.
			// Let's still return 201 Created but log the tagging error.
			reg.log.Printf("Error tagging manifest %s with tag %s for %s: %v", calculatedDigest, tagName, repoName, err)
			// Consider if a different response/error is more appropriate.
		}
	}

	// TODO: Handle 'subject' field and OCI-Subject header for Referrers API support.

	// Success!
	manifestLocation := fmt.Sprintf("/v2/%s/manifests/%s", repoName, calculatedDigest)
	w.Header().Set("Location", manifestLocation)
	w.Header().Set("Docker-Content-Digest", calculatedDigest.String())
	w.WriteHeader(http.StatusCreated) // 201 Created

	reg.log.Printf("Stored manifest for %s/%s with digest %s", repoName, reference, calculatedDigest)
}

// --- Upload Handlers ---

// StartBlobUploadHandler initiates a new blob upload.
// Pattern: POST /v2/{name}/blobs/uploads/
func (reg *Registry) StartBlobUploadHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	// TODO: Handle monolithic blob push via single POST request (?digest=<digest>)
	// TODO: Handle cross-repository blob mount (?mount=<digest>&from=<other_name>)

	// Initiate upload session with the storage driver
	uploadID, err := reg.driver.StartUpload(r.Context(), repoName)
	if err != nil {
		reg.log.Printf("Error starting blob upload for %s: %v", repoName, err)
		reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to start blob upload", http.StatusInternalServerError, err)
		return
	}

	// Construct the upload URL. It should be relative to the registry base.
	// The spec allows absolute or relative URLs. Relative is often simpler.
	// The <reference> in the PATCH/PUT URL will be this uploadID.
	uploadURL := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repoName, uploadID)

	w.Header().Set("Location", uploadURL)
	w.Header().Set("Range", "0-0") // Initial range for chunked upload
	// OCI-Chunk-Min-Length header could be set here if the driver provides it.
	w.WriteHeader(http.StatusAccepted) // 202 Accepted

	reg.log.Printf("Started blob upload for %s, upload ID: %s, location: %s", repoName, uploadID, uploadURL)
}

// PatchBlobUploadHandler handles chunked blob uploads.
// Pattern: PATCH /v2/{name}/blobs/uploads/{uuid}
func (reg *Registry) PatchBlobUploadHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	uploadID := r.PathValue("uuid") // Assuming the path param is named 'uuid'

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/octet-stream" {
		reg.sendError(w, r, distribution.ErrorCodeBlobUploadInvalid, "Invalid Content-Type, expected application/octet-stream", http.StatusBadRequest, nil)
		return
	}

	// Parse Content-Range header (e.g., "0-999")
	contentRange := r.Header.Get("Content-Range")
	var startOffset, endOffset int64
	if contentRange != "" {
		// Note: The spec says range MUST be inclusive, e.g., 0-999 for 1000 bytes.
		// fmt.Sscanf is simple but might be too lenient. A regex might be better.
		_, err := fmt.Sscanf(contentRange, "%d-%d", &startOffset, &endOffset)
		if err != nil || startOffset < 0 || endOffset < startOffset {
			reg.sendError(w, r, distribution.ErrorCodeBlobUploadInvalid, "Invalid Content-Range header format", http.StatusRequestedRangeNotSatisfiable, err)
			return
		}
	} else {
		// Content-Range is required for PATCH according to spec? Let's assume yes for now.
		// If not provided, maybe try to infer from Content-Length if offset is 0? Risky.
		reg.sendError(w, r, distribution.ErrorCodeBlobUploadInvalid, "Missing Content-Range header", http.StatusBadRequest, nil)
		return
	}

	// Validate Content-Length (size of the chunk being sent)
	contentLengthStr := r.Header.Get("Content-Length")
	chunkSize, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil || chunkSize < 0 {
		reg.sendError(w, r, distribution.ErrorCodeSizeInvalid, "Invalid or missing Content-Length header", http.StatusBadRequest, err)
		return
	}

	// Check if chunk size matches the range
	expectedChunkSize := endOffset - startOffset + 1
	if chunkSize != expectedChunkSize {
		reg.sendError(w, r, distribution.ErrorCodeSizeInvalid, "Content-Length does not match Content-Range", http.StatusBadRequest, fmt.Errorf("range %d-%d implies size %d, but Content-Length is %d", startOffset, endOffset, expectedChunkSize, chunkSize))
		return
	}

	// Call storage driver to put the chunk
	bytesWritten, err := reg.driver.PutUploadChunk(r.Context(), uploadID, startOffset, r.Body)
	// Note: r.Body is automatically closed by the http server

	if err != nil {
		if errors.As(err, &storage.UploadNotFoundError{}) {
			reg.sendError(w, r, distribution.ErrorCodeBlobUploadUnknown, "Upload session not found", http.StatusNotFound, err)
		} else if errors.As(err, &storage.InvalidOffsetError{}) {
			// If offset is wrong, return 416 Range Not Satisfiable
			// Get current progress to inform client
			currentOffset, progressErr := reg.driver.GetUploadProgress(r.Context(), uploadID)
			if progressErr != nil {
				reg.log.Printf("Error getting upload progress for %s after invalid offset: %v", uploadID, progressErr)
				// Fallback to generic error if we can't get progress
				reg.sendError(w, r, distribution.ErrorCodeBlobUploadInvalid, "Invalid upload offset", http.StatusRequestedRangeNotSatisfiable, err)
			} else {
				uploadURL := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repoName, uploadID)
				w.Header().Set("Location", uploadURL)
				w.Header().Set("Range", fmt.Sprintf("0-%d", currentOffset-1)) // Range is inclusive
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)        // 416
				reg.log.Printf("Invalid offset for upload %s. Expected %d, got %d.", uploadID, currentOffset, startOffset)
			}
		} else {
			reg.log.Printf("Error putting upload chunk for %s: %v", uploadID, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to write upload chunk", http.StatusInternalServerError, err)
		}
		return
	}

	// Success
	newEndOffset := startOffset + bytesWritten - 1 // Calculate the actual end offset based on bytes written
	uploadURL := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repoName, uploadID)
	w.Header().Set("Location", uploadURL)
	w.Header().Set("Range", fmt.Sprintf("0-%d", newEndOffset)) // Range is inclusive, 0-based
	w.WriteHeader(http.StatusAccepted)                         // 202 Accepted

	reg.log.Printf("Handled PATCH blob upload chunk for %s/%s, range %d-%d, bytes written: %d", repoName, uploadID, startOffset, endOffset, bytesWritten)
}

// PutBlobUploadHandler finalizes a blob upload (chunked or monolithic POST/PUT).
// Pattern: PUT /v2/{name}/blobs/uploads/{uuid}?digest={digest}
func (reg *Registry) PutBlobUploadHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	uploadID := r.PathValue("uuid")
	digestStr := r.URL.Query().Get("digest")

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	// Validate the final digest provided in the query parameter
	finalDigest := distribution.Digest(digestStr)
	if err := finalDigest.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeDigestInvalid, "Invalid digest query parameter", http.StatusBadRequest, err)
		return
	}

	// Note: The spec allows the final chunk to be sent with this PUT request.
	// The current filesystem driver's FinishUpload expects the data file to be complete.
	// Handling an optional body here adds complexity (need to append chunk then finish).
	// For now, assume the final chunk was sent via PATCH or it was a monolithic POST/PUT.
	// If r.ContentLength > 0, we might need to handle that final chunk here.
	if r.ContentLength > 0 {
		// TODO: Handle final chunk upload if necessary. This might involve:
		// 1. Getting current upload progress.
		// 2. Parsing Content-Range if present (optional for final PUT chunk?).
		// 3. Calling PutUploadChunk with r.Body.
		// 4. Proceeding to FinishUpload only if PutUploadChunk succeeds.
		reg.sendError(w, r, distribution.ErrorCodeUnsupported, "Uploading final chunk via PUT is not yet supported", http.StatusNotImplemented, nil)
		reg.log.Printf("Received PUT request with body for upload %s - final chunk via PUT not implemented", uploadID)
		return
	}

	// Call storage driver to finalize the upload
	err := reg.driver.FinishUpload(r.Context(), uploadID, finalDigest)
	if err != nil {
		if errors.As(err, &storage.UploadNotFoundError{}) {
			reg.sendError(w, r, distribution.ErrorCodeBlobUploadUnknown, "Upload session not found", http.StatusNotFound, err)
		} else if errors.As(err, &storage.DigestMismatchError{}) {
			reg.sendError(w, r, distribution.ErrorCodeDigestInvalid, "Provided digest did not match uploaded content", http.StatusBadRequest, err)
		} else {
			reg.log.Printf("Error finishing upload %s with digest %s: %v", uploadID, finalDigest, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to finalize blob upload", http.StatusInternalServerError, err)
		}
		return
	}

	// Success! Respond with 201 Created and the location of the blob.
	blobLocation := fmt.Sprintf("/v2/%s/blobs/%s", repoName, finalDigest)
	w.Header().Set("Location", blobLocation)
	w.Header().Set("Docker-Content-Digest", finalDigest.String())
	w.WriteHeader(http.StatusCreated) // 201 Created

	reg.log.Printf("Finished blob upload for %s/%s, final digest: %s", repoName, uploadID, finalDigest)
}

// --- Tag Handlers ---

// GetTagsHandler lists tags for a repository.
// Pattern: GET /v2/{name}/tags/list
func (reg *Registry) GetTagsHandler(w http.ResponseWriter, r *http.Request) {
	repoNameStr := r.PathValue("name")
	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	// Get tags from storage driver
	allTags, err := reg.driver.GetTags(r.Context(), repoName)
	if err != nil {
		// Assuming driver returns empty list if repo not found, check for other errors
		reg.log.Printf("Error getting tags for %s: %v", repoName, err)
		reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to retrieve tags", http.StatusInternalServerError, err)
		return
	}

	// Handle pagination
	q := r.URL.Query()
	last := q.Get("last")
	nStr := q.Get("n")
	limit := 0 // 0 means no limit initially

	if nStr != "" {
		n, err := strconv.Atoi(nStr)
		if err != nil || n < 0 {
			reg.sendError(w, r, distribution.ErrorCodePaginationInvalid, "Invalid 'n' parameter for pagination", http.StatusBadRequest, err)
			return
		}
		limit = n
	}

	// Filter tags based on 'last'
	startIndex := 0
	if last != "" {
		// Find the index *after* the 'last' tag (lexical comparison)
		found := false
		for i, tag := range allTags {
			if strings.ToLower(tag) > strings.ToLower(last) {
				startIndex = i
				found = true
				break
			}
		}
		if !found {
			// 'last' was the actual last tag or beyond, return empty list
			startIndex = len(allTags)
		}
	}

	// Apply limit 'n'
	endIndex := len(allTags)
	if limit > 0 && startIndex+limit < endIndex {
		endIndex = startIndex + limit
	}

	tagsResult := allTags[startIndex:endIndex]

	// Prepare response body
	respBody := struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{
		Name: repoNameStr,
		Tags: tagsResult,
	}

	// Set Link header for pagination if needed (RFC 5988)
	if limit > 0 && endIndex < len(allTags) {
		nextLast := tagsResult[len(tagsResult)-1] // The last tag in the current result set
		linkURL := fmt.Sprintf("/v2/%s/tags/list?n=%d&last=%s", repoName, limit, nextLast)
		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", linkURL))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		reg.log.Printf("Failed to encode tags response: %v", err)
	}
	reg.log.Printf("Handled GET tags request for %s (n=%s, last=%s), returned %d tags", repoName, nStr, last, len(tagsResult))
}

// TODO: Implement Referrers API handler (GET /v2/{name}/referrers/{digest})

// --- Delete Handlers ---

// DeleteManifestHandler handles deleting manifests or tags.
// Pattern: DELETE /v2/{name}/manifests/{reference}
func (reg *Registry) DeleteManifestHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Check if deletion is enabled in registry config. Return 405 if disabled.

	repoNameStr := r.PathValue("name")
	referenceStr := r.PathValue("reference")

	repoName := distribution.RepositoryName(repoNameStr)
	if err := repoName.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeNameInvalid, "Invalid repository name format", http.StatusBadRequest, err)
		return
	}

	reference := distribution.Reference(referenceStr)
	if err := reference.Validate(); err != nil {
		reg.sendError(w, r, distribution.ErrorCodeManifestInvalid, "Invalid reference format", http.StatusBadRequest, err)
		return
	}

	var err error
	if reference.IsTag() {
		// Delete the tag
		tagName := reference.String()
		err = reg.driver.UntagManifest(r.Context(), repoName, tagName)
		if err != nil {
			if errors.As(err, &storage.TagNotFoundError{}) {
				reg.sendError(w, r, distribution.ErrorCodeManifestUnknown, "Tag not found", http.StatusNotFound, err)
			} else {
				reg.log.Printf("Error untagging %s/%s: %v", repoName, tagName, err)
				reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to delete tag", http.StatusInternalServerError, err)
			}
			return
		}
		reg.log.Printf("Deleted tag %s/%s", repoName, tagName)
	} else if reference.IsDigest() {
		// Delete the manifest by digest
		dgst := distribution.Digest(reference)
		// We already validated the format, but validate again for safety/consistency
		if errVal := dgst.Validate(); errVal != nil {
			reg.sendError(w, r, distribution.ErrorCodeDigestInvalid, "Invalid digest format", http.StatusBadRequest, errVal)
			return
		}

		// TODO: Implement Referrers API fallback logic if needed (see spec).
		// If deleting a manifest with a subject field and referrers API is not supported,
		// the client *should* update the referrers tag schema. This handler might
		// need to coordinate or simply allow the delete. For now, just delete.

		err = reg.driver.DeleteManifest(r.Context(), dgst)
		if err != nil {
			if errors.As(err, &storage.PathNotFoundError{}) {
				reg.sendError(w, r, distribution.ErrorCodeManifestUnknown, "Manifest not found", http.StatusNotFound, err)
			} else {
				reg.log.Printf("Error deleting manifest %s in %s: %v", dgst, repoName, err)
				reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to delete manifest", http.StatusInternalServerError, err)
			}
			return
		}
		reg.log.Printf("Deleted manifest %s/%s", repoName, dgst)
	} else {
		// This case should be caught by reference.Validate() above, but handle defensively.
		reg.sendError(w, r, distribution.ErrorCodeManifestInvalid, "Invalid reference format", http.StatusBadRequest, nil)
		return
	}

	// Success
	w.WriteHeader(http.StatusAccepted) // 202 Accepted
}

// DeleteBlobHandler handles deleting blobs.
// Pattern: DELETE /v2/{name}/blobs/{digest}
func (reg *Registry) DeleteBlobHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Check if deletion is enabled in registry config. Return 405 if disabled.

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

	// Call storage driver to delete the blob
	err := reg.driver.Delete(r.Context(), dgst)
	if err != nil {
		if errors.As(err, &storage.PathNotFoundError{}) {
			reg.sendError(w, r, distribution.ErrorCodeBlobUnknown, "Blob not found", http.StatusNotFound, err)
		} else {
			reg.log.Printf("Error deleting blob %s in %s: %v", dgst, repoName, err)
			reg.sendError(w, r, distribution.ErrorCodeUnknown, "Failed to delete blob", http.StatusInternalServerError, err)
		}
		return
	}

	// Success
	w.WriteHeader(http.StatusAccepted) // 202 Accepted
	reg.log.Printf("Deleted blob %s/%s", repoName, dgst)
}

// sendError is a helper to format and send API errors according to the spec.
func (reg *Registry) sendError(w http.ResponseWriter, r *http.Request, code distribution.ErrorCode, message string, httpStatus int, detail error) {
	// Add new error code for pagination
	if code == "" { // Handle cases where a specific code isn't set but status indicates error
		if httpStatus == http.StatusBadRequest {
			code = distribution.ErrorCodeUnknown // Or a more specific default?
		} else {
			code = distribution.ErrorCodeUnknown
		}
	}

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
