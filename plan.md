# Plan for Implementing OCI Distribution Specification in Go

## 1. Goal

Implement the Open Container Initiative (OCI) Distribution Specification (as defined in `spec.md`) in Go. The implementation should be designed as a library that can be imported and used by container registry applications. The primary goal is to pass the official OCI distribution-spec conformance tests.

## 2. Phases

### Phase 1: Foundation & Project Setup

*   **Objective:** Establish the project structure, core data types, and basic API endpoint.
*   **Tasks:**
    *   Initialize Go module: `go mod init github.com/your-org/marina-distribution` (or similar).
    *   Define project structure (e.g., `pkg/distribution`, `internal/storage`, `internal/registry`, `cmd/conformance-runner` [optional]).
    *   Implement Go structs for core OCI concepts based on `spec.md` and referenced OCI Image Spec documents:
        *   `Manifest` (covering Image Manifest, Image Index)
        *   `Descriptor`
        *   `Blob` (interface/representation)
        *   `Tag`
        *   `ErrorResponse` (matching the spec's JSON error format)
        *   `Digest` type with validation.
    *   Implement the base `/v2/` endpoint (`GET /v2/`) handler to confirm spec support (`200 OK`).
    *   Choose and set up an HTTP router/framework (e.g., `net/http`, `chi`, `gorilla/mux`).
    *   Set up basic logging.

### Phase 2: Storage Backend

*   **Objective:** Define and implement an abstraction for storing and retrieving registry data (blobs, manifests).
*   **Tasks:**
    *   Define a `StorageDriver` interface abstracting blob and manifest operations (e.g., `Stat`, `GetContent`, `PutContent`, `Move`, `Delete`, `Walk`).
    *   Implement an initial storage driver (e.g., `filesystem` driver).
    *   Consider interfaces for metadata storage (tags, manifest references).

### Phase 3: Pull Workflow Implementation

*   **Objective:** Implement all API endpoints required for pulling content.
*   **Tasks:**
    *   Implement `GET /v2/<name>/manifests/<reference>`:
        *   Handle retrieval by tag and digest.
        *   Implement content negotiation using `Accept` headers.
        *   Set correct `Content-Type` and `Docker-Content-Digest` headers.
        *   Validate repository name (`<name>`) and reference (`<reference>`) formats.
    *   Implement `GET /v2/<name>/blobs/<digest>`:
        *   Retrieve blob content from storage.
        *   Set correct `Content-Length` and `Docker-Content-Digest` headers.
        *   Support `Range` requests for resumable pulls.
    *   Implement `HEAD /v2/<name>/manifests/<reference>` and `HEAD /v2/<name>/blobs/<digest>`:
        *   Check existence without returning body.
        *   Return correct headers (`Content-Length`, `Docker-Content-Digest`).
    *   Implement error handling (`404 Not Found`, etc.) using the defined error codes and format.

### Phase 4: Push Workflow Implementation

*   **Objective:** Implement all API endpoints required for pushing content.
*   **Tasks:**
    *   **Blob Uploads:**
        *   Implement monolithic POST-then-PUT upload:
            *   `POST /v2/<name>/blobs/uploads/` (initiate, return `Location` with upload UUID).
            *   `PUT /v2/<name>/blobs/uploads/<reference>?digest=<digest>` (upload content, validate digest and length, finalize).
        *   Implement single POST monolithic upload (optional but recommended):
            *   `POST /v2/<name>/blobs/uploads/?digest=<digest>` (upload content directly, validate).
        *   Implement chunked upload:
            *   `POST /v2/<name>/blobs/uploads/` (initiate with `Content-Length: 0`, handle `OCI-Chunk-Min-Length`).
            *   `PATCH /v2/<name>/blobs/uploads/<reference>` (upload chunks, handle `Content-Range`, `Content-Length`, return `Range` header).
            *   `PUT /v2/<name>/blobs/uploads/<reference>?digest=<digest>` (finalize, potentially with last chunk).
            *   `GET /v2/<name>/blobs/uploads/<reference>` (get upload status).
        *   Implement blob mounting:
            *   `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<other_name>` (link blob from another repository).
    *   **Manifest Push:**
        *   Implement `PUT /v2/<name>/manifests/<reference>`:
            *   Handle push by tag and digest.
            *   Validate `Content-Type` against manifest `mediaType`.
            *   Verify referenced blobs exist (`MANIFEST_BLOB_UNKNOWN` error).
            *   Store manifest byte-for-byte.
            *   Handle `subject` field and `OCI-Subject` header for Referrers API support.
            *   Implement fallback logic for updating Referrers Tag Schema if Referrers API is not supported/enabled.
            *   Enforce manifest size limits (`413 Payload Too Large`).
    *   Implement validation for digests, content lengths, repository names, tags.
    *   Implement relevant error codes (`BLOB_UPLOAD_INVALID`, `DIGEST_INVALID`, `SIZE_INVALID`, etc.).

### Phase 5: Content Discovery & Management Implementation

*   **Objective:** Implement APIs for listing tags, referrers, and deleting content.
*   **Tasks:**
    *   Implement `GET /v2/<name>/tags/list`:
        *   Return tags in lexical order.
        *   Support pagination using `n` and `last` query parameters.
        *   Implement `Link` header pagination (RFC5988 `rel="next"`).
    *   Implement Referrers API (`GET /v2/<name>/referrers/<digest>`):
        *   Return Image Index (`application/vnd.oci.image.index.v1+json`).
        *   Populate descriptors with `artifactType` and annotations from referred manifests.
        *   Support filtering by `artifactType` (`?artifactType=...`) and `OCI-Filters-Applied` header.
        *   Handle pagination using `Link` header.
        *   Implement upgrade path: Include manifests from existing Referrers Tags when enabling the API.
    *   Implement Content Deletion (configurable enable/disable):
        *   `DELETE /v2/<name>/manifests/<reference>` (delete manifest by digest or tag).
        *   `DELETE /v2/<name>/blobs/<digest>` (delete blob).
        *   Handle `202 Accepted`, `404 Not Found`, `405 Method Not Allowed`.
        *   Implement client-side fallback logic for updating Referrers Tag Schema when deleting manifests with `subject` if Referrers API is not supported.
    *   Implement relevant error codes.

### Phase 6: Validation, Concurrency, and Refinement

*   **Objective:** Enhance robustness, handle concurrent access, and add configuration.
*   **Tasks:**
    *   Implement robust input validation for all API parameters (names, digests, references, ranges).
    *   Implement concurrency controls for operations like tag updates, manifest pushes, and potentially blob uploads/deletes to prevent race conditions (e.g., using database transactions, locking). Pay special attention to Referrers Tag Schema updates if fallback is used.
    *   Implement registry configuration (e.g., storage backend settings, enable/disable deletion, logging levels).
    *   Implement handling for `Warning` headers (RFC 7234).
    *   Refine error handling and reporting.

### Phase 7: Testing

*   **Objective:** Ensure correctness and conformance to the specification.
*   **Tasks:**
    *   Write comprehensive unit tests for handlers, storage logic, validation functions, and core data structures.
    *   Write integration tests simulating client workflows (push, pull, list, delete).
    *   Set up and run the official OCI distribution-spec conformance test suite (`github.com/opencontainers/distribution-spec/conformance`).
    *   Iteratively fix bugs and implementation gaps identified by conformance tests.

### Phase 8: Documentation & Packaging

*   **Objective:** Prepare the library for consumption.
*   **Tasks:**
    *   Add Go documentation comments (`godoc`) to exported types and functions.
    *   Write a `README.md` explaining how to use the library.
    *   Provide examples of how to integrate the library into a registry application.
    *   Ensure the library is easily importable and usable.

## 3. Considerations

*   **Authentication/Authorization:** The spec defers this. Initially, implementation can omit auth, but the design should allow plugging in auth middleware later.
*   **Storage Driver Extensibility:** Design the storage interface to allow for different backends (S3, GCS, etc.) in the future.
*   **Performance:** Profile and optimize critical paths, especially blob transfers and manifest handling.
*   **Garbage Collection:** Deleting manifests/blobs might require a separate garbage collection process to reclaim storage space for unreferenced blobs, which is outside the scope of the core API spec but important for a real registry.
*   **Referrers API vs. Tag Schema:** Prioritize implementing the Referrers API (`/v2/<name>/referrers/<digest>`) but ensure the client-side fallback logic for the tag schema (`sha256-<digest-prefix>`) is implemented for pushes/deletes when the API is unavailable, as required by the spec for backwards compatibility.
