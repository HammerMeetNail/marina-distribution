# Plan for Implementing OCI Referrers API (Phase 5)

This document outlines the steps to implement the OCI Referrers API (`/v2/{name}/referrers/{digest}`) as defined in the OCI Distribution Specification v1.1.

## 1. Define API Route

*   **File:** `internal/registry/handlers.go` (or router setup location)
*   **Action:** Define a new HTTP `GET` route:
    *   `/v2/{name}/referrers/{digest}`
    *   Must handle optional query parameter: `?artifactType={type}`
*   **Handler:** Map this route to a new function, e.g., `handleGetReferrers`.

## 2. Implement Handler Function (`handleGetReferrers`)

*   **File:** `internal/registry/handlers.go`
*   **Responsibilities:**
    *   Parse `name` (repository) and `digest` (subject) from the URL path.
    *   Validate `digest` format (return `400 Bad Request` if invalid).
    *   Parse optional `artifactType` query parameter.
    *   Call core registry logic: `registry.GetReferrers(ctx, repoName, subjectDigest, artifactTypeFilter)`.
    *   Handle errors from core logic (`404 Not Found` for repo, `500 Internal Server Error` for others).
    *   On success:
        *   Set `Content-Type: application/vnd.oci.image.index.v1+json`.
        *   Set `OCI-Filters-Applied: artifactType` header if filtering was applied by core logic.
        *   Marshal the returned OCI Image Index to JSON.
        *   Respond with `200 OK` and the JSON body (even if `manifests` is empty).
*   **Note:** Initial implementation may omit pagination (`Link` header).

## 3. Implement Core Logic (`registry.GetReferrers`)

*   **File:** `internal/registry/registry.go`
*   **Method Signature:** `GetReferrers(ctx context.Context, repoName string, subjectDigest digest.Digest, artifactTypeFilter string) (*ociindex.Index, bool, error)`
*   **Responsibilities:**
    *   **Find Referrers (Scan Strategy):**
        *   List all manifest digests in `repoName` via storage driver.
        *   For each manifest:
            *   Fetch content.
            *   Unmarshal JSON.
            *   Check if `subject.digest` matches `subjectDigest`.
            *   If match, create a valid OCI descriptor (including `artifactType` derivation and `annotations`). Add to a temporary list.
    *   **Handle Pre-API Referrers (Tag Schema):**
        *   Calculate the expected tag name for `subjectDigest` based on the spec's "Referrers Tag Schema".
        *   Attempt to fetch the manifest for this tag.
        *   If it's a valid OCI Image Index, add its descriptors to the temporary list.
    *   **Filter & Deduplicate:**
        *   Combine descriptors from the scan and the tag schema.
        *   Remove duplicates based on digest.
        *   If `artifactTypeFilter` is present, filter the list by `artifactType`. Track if filtering occurred.
    *   **Construct Response:**
        *   Create a new OCI Image Index.
        *   Populate `manifests` with the final list of descriptors.
        *   Return the index, the filtering status (boolean), and nil error.

## 4. Storage Layer (`internal/storage/`)

*   **Action:** Verify `driver.StorageDriver` interface and implementations support:
    *   Listing manifest digests within a repository.
    *   Fetching manifest content by digest.
    *   Resolving a tag to its manifest digest.
*   **Note:** No immediate changes expected for the scan strategy. Indexing for performance is a future optimization.

## 5. Testing

*   **New File:** `05_referrers_test.go` (or similar)
*   **Integration Tests:**
    *   Test successful queries (with/without filter).
    *   Test `OCI-Filters-Applied` header presence.
    *   Test empty results (`200 OK`, empty `manifests` array).
    *   Test invalid digest (`400 Bad Request`).
    *   Test non-existent repository (`404 Not Found`).
    *   Test tag schema fallback mechanism.
*   **Unit Tests:** (`internal/registry/registry_test.go`)
    *   Test `registry.GetReferrers` logic for various scenarios (no referrers, subject match, tag match, filtering, errors).

## 6. Documentation

*   **Files:** `README.md`, `plan.md`
*   **Action:** Update documentation to reflect Referrers API support upon completion.
