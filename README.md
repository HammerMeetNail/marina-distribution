# marina-distribution

An implementation of the OCI Distribution Specification.

## Implemented Features

This registry implements the following parts of the OCI Distribution Specification (v1.1):

*   **API Version Check:** `GET /v2/`
*   **Pull:**
    *   `GET /v2/{name}/blobs/{digest}`
    *   `HEAD /v2/{name}/blobs/{digest}`
    *   `GET /v2/{name}/manifests/{reference}`
    *   `HEAD /v2/{name}/manifests/{reference}`
*   **Push:**
    *   Blob Upload (Monolithic POST/PUT, Chunked POST/PATCH/PUT)
        *   `POST /v2/{name}/blobs/uploads/`
        *   `PATCH /v2/{name}/blobs/uploads/{uuid}`
        *   `PUT /v2/{name}/blobs/uploads/{uuid}?digest={digest}`
        *   `GET /v2/{name}/blobs/uploads/{uuid}` (Upload progress)
    *   Manifest Upload
        *   `PUT /v2/{name}/manifests/{reference}`
*   **Content Discovery:**
    *   Tag Listing: `GET /v2/{name}/tags/list` (with pagination)
    *   Referrers Listing: `GET /v2/{name}/referrers/{digest}` (with `artifactType` filtering)
*   **Content Management:**
    *   `DELETE /v2/{name}/manifests/{reference}` (Tags and Manifests)
    *   `DELETE /v2/{name}/blobs/{digest}`

See `plan.md` for the original implementation plan and `spec.md` for the specification details.

## Running the Registry

```bash
go run ./cmd/registry/main.go
```

The registry will start on port `:5000` by default and store data in `./registry-data`.
