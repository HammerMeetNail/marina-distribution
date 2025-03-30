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

See `docs/plan.md` and `docs/referrers_plan.md` for the original implementation plans.

## Running the Registry

```bash
go run ./cmd/registry/main.go
```

The registry will start on port `:5000` by default and store data in `./registry-data`.

## Building

To build the registry executable, run the following command from the project root:

```bash
go build -o marina-distribution ./cmd/registry/main.go
```

This will create an executable file named `marina-distribution` in the project root. You can then run it directly:

```bash
./marina-distribution
```

## Running with Podman

You can build and run this registry as a container using Podman (or Docker).

1.  **Build the Image:** From the project root, build the container image:

    ```bash
    podman build -t marina-distribution .
    ```

2.  **Run the Container:** Run the container, mapping the port and mounting a volume for persistent data storage:

    ```bash
    # Create a directory for persistent data on the host if it doesn't exist
    mkdir -p ./registry-data

    # Run the container
    podman run -d --name marina-registry \
      -p 5000:5000 \
      -v ./registry-data:/data:Z \
      marina-distribution
    ```

    *   `-d`: Run in detached mode (background).
    *   `--name marina-registry`: Assign a name to the container.
    *   `-p 5000:5000`: Map port 5000 on the host to port 5000 in the container.
    *   `-v ./registry-data:/data:Z`: Mount the local `./registry-data` directory into the container at `/data` for persistent storage. The `:Z` label ensures SELinux compatibility if enabled.

    The registry will be accessible at `localhost:5000`.

3.  **View Logs:**

    ```bash
    podman logs marina-registry
    ```

4.  **Stop and Remove:**

    ```bash
    podman stop marina-registry
    podman rm marina-registry
    ```

## Running Conformance Tests

The OCI Distribution Conformance tests can be run against this registry implementation using the provided script.

1.  **Prerequisites:** Ensure you have the `conformance.test` binary (from the [distribution-spec conformance suite](https://github.com/opencontainers/distribution-spec/tree/main/conformance)) placed in the `tests/` directory.
2.  **Configuration:** Review and adjust the environment variables in `tests/.env_vars` to configure the registry URL, namespace, and which test workflows to run.
3.  **Execution:** Run the test script from the project root:

    ```bash
    ./run_conformance_tests.sh
    ```

    The script will:
    *   Check if port 5000 is free and prompt to kill any occupying process if necessary.
    *   Start the registry server using `go run`.
    *   Source the environment variables from `tests/.env_vars`.
    *   Execute the `tests/conformance.test` binary.
    *   Stop the registry server upon completion.
    *   Output test results to the console and generate an HTML report (`report.html`). Server logs are saved to `tests/registry.log`.
