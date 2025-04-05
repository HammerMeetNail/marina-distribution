# marina-distribution

> This repository was created with gemini-2.5-pro-exp-03-25

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

See `docs/plan.md`, `docs/referrers_plan.md`, and `docs/storage.md` for implementation plans.

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

## Storage Backend

The registry uses a storage driver abstraction (`pkg/distribution/storage.go`) to handle the persistence of blobs and manifests. This allows for different backend implementations.

Currently, the following storage drivers are implemented:

*   **Filesystem:** Stores registry data on the local filesystem.
*   **S3:** Stores registry data in an S3-compatible object storage service (like AWS S3 or MinIO).

### Configuration

The storage driver is selected and configured via environment variables when running the registry:

#### Filesystem Driver

*   `STORAGE_DRIVER=filesystem` (This is the default if `STORAGE_DRIVER` is not set)
*   `STORAGE_PATH`: Specifies the root directory for the `filesystem` storage driver. Defaults to `./registry-data`.

Example:
```bash
export STORAGE_DRIVER=filesystem
export STORAGE_PATH=/mnt/registry-storage
go run ./cmd/registry/main.go
```

#### S3 Driver

*   `STORAGE_DRIVER=s3`
*   `S3_BUCKET`: (Required) The name of the S3 bucket.
*   `S3_REGION`: (Required for AWS S3) The AWS region of the bucket (e.g., `us-east-1`).
*   `S3_ENDPOINT`: (Optional, for S3-compatible services like MinIO) The endpoint URL of the S3 service (e.g., `https://localhost:9000`).
*   `S3_PREFIX`: (Optional) A prefix within the bucket to store registry data under (e.g., `registry`).
*   `S3_FORCE_PATH_STYLE`: (Optional, usually `true` for MinIO) Set to `true` to force path-style addressing (e.g., `https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`).
*   `S3_INSECURE_SKIP_VERIFY`: (Optional, **Use with caution!**) Set to `true` to disable TLS certificate verification. Useful for testing with self-signed certificates (like local MinIO). **DO NOT USE IN PRODUCTION.**
*   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`: (Optional) Standard AWS credentials. If not set, the driver uses the default AWS credential chain (environment variables, shared credentials file, IAM role). These are also used for MinIO if `S3_ENDPOINT` is set.

**Example (AWS S3):**

```bash
export STORAGE_TYPE=s3
export S3_BUCKET=test
export S3_REGION=us-east-1
export S3_ENDPOINT=https://localhost:9000
export S3_FORCE_PATH_STYLE=true
export AWS_ACCESS_KEY_ID=abc
export AWS_SECRET_ACCESS_KEY=123
# Ensure AWS credentials are configured via environment or ~/.aws/credentials
go run ./cmd/registry/main.go
```

**Example (Local MinIO with Self-Signed Certs):**

This setup is useful for local development and testing.

1.  **Generate Self-Signed Certificates using OpenSSL:**
    *   Create a directory for certificates: `mkdir -p minio-certs`
    *   Generate the self-signed certificate:
        ```bash
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout minio-certs/private.key -out minio-certs/public.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
        ```

2.  **Start MinIO with Certificates:**
    *   Start the MinIO server:
        ```bash
        podman run -d --rm \
        -p 9000:9000 \
        -p 9001:9001 \
        --name minio \
        -e "MINIO_ROOT_USER=minioadmin" \
        -e "MINIO_ROOT_PASSWORD=minioadmin" \
        -e "MINIO_CERT_DIR=/root/.minio/certs" \
        -v ./minio-certs:/root/.minio/certs:Z \
        -v ./minio-data:/data:Z \
        minio/minio server /data --console-address ":9001"
        ```
        MinIO should automatically pick up the certificates from `./minio-certs` and serve over HTTPS on port 9000.

4.  **Create a Bucket:** Use the MinIO Client (`mc`) or the web console (usually `https://localhost:9001`) to create a bucket (e.g., `registry-data`).
    ```bash
    # Install mc: https://min.io/docs/minio/linux/reference/minio-mc.html#install-mc
    mc alias set localminio https://localhost:9000 minioadmin minioadmin --api s3v4 --insecure
    mc mb localminio/registry-data --insecure
    ```

5.  **Run the Registry:**
    ```bash
    export STORAGE_DRIVER=s3
    export S3_BUCKET=registry-data
    export S3_ENDPOINT=https://localhost:9000
    export S3_FORCE_PATH_STYLE=true
    export S3_INSECURE_SKIP_VERIFY=true # Required for self-signed certs
    export AWS_ACCESS_KEY_ID=minioadmin # Use MinIO credentials
    export AWS_SECRET_ACCESS_KEY=minioadmin # Use MinIO credentials

    go run ./cmd/registry/main.go
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

1.  **Prerequisites:** Ensure you have the `conformance.test` binary. This has been compiled on an M1 Mac and is available in `tests` directory. For all other architectures, please compile using [distribution-spec conformance suite](https://github.com/opencontainers/distribution-spec/tree/main/conformance).
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
