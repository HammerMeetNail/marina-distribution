# Storage Driver Abstraction Plan

This plan outlines the steps to refactor the storage layer of the `marina-distribution` library to support multiple backend implementations (e.g., filesystem, S3, GCS) while strictly adhering to the OCI distribution specification operations. Administrative or non-spec features will be deferred to higher-level applications using this library.

## Goals

1.  Define a `StorageDriver` interface focused solely on OCI spec operations.
2.  Implement a factory pattern to instantiate different storage drivers based on configuration.
3.  Refactor the existing `filesystem` driver to conform to the refined interface and configuration pattern.
4.  Establish a testing strategy that includes both OCI conformance tests and driver-specific unit tests.

## Plan Details

1.  **Refine `StorageDriver` Interface (`internal/storage/driver.go`):**
    *   **Focus on Core OCI Operations:** The interface will only include methods directly related to OCI spec actions:
        *   Blob Operations: `GetContent`, `PutContent`, `Stat`, `Delete`
        *   Upload Operations: `StartUpload`, `PutUploadChunk`, `GetUploadProgress`, `AbortUpload`, `FinishUpload`
        *   Manifest Operations: `GetManifest`, `PutManifest`, `StatManifest`, `DeleteManifest`
        *   Tag Operations: `ResolveTag`, `GetTags`, `TagManifest`, `UntagManifest`
    *   **Remove `ListManifestDigests`:** This method will be removed from the interface as it's not a standard client-facing OCI API operation.
    *   **Keep `FileInfo`:** The `FileInfo` struct (including `Path`) will remain for potential debugging context.

2.  **Introduce Storage Configuration:**
    *   Define a configuration mechanism (e.g., structs in `internal/config` or passed directly to the factory) to specify:
        *   The storage driver type (e.g., `"filesystem"`, `"s3"`, `"gcs"`).
        *   Driver-specific parameters (e.g., `rootDirectory` for filesystem, `bucket`, `region`, `prefix` for S3).
    *   Credentials must be handled externally (e.g., environment variables, IAM roles, application default credentials).

3.  **Implement a Driver Factory:**
    *   Create a factory function `storage.NewDriver(cfg config.StorageConfig) (StorageDriver, error)` (or similar signature) that takes the storage configuration and returns an initialized instance of the appropriate `StorageDriver` implementation based on the configured type.

4.  **Refactor `filesystem.Driver`:**
    *   Remove the implementation for `ListManifestDigests` as it's being removed from the interface.
    *   Update `filesystem.NewDriver` to accept its configuration (the root directory) potentially via a struct passed from the factory.
    *   Ensure all remaining methods correctly implement the refined `StorageDriver` interface.

5.  **Design Backend Implementations (Interface Compliance):**
    *   Future backend implementations (e.g., `internal/storage/s3`) must focus solely on correctly implementing the methods defined in the refined `StorageDriver` interface.
    *   Map interface operations to corresponding backend API calls.
    *   Define appropriate object key/path structures for the backend.
    *   Translate backend errors to the standard `storage` error types where applicable.

6.  **Testing Strategy:**
    *   **Conformance Tests:** Continue using the OCI conformance tests (`run_conformance_tests.sh`) against the registry configured with different drivers (starting with filesystem).
    *   **Driver Unit Tests:** Implement specific unit tests for each `StorageDriver` implementation (starting with `filesystem`). These tests should mock external dependencies (filesystem, cloud APIs) and verify the driver methods adhere to the interface contract, including error handling.

## Visualization

```mermaid
graph TD
    subgraph Configuration
        ConfigLoader --> StorageConfig{Storage Config (type, params)}
    end

    subgraph Registry Core (OCI Spec Focused)
        RegistryHandlers[Registry Handlers (cmd/registry)] --> StorageDriverInterface[storage.StorageDriver]
        RegistryHandlers --> StorageFactory[storage.NewDriver(cfg)]
        StorageFactory -->|type="filesystem"| FilesystemDriver(filesystem.NewDriver)
        StorageFactory -->|type="s3"| S3Driver(s3.NewDriver)
        StorageFactory -->|...| OtherDrivers(...)
    end

    subgraph Storage Drivers (Implements Interface)
        StorageDriverInterface <|.. FilesystemDriver
        StorageDriverInterface <|.. S3Driver
        StorageDriverInterface <|.. OtherDrivers

        FilesystemDriver --> |Uses| LocalFS[Local Filesystem]
        S3Driver --> |Uses| CloudSDK[Cloud SDK (e.g., AWS)] --> ObjectStore[Object Store (e.g., S3)]
        OtherDrivers --> |Uses| CloudSDK2[...] --> ObjectStore2[...]
    end

    subgraph Testing
        ConformanceTests[OCI Conformance Tests] --> RegistryHandlers
        DriverUnitTests[Driver Unit Tests] --> FilesystemDriver
        DriverUnitTests --> S3Driver
        DriverUnitTests --> OtherDrivers
    end

    style StorageDriverInterface fill:#f9f,stroke:#333,stroke-width:2px
```

## Next Steps

Implement the changes outlined in this plan.
