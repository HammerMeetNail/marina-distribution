package distribution

import (
	"context"
	"fmt"
	"io"
	"time"
)

// === Storage Driver Interface ===

// FileInfo contains information about a file stored by the driver.
type FileInfo struct {
	Path    string    // Path or key identifying the file
	Size    int64     // Logical size of the file in bytes
	ModTime time.Time // Modification time
	IsDir   bool      // True if the path is a directory
	Digest  Digest    // Digest of the file content, if available/applicable
}

// StorageDriver defines the interface for registry storage operations.
// Implementations are responsible for handling the actual storage and retrieval
// of blobs and potentially other registry artifacts like manifest signatures.
// Paths passed to these methods are generally relative to the driver's root.
type StorageDriver interface {
	// === Blob Operations ===
	GetContent(ctx context.Context, dgst Digest) (io.ReadCloser, error)
	PutContent(ctx context.Context, dgst Digest, content io.Reader) (bytesWritten int64, err error)
	Stat(ctx context.Context, dgst Digest) (FileInfo, error)
	Delete(ctx context.Context, dgst Digest) error

	// === Upload Operations ===
	StartUpload(ctx context.Context, repoName RepositoryName) (uploadID string, err error)
	PutUploadChunk(ctx context.Context, uploadID string, offset int64, chunk io.Reader) (bytesWritten int64, err error)
	GetUploadProgress(ctx context.Context, uploadID string) (offset int64, err error)
	AbortUpload(ctx context.Context, uploadID string) error
	FinishUpload(ctx context.Context, uploadID string, finalDigest Digest) error

	// === Manifest Operations ===
	GetManifest(ctx context.Context, dgst Digest) (io.ReadCloser, error)
	PutManifest(ctx context.Context, dgst Digest, content io.Reader) (bytesWritten int64, err error)
	StatManifest(ctx context.Context, dgst Digest) (FileInfo, error)
	DeleteManifest(ctx context.Context, dgst Digest) error

	// === Tag Operations ===
	ResolveTag(ctx context.Context, repoName RepositoryName, tagName string) (Digest, error)
	GetTags(ctx context.Context, repoName RepositoryName) ([]string, error)
	TagManifest(ctx context.Context, repoName RepositoryName, tagName string, dgst Digest) error
	UntagManifest(ctx context.Context, repoName RepositoryName, tagName string) error
}

// === Storage Configuration ===

// DriverType defines the type of storage driver.
type DriverType string

const (
	// FilesystemDriverType represents the local filesystem storage driver.
	FilesystemDriverType DriverType = "filesystem"
	// S3DriverType represents the AWS S3 storage driver (Placeholder).
	S3DriverType DriverType = "s3"
	// GCSDriverType represents the Google Cloud Storage driver (Placeholder).
	GCSDriverType DriverType = "gcs"
	// Add other driver types here (e.g., Azure Blob Storage)
)

// Config holds the overall storage configuration.
// It specifies the driver type and contains driver-specific settings.
type Config struct {
	// Type selects the storage driver implementation. Required.
	Type DriverType `mapstructure:"type"`

	// Filesystem holds configuration specific to the filesystem driver.
	// Used only if Type is "filesystem".
	Filesystem FilesystemConfig `mapstructure:"filesystem"`

	// S3 holds configuration specific to the S3 driver.
	// Used only if Type is "s3".
	S3 S3Config `mapstructure:"s3"`

	// GCS holds configuration specific to the GCS driver. (Placeholder)
	// Used only if Type is "gcs".
	// GCS GCSConfig `mapstructure:"gcs"`
}

// FilesystemConfig contains configuration for the filesystem storage driver.
type FilesystemConfig struct {
	// RootDirectory is the base directory where the registry data is stored. Required.
	RootDirectory string `mapstructure:"rootdirectory"`
}

// Validate checks the filesystem configuration for errors.
func (c *FilesystemConfig) Validate() error {
	if c.RootDirectory == "" {
		return fmt.Errorf("filesystem storage requires a rootdirectory configuration")
	}
	return nil
}

// S3Config contains configuration for the S3 storage driver.
type S3Config struct {
	// Bucket is the S3 bucket name. Required.
	Bucket string `mapstructure:"bucket"`
	// Region is the AWS region. Optional, but recommended for AWS S3.
	Region string `mapstructure:"region"`
	// Endpoint is the S3 API endpoint URL. Optional. Use for S3-compatible storage like Minio.
	Endpoint string `mapstructure:"endpoint"`
	// Prefix is an optional path prefix within the bucket for registry data.
	Prefix string `mapstructure:"prefix"`
	// ForcePathStyle forces path-style addressing (e.g., `endpoint/bucket/key`).
	// Required for Minio. Defaults to false (virtual-hosted style). Optional.
	ForcePathStyle bool `mapstructure:"forcepathstyle"`
	// InsecureSkipVerify allows skipping TLS certificate verification.
	// WARNING: Only use for local testing with self-signed certificates. DO NOT USE IN PRODUCTION. Optional. Defaults to false.
	InsecureSkipVerify bool `mapstructure:"insecureskipverify"`
	// Note: Credentials are handled via the standard AWS SDK credential chain.
}

// Validate checks the S3 configuration for errors.
func (c *S3Config) Validate() error {
	if c.Bucket == "" {
		return fmt.Errorf("s3 storage requires a bucket configuration")
	}
	// Region is optional but good practice for AWS. Endpoint is optional.
	return nil
}

// GCSConfig contains configuration for the GCS storage driver. (Placeholder)
// type GCSConfig struct {
// 	Bucket string `mapstructure:"bucket"`
// 	Prefix string `mapstructure:"prefix"`
// 	// Add other GCS specific options: credentials (handled externally?), etc.
// }

// Validate checks the overall storage configuration.
func (c *Config) Validate() error {
	switch c.Type {
	case FilesystemDriverType:
		if err := c.Filesystem.Validate(); err != nil {
			return fmt.Errorf("filesystem config validation failed: %w", err)
		}
	case S3DriverType:
		// Validate S3 specific config
		if err := c.S3.Validate(); err != nil {
			return fmt.Errorf("s3 config validation failed: %w", err)
		}
	case GCSDriverType:
		// Placeholder for GCS validation
		return fmt.Errorf("gcs storage driver is not yet implemented")
	case "":
		return fmt.Errorf("storage driver type must be specified")
	default:
		return fmt.Errorf("unsupported storage driver type: %s", c.Type)
	}
	return nil
}

// === Storage Error Types ===

// TagNotFoundError indicates that a tag was not found in the specified repository.
type TagNotFoundError struct {
	Repository RepositoryName
	Tag        string
}

func (e TagNotFoundError) Error() string {
	return fmt.Sprintf("tag %s not found in repository %s", e.Tag, e.Repository)
}

// PathNotFoundError indicates that a file or directory was not found at the specified path.
type PathNotFoundError struct {
	Path string
}

func (e PathNotFoundError) Error() string {
	return "path not found: " + e.Path
}

// InvalidOffsetError indicates that an invalid offset was provided for an upload operation.
type InvalidOffsetError struct {
	UploadID string
	Offset   int64
}

func (e InvalidOffsetError) Error() string {
	return fmt.Sprintf("invalid offset %d for upload %s", e.Offset, e.UploadID)
}

// DigestMismatchError indicates that the provided digest does not match the content.
type DigestMismatchError struct {
	Provided Digest
	Actual   Digest
}

func (e DigestMismatchError) Error() string {
	return fmt.Sprintf("digest mismatch: provided %s, actual %s", e.Provided, e.Actual)
}

// UploadNotFoundError indicates that an upload session ID was not found.
type UploadNotFoundError struct {
	UploadID string
}

func (e UploadNotFoundError) Error() string {
	return "upload not found: " + e.UploadID
}
