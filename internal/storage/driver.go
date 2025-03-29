package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
)

// FileInfo contains information about a file stored by the driver.
type FileInfo struct {
	Path    string              // Path or key identifying the file
	Size    int64               // Logical size of the file in bytes
	ModTime time.Time           // Modification time
	IsDir   bool                // True if the path is a directory
	Digest  distribution.Digest // Digest of the file content, if available/applicable
}

// StorageDriver defines the interface for registry storage operations.
// Implementations are responsible for handling the actual storage and retrieval
// of blobs and potentially other registry artifacts like manifest signatures.
// Paths passed to these methods are generally relative to the driver's root.
type StorageDriver interface {
	// === Blob Operations ===

	// GetContent retrieves the content of a blob identified by its digest.
	// Returns an io.ReadCloser for the blob's content.
	// The caller is responsible for closing the reader.
	GetContent(ctx context.Context, dgst distribution.Digest) (io.ReadCloser, error)

	// PutContent stores the content read from 'content' as a blob with the given digest.
	// The content stream is verified against the digest.
	// Returns the number of bytes written and an error if verification fails or storage fails.
	PutContent(ctx context.Context, dgst distribution.Digest, content io.Reader) (bytesWritten int64, err error)

	// Stat retrieves information about a blob identified by its digest.
	// Returns FileInfo or an error if the blob doesn't exist.
	Stat(ctx context.Context, dgst distribution.Digest) (FileInfo, error)

	// Delete removes a blob identified by its digest.
	// Returns an error if the blob doesn't exist or deletion fails.
	Delete(ctx context.Context, dgst distribution.Digest) error

	// === Upload Operations ===
	// These methods handle the process of resumable blob uploads.

	// StartUpload initiates a new blob upload session in the given repository.
	// Returns a unique upload ID or an error.
	StartUpload(ctx context.Context, repoName distribution.RepositoryName) (uploadID string, err error)

	// PutUploadChunk appends a chunk of data to an ongoing upload session.
	// 'chunk' is the data reader, 'uploadID' identifies the session, 'offset' is the starting byte position.
	// Returns the number of bytes written in this chunk or an error.
	// Implementations should handle potential concurrent writes to the same uploadID if necessary.
	PutUploadChunk(ctx context.Context, uploadID string, offset int64, chunk io.Reader) (bytesWritten int64, err error)

	// GetUploadProgress retrieves the current progress (last byte offset written) for an upload session.
	GetUploadProgress(ctx context.Context, uploadID string) (offset int64, err error)

	// AbortUpload cancels an ongoing upload session and cleans up temporary resources.
	AbortUpload(ctx context.Context, uploadID string) error

	// FinishUpload completes an upload session.
	// It verifies the total uploaded content against the provided digest.
	// If successful, it moves the completed blob to its final content-addressable location.
	// 'uploadID' identifies the session, 'finalDigest' is the expected digest of the full blob.
	FinishUpload(ctx context.Context, uploadID string, finalDigest distribution.Digest) error

	// === Manifest & Tag Operations (Placeholders - To be defined more concretely later) ===

	// GetManifest(ctx context.Context, repoName distribution.RepositoryName, reference distribution.Reference) (distribution.Manifest, error)
	// PutManifest(ctx context.Context, repoName distribution.RepositoryName, reference distribution.Reference, manifest distribution.Manifest) error
	// DeleteManifest(ctx context.Context, repoName distribution.RepositoryName, reference distribution.Reference) error
	// GetTags(ctx context.Context, repoName distribution.RepositoryName) ([]string, error)
	// TagManifest(ctx context.Context, repoName distribution.RepositoryName, tagName string, dgst distribution.Digest) error
	// UntagManifest(ctx context.Context, repoName distribution.RepositoryName, tagName string) error
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
	Provided distribution.Digest
	Actual   distribution.Digest
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
