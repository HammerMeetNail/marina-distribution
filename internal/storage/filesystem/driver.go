package filesystem

import (
	"context"
	"crypto/sha256" // Using SHA256 for path hashing, not digest verification here
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/HammerMeetNail/marina-distribution/internal/storage"
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
)

const (
	blobDataFolder     = "blobs"
	uploadDataFolder   = "uploads"
	manifestDataFolder = "manifests" // Placeholder for future use
	tagDataFolder      = "tags"      // Placeholder for future use
	tempSuffix         = ".tmp"
)

// Driver implements the storage.StorageDriver interface using the local filesystem.
type Driver struct {
	rootDirectory string
}

// NewDriver creates a new filesystem storage driver rooted at rootDirectory.
// It creates the necessary subdirectories if they don't exist.
func NewDriver(rootDirectory string) (*Driver, error) {
	root := filepath.Clean(rootDirectory)
	if root == "" {
		return nil, fmt.Errorf("root directory cannot be empty")
	}

	// Create necessary subdirectories
	blobPath := filepath.Join(root, blobDataFolder)
	uploadPath := filepath.Join(root, uploadDataFolder)
	// manifestPath := filepath.Join(root, manifestDataFolder) // Future
	// tagPath := filepath.Join(root, tagDataFolder)          // Future

	for _, dir := range []string{root, blobPath, uploadPath /*, manifestPath, tagPath*/} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &Driver{rootDirectory: root}, nil
}

// blobPath returns the path for a blob based on its digest.
// It uses a sharded structure (e.g., /blobs/sha256/ab/abcdef123...) to avoid too many files in one directory.
func (d *Driver) blobPath(dgst distribution.Digest) (string, error) {
	if err := dgst.Validate(); err != nil {
		return "", fmt.Errorf("invalid digest: %w", err)
	}
	parts := strings.SplitN(string(dgst), ":", 2)
	algo := parts[0]
	hash := parts[1]
	if len(hash) < 2 {
		return "", fmt.Errorf("digest hash too short: %s", hash)
	}
	// Example sharding: use the first 2 chars of the hash
	shard := hash[:2]
	return filepath.Join(d.rootDirectory, blobDataFolder, algo, shard, hash), nil
}

// GetContent retrieves the content of a blob identified by its digest.
func (d *Driver) GetContent(ctx context.Context, dgst distribution.Digest) (io.ReadCloser, error) {
	path, err := d.blobPath(dgst)
	if err != nil {
		return nil, err // Invalid digest format
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.PathNotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to open blob %s: %w", dgst, err)
	}
	return file, nil
}

// PutContent stores the content read from 'content' as a blob with the given digest.
func (d *Driver) PutContent(ctx context.Context, dgst distribution.Digest, content io.Reader) (bytesWritten int64, err error) {
	targetPath, err := d.blobPath(dgst)
	if err != nil {
		return 0, err // Invalid digest format
	}

	// Ensure parent directory exists
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create blob directory %s: %w", targetDir, err)
	}

	// Create a temporary file in the same directory to ensure atomic rename later
	tempFile, err := os.CreateTemp(targetDir, filepath.Base(targetPath)+tempSuffix)
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file for blob %s: %w", dgst, err)
	}
	defer func() {
		// Ensure temp file is closed and removed if anything goes wrong
		tempFile.Close()
		if err != nil {
			if removeErr := os.Remove(tempFile.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
				// Log the cleanup error, but return the original error
				fmt.Fprintf(os.Stderr, "warning: failed to remove temporary file %s: %v\n", tempFile.Name(), removeErr)
			}
		}
	}()

	// Get the appropriate hash function based on the digest algorithm
	hashFunc, err := distribution.GetHashFunc(dgst.Algorithm())
	if err != nil {
		return 0, fmt.Errorf("unsupported digest algorithm %s: %w", dgst.Algorithm(), err)
	}
	hasher := hashFunc.New()

	// Use TeeReader to write to file and calculate hash simultaneously
	teeReader := io.TeeReader(content, hasher)

	bytesWritten, err = io.Copy(tempFile, teeReader)
	if err != nil {
		return bytesWritten, fmt.Errorf("failed to write blob content to temporary file %s: %w", tempFile.Name(), err)
	}

	// Verify the calculated digest
	calculatedDigest := distribution.NewDigest(dgst.Algorithm(), hasher)
	if calculatedDigest != dgst {
		err = storage.DigestMismatchError{Provided: dgst, Actual: calculatedDigest}
		return bytesWritten, err // Temp file will be removed by defer
	}

	// Close the temp file before renaming
	if err = tempFile.Close(); err != nil {
		// Don't remove the temp file here, as the write was successful, but rename failed.
		// Mark err so defer doesn't try to remove it again.
		err = fmt.Errorf("failed to close temporary file %s before rename: %w", tempFile.Name(), err)
		return bytesWritten, err
	}

	// Rename the temporary file to the final path
	if err = os.Rename(tempFile.Name(), targetPath); err != nil {
		// If rename fails, try to remove the temp file as it's useless now.
		if removeErr := os.Remove(tempFile.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
			fmt.Fprintf(os.Stderr, "warning: failed to remove temporary file %s after failed rename: %v\n", tempFile.Name(), removeErr)
		}
		err = fmt.Errorf("failed to rename temporary file %s to final path %s: %w", tempFile.Name(), targetPath, err)
		return bytesWritten, err
	}

	// Success! err is nil, defer will just close the already closed file (no-op) and won't remove it.
	return bytesWritten, nil
}

// Stat retrieves information about a blob identified by its digest.
func (d *Driver) Stat(ctx context.Context, dgst distribution.Digest) (storage.FileInfo, error) {
	path, err := d.blobPath(dgst)
	if err != nil {
		return storage.FileInfo{}, err // Invalid digest format
	}

	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.FileInfo{}, storage.PathNotFoundError{Path: path}
		}
		return storage.FileInfo{}, fmt.Errorf("failed to stat blob %s: %w", dgst, err)
	}

	if fi.IsDir() {
		// Blobs should not be directories
		return storage.FileInfo{}, fmt.Errorf("blob path is a directory: %s", path)
	}

	return storage.FileInfo{
		Path:    path, // Or perhaps just the digest? TBD
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		IsDir:   false,
		Digest:  dgst, // We assume the file at this path corresponds to the digest
	}, nil
}

// Delete removes a blob identified by its digest.
func (d *Driver) Delete(ctx context.Context, dgst distribution.Digest) error {
	path, err := d.blobPath(dgst)
	if err != nil {
		return err // Invalid digest format
	}

	err = os.Remove(path)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.PathNotFoundError{Path: path}
		}
		return fmt.Errorf("failed to delete blob %s: %w", dgst, err)
	}

	// Optional: Clean up empty parent directories.
	// This can be complex and might have race conditions if not done carefully.
	// For simplicity, we'll skip this for now. A separate garbage collection
	// process is often better suited for this.

	return nil
}

// --- Upload Operations ---

// uploadPath returns the path for storing temporary upload data.
// It uses a hash of the upload ID for sharding.
func (d *Driver) uploadPath(uploadID string) string {
	// Simple sharding based on upload ID hash to avoid too many files/dirs
	hasher := sha256.New()
	hasher.Write([]byte(uploadID))
	hash := hex.EncodeToString(hasher.Sum(nil))
	shard := hash[:2]
	return filepath.Join(d.rootDirectory, uploadDataFolder, shard, uploadID)
}

// StartUpload initiates a new blob upload session.
func (d *Driver) StartUpload(ctx context.Context, repoName distribution.RepositoryName) (uploadID string, err error) {
	// Generate a unique upload ID
	newUUID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate upload UUID: %w", err)
	}
	uploadID = newUUID.String()

	// Create the upload directory
	uploadDir := d.uploadPath(uploadID)
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create upload directory %s: %w", uploadDir, err)
	}

	// Optionally, create metadata files here (e.g., start time, repo name)
	// For now, just creating the directory is sufficient to represent the session.

	return uploadID, nil
}

// PutUploadChunk appends a chunk of data to an ongoing upload session.
func (d *Driver) PutUploadChunk(ctx context.Context, uploadID string, offset int64, chunk io.Reader) (bytesWritten int64, err error) {
	uploadDir := d.uploadPath(uploadID)
	dataPath := filepath.Join(uploadDir, "data") // Assuming data is stored in a file named "data"

	// Check if upload session exists (directory exists)
	if _, err := os.Stat(uploadDir); err != nil {
		if os.IsNotExist(err) {
			return 0, storage.UploadNotFoundError{UploadID: uploadID}
		}
		return 0, fmt.Errorf("failed to stat upload directory %s: %w", uploadDir, err)
	}

	// Open the data file for writing. Create if it doesn't exist (first chunk).
	file, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to open upload data file %s: %w", dataPath, err)
	}
	defer file.Close()

	// Verify the offset matches the current file size for sequential writes.
	currentSize, err := file.Seek(0, io.SeekEnd) // Seek to end to get current size
	if err != nil {
		return 0, fmt.Errorf("failed to seek upload data file %s: %w", dataPath, err)
	}
	if currentSize != offset {
		return 0, storage.InvalidOffsetError{UploadID: uploadID, Offset: offset}
	}

	// Append the chunk data
	bytesWritten, err = io.Copy(file, chunk)
	if err != nil {
		return bytesWritten, fmt.Errorf("failed to write chunk to upload data file %s: %w", dataPath, err)
	}

	return bytesWritten, nil
}

// GetUploadProgress retrieves the current progress (last byte offset written) for an upload session.
func (d *Driver) GetUploadProgress(ctx context.Context, uploadID string) (offset int64, err error) {
	uploadDir := d.uploadPath(uploadID)
	dataPath := filepath.Join(uploadDir, "data")

	// Stat the data file
	fi, err := os.Stat(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Check if the directory itself exists. If not, the upload is unknown.
			// If the directory exists but the file doesn't, it means 0 bytes were uploaded.
			if _, dirErr := os.Stat(uploadDir); os.IsNotExist(dirErr) {
				return 0, storage.UploadNotFoundError{UploadID: uploadID}
			}
			// Directory exists, but no data file yet (0 bytes uploaded)
			return 0, nil
		}
		// Other stat error
		return 0, fmt.Errorf("failed to stat upload data file %s: %w", dataPath, err)
	}

	if fi.IsDir() {
		// Should not happen if PutUploadChunk is correct, but check anyway
		return 0, fmt.Errorf("upload data path %s is a directory", dataPath)
	}

	// Return the current size as the progress offset
	return fi.Size(), nil
}

// AbortUpload cancels an ongoing upload session and cleans up temporary resources.
func (d *Driver) AbortUpload(ctx context.Context, uploadID string) error {
	uploadDir := d.uploadPath(uploadID)

	err := os.RemoveAll(uploadDir)
	if err != nil && !os.IsNotExist(err) {
		// Ignore "not found" errors, as the goal is deletion.
		// Report other errors.
		return fmt.Errorf("failed to abort upload %s by removing directory %s: %w", uploadID, uploadDir, err)
	}

	return nil // Successfully aborted (or directory didn't exist)
}

// FinishUpload completes an upload session.
// It verifies the total uploaded content against the provided digest.
// If successful, it moves the completed blob to its final content-addressable location
// and cleans up the upload session resources.
func (d *Driver) FinishUpload(ctx context.Context, uploadID string, finalDigest distribution.Digest) (err error) {
	uploadDir := d.uploadPath(uploadID)
	dataPath := filepath.Join(uploadDir, "data")

	// Check if upload session exists
	if _, dirErr := os.Stat(uploadDir); os.IsNotExist(dirErr) {
		return storage.UploadNotFoundError{UploadID: uploadID}
	}

	// Ensure the final digest is valid before proceeding
	if err := finalDigest.Validate(); err != nil {
		return fmt.Errorf("invalid final digest provided: %w", err)
	}

	// Open the uploaded data file for reading
	dataFile, err := os.Open(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Data file doesn't exist, maybe 0 bytes uploaded? Or chunking error?
			// Treat as upload not found or incomplete for simplicity here.
			// A more robust implementation might check metadata if stored.
			return storage.UploadNotFoundError{UploadID: uploadID} // Or a different error?
		}
		return fmt.Errorf("failed to open upload data file %s: %w", dataPath, err)
	}
	defer dataFile.Close()

	// Calculate the digest of the uploaded file
	hashFunc, err := distribution.GetHashFunc(finalDigest.Algorithm())
	if err != nil {
		// This should have been caught by finalDigest.Validate(), but double-check
		return fmt.Errorf("unsupported digest algorithm %s: %w", finalDigest.Algorithm(), err)
	}
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, dataFile); err != nil {
		return fmt.Errorf("failed to hash uploaded data file %s: %w", dataPath, err)
	}
	calculatedDigest := distribution.NewDigest(finalDigest.Algorithm(), hasher)

	// Compare with the expected final digest
	if calculatedDigest != finalDigest {
		// Cleanup the failed upload attempt
		if cleanupErr := os.RemoveAll(uploadDir); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			fmt.Fprintf(os.Stderr, "warning: failed to cleanup upload directory %s after digest mismatch: %v\n", uploadDir, cleanupErr)
		}
		return storage.DigestMismatchError{Provided: finalDigest, Actual: calculatedDigest}
	}

	// Digests match, determine final blob path
	targetPath, err := d.blobPath(finalDigest)
	if err != nil {
		// Should not happen as digest was validated, but handle defensively
		return fmt.Errorf("failed to determine final blob path: %w", err)
	}
	targetDir := filepath.Dir(targetPath)

	// Ensure final directory exists
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create final blob directory %s: %w", targetDir, err)
	}

	// Move the data file to the final location
	// Note: os.Rename is generally atomic on the same filesystem.
	if err = os.Rename(dataPath, targetPath); err != nil {
		// If rename fails, the upload is effectively incomplete/corrupted.
		// Attempt cleanup, but return the rename error.
		if cleanupErr := os.RemoveAll(uploadDir); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			fmt.Fprintf(os.Stderr, "warning: failed to cleanup upload directory %s after failed rename: %v\n", uploadDir, cleanupErr)
		}
		return fmt.Errorf("failed to move uploaded file %s to final path %s: %w", dataPath, targetPath, err)
	}

	// Successfully moved the blob, now clean up the upload directory
	if err = os.RemoveAll(uploadDir); err != nil && !os.IsNotExist(err) {
		// Log cleanup error, but the operation was successful otherwise.
		fmt.Fprintf(os.Stderr, "warning: failed to cleanup upload directory %s after successful finish: %v\n", uploadDir, err)
	}

	return nil // Success
}

// --- Manifest & Tag Operations (Stubs) ---

// Implementations for Manifest and Tag operations will be added later.
