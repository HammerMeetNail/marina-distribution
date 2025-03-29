package filesystem

import (
	"context"
	"crypto/sha256" // Using SHA256 for path hashing, not digest verification here
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/HammerMeetNail/marina-distribution/internal/storage"
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
)

const (
	blobDataFolder     = "blobs"
	uploadDataFolder   = "uploads"
	manifestDataFolder = "manifests"
	repositoryFolder   = "repositories" // Contains tag data per repo
	tagSubFolder       = "_tags"        // Subfolder within repo for tags
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
	manifestPath := filepath.Join(root, manifestDataFolder)
	repoPath := filepath.Join(root, repositoryFolder)

	// Ensure all base directories exist
	for _, dir := range []string{root, blobPath, uploadPath, manifestPath, repoPath} {
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

// --- Manifest Operations ---

// manifestPath returns the storage path for a manifest based on its digest.
// Uses the same sharding logic as blobs.
func (d *Driver) manifestPath(dgst distribution.Digest) (string, error) {
	if err := dgst.Validate(); err != nil {
		return "", fmt.Errorf("invalid digest: %w", err)
	}
	parts := strings.SplitN(string(dgst), ":", 2)
	algo := parts[0]
	hash := parts[1]
	if len(hash) < 2 {
		return "", fmt.Errorf("digest hash too short: %s", hash)
	}
	shard := hash[:2]
	return filepath.Join(d.rootDirectory, manifestDataFolder, algo, shard, hash), nil
}

// GetManifest retrieves the content of a manifest identified by its digest.
func (d *Driver) GetManifest(ctx context.Context, dgst distribution.Digest) (io.ReadCloser, error) {
	path, err := d.manifestPath(dgst)
	if err != nil {
		return nil, err // Invalid digest format
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.PathNotFoundError{Path: path}
		}
		return nil, fmt.Errorf("failed to open manifest %s: %w", dgst, err)
	}
	return file, nil
}

// PutManifest stores the content read from 'content' as a manifest with the given digest.
func (d *Driver) PutManifest(ctx context.Context, dgst distribution.Digest, content io.Reader) (bytesWritten int64, err error) {
	targetPath, err := d.manifestPath(dgst)
	if err != nil {
		return 0, err // Invalid digest format
	}

	// Ensure parent directory exists
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create manifest directory %s: %w", targetDir, err)
	}

	// Create a temporary file
	tempFile, err := os.CreateTemp(targetDir, filepath.Base(targetPath)+tempSuffix)
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file for manifest %s: %w", dgst, err)
	}
	defer func() {
		tempFile.Close()
		if err != nil { // If an error occurred during the process, remove the temp file
			if removeErr := os.Remove(tempFile.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
				fmt.Fprintf(os.Stderr, "warning: failed to remove temporary manifest file %s: %v\n", tempFile.Name(), removeErr)
			}
		}
	}()

	// Get hash function based on digest algorithm
	hashFunc, err := distribution.GetHashFunc(dgst.Algorithm())
	if err != nil {
		return 0, fmt.Errorf("unsupported digest algorithm %s: %w", dgst.Algorithm(), err)
	}
	hasher := hashFunc.New()

	// Tee reader to write and hash simultaneously
	teeReader := io.TeeReader(content, hasher)

	// Copy data to temp file
	bytesWritten, err = io.Copy(tempFile, teeReader)
	if err != nil {
		return bytesWritten, fmt.Errorf("failed to write manifest content to temporary file %s: %w", tempFile.Name(), err)
	}

	// Verify calculated digest
	calculatedDigest := distribution.NewDigest(dgst.Algorithm(), hasher)
	if calculatedDigest != dgst {
		err = storage.DigestMismatchError{Provided: dgst, Actual: calculatedDigest}
		return bytesWritten, err // Temp file removed by defer
	}

	// Close temp file before rename
	if err = tempFile.Close(); err != nil {
		err = fmt.Errorf("failed to close temporary manifest file %s before rename: %w", tempFile.Name(), err)
		return bytesWritten, err
	}

	// Rename temp file to final path
	if err = os.Rename(tempFile.Name(), targetPath); err != nil {
		// Attempt cleanup if rename fails
		if removeErr := os.Remove(tempFile.Name()); removeErr != nil && !os.IsNotExist(removeErr) {
			fmt.Fprintf(os.Stderr, "warning: failed to remove temporary manifest file %s after failed rename: %v\n", tempFile.Name(), removeErr)
		}
		err = fmt.Errorf("failed to rename temporary manifest file %s to final path %s: %w", tempFile.Name(), targetPath, err)
		return bytesWritten, err
	}

	// Success
	return bytesWritten, nil
}

// StatManifest retrieves information about a manifest identified by its digest.
func (d *Driver) StatManifest(ctx context.Context, dgst distribution.Digest) (storage.FileInfo, error) {
	path, err := d.manifestPath(dgst)
	if err != nil {
		return storage.FileInfo{}, err // Invalid digest format
	}

	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.FileInfo{}, storage.PathNotFoundError{Path: path}
		}
		return storage.FileInfo{}, fmt.Errorf("failed to stat manifest %s: %w", dgst, err)
	}

	if fi.IsDir() {
		// Manifests should not be directories
		return storage.FileInfo{}, fmt.Errorf("manifest path is a directory: %s", path)
	}

	// Note: We assume the file content matches the digest for Stat operations.
	// Verification happens during PutManifest.
	return storage.FileInfo{
		Path:    path, // Or perhaps just the digest? TBD
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		IsDir:   false,
		Digest:  dgst, // We assume the file at this path corresponds to the digest
	}, nil
}

// DeleteManifest removes a manifest identified by its digest.
// TODO: Implement this method.
func (d *Driver) DeleteManifest(ctx context.Context, dgst distribution.Digest) error {
	// Implementation Note: Similar to Delete for blobs.
	// 1. Get path using manifestPath.
	// 2. os.Remove.
	// 3. Handle errors (PathNotFoundError).
	return fmt.Errorf("DeleteManifest not yet implemented")
}

// --- Tag Operations ---

// repoTagsPath returns the path to the directory storing tags for a repository.
func (d *Driver) repoTagsPath(repoName distribution.RepositoryName) string {
	// Note: repoName might contain '/', which is fine for subdirectories.
	// Ensure the repoName is cleaned to prevent path traversal issues, although
	// validation should handle most cases.
	cleanRepoName := filepath.Clean(string(repoName))
	return filepath.Join(d.rootDirectory, repositoryFolder, cleanRepoName, tagSubFolder)
}

// tagPath returns the path to the file storing the digest for a specific tag.
func (d *Driver) tagPath(repoName distribution.RepositoryName, tagName string) string {
	// TODO: Validate tagName format? The spec regex allows '.', '_', '-' but filesystem might have issues?
	// For now, assume valid tag names are filesystem-safe. Need to ensure tagName is also cleaned.
	cleanTagName := filepath.Clean(tagName) // Basic cleaning
	return filepath.Join(d.repoTagsPath(repoName), cleanTagName)
}

// ResolveTag retrieves the digest associated with a tag in a specific repository.
func (d *Driver) ResolveTag(ctx context.Context, repoName distribution.RepositoryName, tagName string) (distribution.Digest, error) {
	path := d.tagPath(repoName, tagName)

	contentBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Use the specific TagNotFoundError
			return "", storage.TagNotFoundError{Repository: repoName, Tag: tagName}
		}
		return "", fmt.Errorf("failed to read tag file %s: %w", path, err)
	}

	// Content should be just the digest string
	dgstStr := strings.TrimSpace(string(contentBytes))
	dgst := distribution.Digest(dgstStr)

	// Validate the digest read from the file
	if err := dgst.Validate(); err != nil {
		// This indicates a corrupted tag file
		return "", fmt.Errorf("invalid digest found in tag file %s: %w", path, err)
	}

	return dgst, nil
}

// GetTags lists all tags for a given repository.
func (d *Driver) GetTags(ctx context.Context, repoName distribution.RepositoryName) ([]string, error) {
	tagsPath := d.repoTagsPath(repoName)
	entries, err := os.ReadDir(tagsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // No tags directory means no tags, return empty list.
		}
		return nil, fmt.Errorf("failed to read tags directory %s: %w", tagsPath, err)
	}

	tags := make([]string, 0, len(entries))
	for _, entry := range entries {
		// Ignore directories or non-regular files within the tags directory
		if !entry.IsDir() {
			// TODO: Should we validate that the filename matches the tag regex?
			tags = append(tags, entry.Name())
		}
	}

	// Sort tags lexically (case-insensitive alphanumeric) as required by spec.
	// Using strings.ToLower for case-insensitivity.
	sort.Slice(tags, func(i, j int) bool {
		return strings.ToLower(tags[i]) < strings.ToLower(tags[j])
	})

	return tags, nil
}

// TagManifest associates a tag with a manifest digest in a specific repository.
func (d *Driver) TagManifest(ctx context.Context, repoName distribution.RepositoryName, tagName string, dgst distribution.Digest) error {
	if err := dgst.Validate(); err != nil {
		return fmt.Errorf("invalid digest provided for tagging: %w", err)
	}

	// TODO: Validate tagName format strictly?

	tagFilePath := d.tagPath(repoName, tagName)
	tagDirPath := filepath.Dir(tagFilePath)

	// Ensure parent directory exists
	if err := os.MkdirAll(tagDirPath, 0755); err != nil {
		return fmt.Errorf("failed to create tag directory %s: %w", tagDirPath, err)
	}

	// Write the digest string to the tag file.
	// Using WriteFile is simple and sufficient for tags, as concurrent writes
	// to the same tag should just result in the last write winning, which is acceptable.
	// A temp file + rename would provide more atomicity if needed.
	err := os.WriteFile(tagFilePath, []byte(dgst.String()), 0644)
	if err != nil {
		return fmt.Errorf("failed to write tag file %s: %w", tagFilePath, err)
	}

	return nil
}

// UntagManifest removes a tag association from a repository.
// TODO: Implement this method.
func (d *Driver) UntagManifest(ctx context.Context, repoName distribution.RepositoryName, tagName string) error {
	// Implementation Note:
	// 1. Get path using tagPath.
	// 2. Use os.Remove to delete the tag file.
	// 3. Handle errors (os.IsNotExist -> TagNotFoundError).
	// 4. Consider cleaning up empty repo tag directories? (Similar to blob/manifest deletion).
	return fmt.Errorf("UntagManifest not yet implemented")
}
