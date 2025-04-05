package s3

import (
	"context"
	"crypto/tls"

	// "encoding/json" // Removed for local temp file approach
	"errors"
	"fmt"
	"io"
	"io/ioutil" // Added for TempFile
	"log"
	"net/http"
	"net/url"
	"os" // Added for file operations
	"path"

	// "sort" // Removed, no longer sorting S3 parts
	"strings"
	"sync" // Added for map locking
	"time"

	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
	"github.com/google/uuid" // For generating unique upload IDs

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types" // Re-enabled for isS3NotFoundError
)

// Ensure driver implements the StorageDriver interface
var _ distribution.StorageDriver = &driver{}

// localUploadState tracks the state of an upload buffered locally.
type localUploadState struct {
	filePath  string   // Path to the temporary file buffering the upload
	totalSize int64    // Current total size written to the temp file
	file      *os.File // Open file handle
}

// driver implements the distribution.StorageDriver interface using AWS S3.
type driver struct {
	s3Client      *s3.Client
	config        distribution.S3Config
	tempDir       string                       // Directory for temporary upload files
	activeUploads map[string]*localUploadState // Map of active uploads (UploadID -> State)
	uploadsLock   sync.RWMutex                 // Mutex to protect activeUploads map
}

// NewDriver creates a new S3 storage driver instance.
func NewDriver(config distribution.S3Config) (distribution.StorageDriver, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("s3 config validation failed: %w", err)
	}

	// Determine temporary directory
	// TODO: Consider making tempDir configurable via S3Config
	tempDir := os.TempDir()
	// Ensure temp directory exists (though os.TempDir() usually does)
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		// Attempt to create it if it doesn't exist
		if err := os.MkdirAll(tempDir, 0700); err != nil {
			return nil, fmt.Errorf("temporary directory %s does not exist and could not be created: %w", tempDir, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to stat temporary directory %s: %w", tempDir, err)
	}

	// Prepare AWS SDK config loaders
	configLoaders := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(config.Region),
		// Potentially add credential provider if needed, but default chain is usually sufficient
		// awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)),
	}

	// --- Conditionally add HTTP Client with InsecureSkipVerify ---
	if config.InsecureSkipVerify {
		log.Println("Warning: Using insecure TLS verification. DO NOT USE IN PRODUCTION.")
		customHttpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		configLoaders = append(configLoaders, awsconfig.WithHTTPClient(customHttpClient))
	}
	// --- End Conditional HTTP Client ---

	// Load AWS configuration using the default credential chain and conditional options
	cfg, err := awsconfig.LoadDefaultConfig(context.TODO(), configLoaders...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client options
	options := &s3.Options{
		Region: cfg.Region, // Use region from loaded config
	}

	// Configure custom endpoint and path-style addressing if specified (for Minio, etc.)
	if config.Endpoint != "" {
		// Validate endpoint URL
		_, err := url.Parse(config.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid s3 endpoint URL %q: %w", config.Endpoint, err)
		}

		options.BaseEndpoint = aws.String(config.Endpoint)
		options.UsePathStyle = config.ForcePathStyle // Use path style if ForcePathStyle is true

		// For non-AWS endpoints, often need static credentials if not using env vars
		// Check if credentials were loaded, otherwise, SDK might fail later.
		// Consider adding explicit credential config fields if default chain isn't enough for endpoint.
		// For now, rely on env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
		// or shared credentials file even for custom endpoints.
		// If using Minio with default user/pass, set these env vars.
		creds, err := cfg.Credentials.Retrieve(context.TODO())
		if err != nil || creds.AccessKeyID == "" {
			// Attempt to load static credentials if endpoint is set and default chain failed/empty
			// This assumes env vars might be set specifically for this endpoint
			staticCreds := credentials.NewStaticCredentialsProvider(
				aws.ToString(aws.String(config.Endpoint)), // Placeholder - need actual creds
				aws.ToString(aws.String(config.Endpoint)), // Placeholder
				"", // Session token
			)
			cfg.Credentials = aws.NewCredentialsCache(staticCreds)
			// Re-check after attempting static load (this part needs refinement based on actual credential strategy)
			// For now, we primarily rely on the default chain being correctly configured externally.
			fmt.Println("Warning: S3 endpoint specified, ensure AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) are set in environment or config files.")

		}

		// Custom resolver needed for path style with endpoint override
		// Note: As of recent SDK versions, setting BaseEndpoint and UsePathStyle might be sufficient.
		// Keeping resolver logic commented for reference if needed.
		/*
			resolver := s3.EndpointResolverFunc(func(region string, options s3.EndpointResolverOptions) (aws.Endpoint, error) {
				if config.Endpoint != "" {
					return aws.Endpoint{
						URL:               config.Endpoint,
						HostnameImmutable: true, // Important for custom endpoints
						Source:            aws.EndpointSourceCustom,
						SigningRegion:     cfg.Region, // Use the configured region for signing
					}, nil
				}
				// Fallback to default AWS endpoint resolution
				return s3.NewDefaultEndpointResolver().ResolveEndpoint(region, options)
			})
			options.EndpointResolver = resolver
		*/
	}

	// Create the S3 client
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.Region = options.Region
		o.BaseEndpoint = options.BaseEndpoint
		o.UsePathStyle = options.UsePathStyle
		// o.EndpointResolver = options.EndpointResolver // If using custom resolver
	})

	// Basic check: Try to list buckets (requires permissions) or head bucket
	// This helps catch config errors early. HeadBucket is less intrusive.
	_, err = s3Client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: aws.String(config.Bucket),
	})
	if err != nil {
		// Handle potential NoSuchBucket error specifically? Or just generic failure?
		// For now, generic failure is okay. User needs to ensure bucket exists and creds are valid.
		return nil, fmt.Errorf("failed to access S3 bucket %q: %w. Check bucket existence, permissions, region, endpoint, and credentials", config.Bucket, err)
	}

	return &driver{
		s3Client:      s3Client,
		config:        config,
		tempDir:       tempDir,
		activeUploads: make(map[string]*localUploadState),
		// uploadsLock is initialized automatically
	}, nil
}

// --- Helper Methods ---

// getBlobPath constructs the S3 key for a blob.
func (d *driver) getBlobPath(dgst distribution.Digest) string {
	return path.Join(d.config.Prefix, "blobs", dgst.Algorithm().String(), dgst.Hex())
}

// getManifestPath constructs the S3 key for a manifest.
func (d *driver) getManifestPath(dgst distribution.Digest) string {
	// Assuming manifests are stored similarly to blobs but under a 'manifests' prefix
	return path.Join(d.config.Prefix, "manifests", dgst.Algorithm().String(), dgst.Hex())
}

// getTagPath constructs the S3 key for a tag link file.
func (d *driver) getTagPath(repoName distribution.RepositoryName, tagName string) string {
	return path.Join(d.config.Prefix, "repositories", repoName.String(), "_tags", tagName)
}

// getUploadPath constructs the S3 key prefix for multipart upload parts/state.
func (d *driver) getUploadPath(uploadID string) string {
	// Store upload related data under a specific prefix
	return path.Join(d.config.Prefix, "_uploads", uploadID)
}

// --- distribution.StorageDriver Interface Implementation ---

// GetContent retrieves the content of a blob identified by its digest.
func (d *driver) GetContent(ctx context.Context, dgst distribution.Digest) (io.ReadCloser, error) {
	blobPath := d.getBlobPath(dgst)
	resp, err := d.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(blobPath),
	})
	if err != nil {
		if isS3NotFoundError(err) {
			return nil, distribution.PathNotFoundError{Path: blobPath}
		}
		return nil, fmt.Errorf("failed to get s3 object %s: %w", blobPath, err)
	}
	// The Body is an io.ReadCloser, which is exactly what we need to return.
	return resp.Body, nil
}

// PutContent uploads blob content, identified by its digest.
// Note: This implementation uses PutObject, which is suitable for moderate-sized blobs.
// For very large blobs, S3 Transfer Manager (Upload) might be more robust, handling multipart uploads automatically.
// Also, PutObject doesn't easily return bytesWritten without consuming the reader first or requiring ContentLength.
// We return 0 for bytesWritten for now, assuming the caller verifies via Stat if needed.
func (d *driver) PutContent(ctx context.Context, dgst distribution.Digest, content io.Reader) (bytesWritten int64, err error) {
	blobPath := d.getBlobPath(dgst)
	_, err = d.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(blobPath),
		Body:   content,
		// Consider setting ContentType, Metadata, etc. if needed
	})
	if err != nil {
		return 0, fmt.Errorf("failed to put s3 object %s: %w", blobPath, err)
	}
	// PutObjectOutput doesn't contain the size. Return 0 as a placeholder.
	// Caller should Stat the object after Put to confirm size if required.
	return 0, nil
}

// Stat retrieves information about a blob.
func (d *driver) Stat(ctx context.Context, dgst distribution.Digest) (distribution.FileInfo, error) {
	blobPath := d.getBlobPath(dgst)
	resp, err := d.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(blobPath),
	})
	if err != nil {
		if isS3NotFoundError(err) {
			return distribution.FileInfo{}, distribution.PathNotFoundError{Path: blobPath}
		}
		return distribution.FileInfo{}, fmt.Errorf("failed to head s3 object %s: %w", blobPath, err)
	}

	modTime := time.Time{}
	if resp.LastModified != nil {
		modTime = *resp.LastModified
	}

	// Note: S3 doesn't inherently store the original digest in metadata unless explicitly added.
	// We return the requested digest here.
	return distribution.FileInfo{
		Path:    blobPath,
		Size:    aws.ToInt64(resp.ContentLength), // Dereference *int64 safely
		ModTime: modTime,
		IsDir:   false, // Blobs are files
		Digest:  dgst,  // Return the digest used for lookup
	}, nil
}

// Delete removes a blob.
func (d *driver) Delete(ctx context.Context, dgst distribution.Digest) error {
	blobPath := d.getBlobPath(dgst)
	_, err := d.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(blobPath),
	})
	if err != nil {
		// According to S3 docs, DeleteObject is idempotent. It succeeds even if the key doesn't exist.
		// So, we don't typically need to check for NoSuchKey here.
		// However, other errors (permissions, etc.) should be reported.
		return fmt.Errorf("failed to delete s3 object %s: %w", blobPath, err)
	}
	return nil
}

// --- Upload Operations Implementation (Local Temp File Approach) ---

// StartUpload initiates a resumable upload session by creating a temporary local file.
func (d *driver) StartUpload(ctx context.Context, repoName distribution.RepositoryName) (uploadID string, err error) {
	ourUploadID := uuid.NewString()

	// Create a temporary file to buffer the upload
	// Pattern: "s3upload-<uuid>-*"
	tempFile, err := ioutil.TempFile(d.tempDir, fmt.Sprintf("s3upload-%s-*", ourUploadID))
	if err != nil {
		return "", fmt.Errorf("failed to create temporary upload file: %w", err)
	}

	// Create and store the initial state
	state := &localUploadState{
		filePath:  tempFile.Name(),
		totalSize: 0,
		file:      tempFile, // Keep the file handle open
	}

	d.uploadsLock.Lock()
	d.activeUploads[ourUploadID] = state
	d.uploadsLock.Unlock()

	// Log the creation for debugging
	// log.Printf("Started local upload %s, temp file: %s", ourUploadID, state.filePath)

	return ourUploadID, nil
}

// PutUploadChunk writes a chunk of data to the temporary local file.
func (d *driver) PutUploadChunk(ctx context.Context, ourUploadID string, offset int64, chunk io.Reader) (bytesWritten int64, err error) {
	d.uploadsLock.RLock()
	state, ok := d.activeUploads[ourUploadID]
	d.uploadsLock.RUnlock()

	if !ok {
		return 0, distribution.UploadNotFoundError{UploadID: ourUploadID}
	}

	// Validate offset
	if offset != state.totalSize {
		return 0, distribution.InvalidOffsetError{UploadID: ourUploadID, Offset: offset}
	}

	// Write the chunk to the temporary file
	// Note: We don't need to seek because we assume chunks arrive sequentially.
	// If seeking were required, we'd need to manage the file handle differently.
	written, err := io.Copy(state.file, chunk)
	if err != nil {
		// Attempt cleanup on write error?
		// d.cleanupUpload(ourUploadID, state) // Be careful with locking here
		return 0, fmt.Errorf("failed to write chunk to temp file %s for upload %s: %w", state.filePath, ourUploadID, err)
	}

	// Update the total size in the state
	// Lock for writing to the state map value (though modifying the struct field itself might be atomic for int64)
	// A safer approach might involve locking around the state modification.
	// For simplicity here, assuming concurrent PutUploadChunk calls for the *same* uploadID are unlikely
	// or handled by higher layers. If they are possible, proper locking around state.totalSize update is needed.
	// Let's add a lock for safety:
	d.uploadsLock.Lock()
	state.totalSize += written // Update size *after* successful write
	d.uploadsLock.Unlock()

	// log.Printf("Wrote %d bytes to upload %s, new offset: %d", written, ourUploadID, state.totalSize)

	return written, nil
}

// GetUploadProgress retrieves the current progress (offset) from the local state.
func (d *driver) GetUploadProgress(ctx context.Context, ourUploadID string) (offset int64, err error) {
	d.uploadsLock.RLock()
	state, ok := d.activeUploads[ourUploadID]
	d.uploadsLock.RUnlock()

	if !ok {
		return 0, distribution.UploadNotFoundError{UploadID: ourUploadID}
	}

	// Return the tracked size from the state
	return state.totalSize, nil
}

// AbortUpload cancels an ongoing upload by closing and deleting the temporary file.
func (d *driver) AbortUpload(ctx context.Context, ourUploadID string) error {
	d.uploadsLock.Lock() // Full lock to safely delete from map
	state, ok := d.activeUploads[ourUploadID]
	if ok {
		delete(d.activeUploads, ourUploadID) // Remove from map first
	}
	d.uploadsLock.Unlock()

	if !ok {
		return nil // Idempotent: If not found, consider it already aborted/finished
	}

	// Cleanup the temporary file (close and delete)
	return d.cleanupUpload(ourUploadID, state)
}

// FinishUpload completes an upload by uploading the temporary file content to S3 using PutObject.
func (d *driver) FinishUpload(ctx context.Context, ourUploadID string, finalDigest distribution.Digest) error {
	d.uploadsLock.Lock() // Full lock to safely delete from map
	state, ok := d.activeUploads[ourUploadID]
	if ok {
		delete(d.activeUploads, ourUploadID) // Remove from map first
	}
	d.uploadsLock.Unlock()

	if !ok {
		return distribution.UploadNotFoundError{UploadID: ourUploadID}
	}

	// Ensure file is closed before reading/uploading and cleanup
	if err := state.file.Close(); err != nil {
		// Log error but attempt cleanup anyway
		fmt.Printf("Warning: Failed to close temp file %s for upload %s before finish: %v\n", state.filePath, ourUploadID, err)
		// Attempt to remove the temp file even if close failed
		_ = os.Remove(state.filePath)
		return fmt.Errorf("failed to close temp file before finalizing upload %s: %w", ourUploadID, err)
	}

	// Re-open the file for reading
	fileReader, err := os.Open(state.filePath)
	if err != nil {
		_ = os.Remove(state.filePath) // Cleanup on error
		return fmt.Errorf("failed to re-open temp file %s for reading: %w", state.filePath, err)
	}
	defer fileReader.Close()        // Ensure reader is closed
	defer os.Remove(state.filePath) // Schedule final cleanup

	// Upload the entire content using PutObject
	finalBlobPath := d.getBlobPath(finalDigest)
	_, err = d.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(finalBlobPath),
		Body:   fileReader, // Stream the temp file content
		// ContentLength: aws.Int64(state.totalSize), // Optional but recommended for PutObject
	})

	if err != nil {
		// Note: Temp file will be removed by the deferred os.Remove
		return fmt.Errorf("failed to put final s3 object %s from temp file %s: %w", finalBlobPath, state.filePath, err)
	}

	// log.Printf("Finished upload %s, uploaded %s from %s", ourUploadID, finalBlobPath, state.filePath)

	// TODO: Digest Verification? Could calculate digest from temp file before upload
	// and compare with finalDigest. If mismatch, return error before PutObject.

	return nil
}

// cleanupUpload closes and removes the temporary file associated with an upload state.
func (d *driver) cleanupUpload(uploadID string, state *localUploadState) error {
	var closeErr, removeErr error

	if state.file != nil {
		// log.Printf("Closing temp file %s for upload %s", state.filePath, uploadID)
		closeErr = state.file.Close()
		state.file = nil // Prevent double close
	}
	if state.filePath != "" {
		// log.Printf("Removing temp file %s for upload %s", state.filePath, uploadID)
		removeErr = os.Remove(state.filePath)
	}

	if closeErr != nil {
		return fmt.Errorf("failed to close temp file %s: %w", state.filePath, closeErr)
	}
	if removeErr != nil && !os.IsNotExist(removeErr) { // Ignore error if file already gone
		return fmt.Errorf("failed to remove temp file %s: %w", state.filePath, removeErr)
	}
	return nil
}

// GetManifest retrieves a manifest identified by its digest.
func (d *driver) GetManifest(ctx context.Context, dgst distribution.Digest) (io.ReadCloser, error) {
	manifestPath := d.getManifestPath(dgst)
	resp, err := d.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(manifestPath),
	})
	if err != nil {
		if isS3NotFoundError(err) {
			// OCI spec often expects specific errors for manifests vs blobs, but PathNotFound is generic here.
			// Consider returning a more specific ManifestNotFound error if defined in distribution pkg.
			return nil, distribution.PathNotFoundError{Path: manifestPath}
		}
		return nil, fmt.Errorf("failed to get s3 manifest object %s: %w", manifestPath, err)
	}
	return resp.Body, nil
}

// PutManifest uploads a manifest, identified by its digest.
func (d *driver) PutManifest(ctx context.Context, dgst distribution.Digest, content io.Reader) (bytesWritten int64, err error) {
	manifestPath := d.getManifestPath(dgst)
	_, err = d.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(manifestPath),
		Body:   content,
		// Consider setting ContentType (e.g., application/vnd.oci.image.manifest.v1+json)
	})
	if err != nil {
		return 0, fmt.Errorf("failed to put s3 manifest object %s: %w", manifestPath, err)
	}
	// PutObjectOutput doesn't contain the size. Return 0.
	return 0, nil
}

// StatManifest retrieves information about a manifest.
func (d *driver) StatManifest(ctx context.Context, dgst distribution.Digest) (distribution.FileInfo, error) {
	manifestPath := d.getManifestPath(dgst)
	resp, err := d.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(manifestPath),
	})
	if err != nil {
		if isS3NotFoundError(err) {
			return distribution.FileInfo{}, distribution.PathNotFoundError{Path: manifestPath}
		}
		return distribution.FileInfo{}, fmt.Errorf("failed to head s3 manifest object %s: %w", manifestPath, err)
	}

	modTime := time.Time{}
	if resp.LastModified != nil {
		modTime = *resp.LastModified
	}

	return distribution.FileInfo{
		Path:    manifestPath,
		Size:    aws.ToInt64(resp.ContentLength),
		ModTime: modTime,
		IsDir:   false,
		Digest:  dgst,
	}, nil
}

// DeleteManifest removes a manifest.
func (d *driver) DeleteManifest(ctx context.Context, dgst distribution.Digest) error {
	manifestPath := d.getManifestPath(dgst)
	_, err := d.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(manifestPath),
	})
	if err != nil {
		// DeleteObject is idempotent. Report only unexpected errors.
		return fmt.Errorf("failed to delete s3 manifest object %s: %w", manifestPath, err)
	}
	return nil
}

// ResolveTag retrieves the digest associated with a tag in a repository.
// It reads the content of the tag object, which should be the manifest digest string.
func (d *driver) ResolveTag(ctx context.Context, repoName distribution.RepositoryName, tagName string) (distribution.Digest, error) {
	tagPath := d.getTagPath(repoName, tagName)
	resp, err := d.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(tagPath),
	})
	if err != nil {
		if isS3NotFoundError(err) {
			return "", distribution.TagNotFoundError{Repository: repoName, Tag: tagName}
		}
		return "", fmt.Errorf("failed to get s3 tag object %s: %w", tagPath, err)
	}
	defer resp.Body.Close()

	// Read the digest string from the object body
	digestBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read tag object body %s: %w", tagPath, err)
	}
	digestStr := string(digestBytes)

	// Assume digestStr is a valid distribution.Digest string.
	// Validation should happen at a higher level or upon use if necessary.
	// The distribution.Digest type itself might just be a string alias.
	dgst := distribution.Digest(digestStr)

	// Basic validation (optional, depends on Digest definition)
	if err := dgst.Validate(); err != nil { // Assuming Digest has a Validate method
		return "", fmt.Errorf("invalid digest format found in tag object %s: %w", tagPath, err)
	}

	return dgst, nil
}

// GetTags lists all tags in a repository by listing objects under the repository's _tags prefix.
func (d *driver) GetTags(ctx context.Context, repoName distribution.RepositoryName) ([]string, error) {
	tagsPrefix := path.Join(d.config.Prefix, "repositories", repoName.String(), "_tags") + "/" // Ensure trailing slash for prefix listing

	var tags []string
	paginator := s3.NewListObjectsV2Paginator(d.s3Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(d.config.Bucket),
		Prefix: aws.String(tagsPrefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list s3 objects for tags in %s: %w", repoName, err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			// Extract tag name from the key (part after the prefix)
			if len(key) > len(tagsPrefix) {
				tagName := key[len(tagsPrefix):]
				// Avoid including potential directory markers if any exist
				if tagName != "" && !strings.Contains(tagName, "/") {
					tags = append(tags, tagName)
				}
			}
		}
	}

	return tags, nil
}

// TagManifest associates a tag with a manifest digest in a repository.
// It creates or overwrites an S3 object where the key is the tag path and the body is the digest string.
func (d *driver) TagManifest(ctx context.Context, repoName distribution.RepositoryName, tagName string, dgst distribution.Digest) error {
	tagPath := d.getTagPath(repoName, tagName)
	digestStr := dgst.String()

	_, err := d.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(tagPath),
		Body:   strings.NewReader(digestStr),
		// Consider setting ContentType: "text/plain" or similar
	})
	if err != nil {
		return fmt.Errorf("failed to put s3 tag object %s: %w", tagPath, err)
	}
	return nil
}

// UntagManifest removes a tag association in a repository by deleting the corresponding tag object.
func (d *driver) UntagManifest(ctx context.Context, repoName distribution.RepositoryName, tagName string) error {
	tagPath := d.getTagPath(repoName, tagName)
	_, err := d.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(d.config.Bucket),
		Key:    aws.String(tagPath),
	})
	if err != nil {
		// DeleteObject is idempotent, report only unexpected errors.
		// We don't need to return TagNotFoundError if it doesn't exist.
		return fmt.Errorf("failed to delete s3 tag object %s: %w", tagPath, err)
	}
	return nil
}

// --- Utility Functions (Consider moving to a separate file if they grow) ---

// isS3NotFoundError checks if an error is equivalent to S3 NoSuchKey or NotFound (generic).
// Note: Error handling in aws-sdk-go-v2 uses errors.As to check for specific API error types.
func isS3NotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check for specific S3 error types
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound // NotFound is often returned by HeadObject
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	// Some SDK versions or operations might wrap differently, add more checks if needed.
	// Basic string check as a fallback (less reliable)
	// if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "NotFound") {
	// 	return true
	// }
	return false
}
