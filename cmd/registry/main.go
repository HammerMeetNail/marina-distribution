package main

import (
	"flag" // Import the flag package
	"fmt"  // Ensure fmt is imported
	"log"
	"net/http"
	"os"      // Import os package to read environment variables
	"strconv" // Import strconv for boolean parsing
	"time"

	"github.com/HammerMeetNail/marina-distribution/internal/registry"
	"github.com/HammerMeetNail/marina-distribution/internal/storage" // Import storage package for the factory
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution" // Import distribution for config types
)

func main() {
	// Define command-line flags
	addr := flag.String("addr", ":5000", "Address and port to listen on")
	storagePath := flag.String("storage-path", "./registry-data", "Path to the registry data directory")

	// Parse the flags
	flag.Parse()

	// Determine storage configuration from environment variables or flags
	var storageConfig distribution.Config
	storageType := os.Getenv("STORAGE_TYPE")

	logMessage := "" // To build a dynamic log message

	switch storageType {
	case string(distribution.S3DriverType):
		log.Println("Configuring S3 storage driver from environment variables...")
		bucket := os.Getenv("S3_BUCKET")
		if bucket == "" {
			log.Fatal("S3_BUCKET environment variable is required for S3 storage")
		}
		forcePathStyle, _ := strconv.ParseBool(os.Getenv("S3_FORCE_PATH_STYLE"))         // Default to false on error
		insecureSkipVerify, _ := strconv.ParseBool(os.Getenv("S3_INSECURE_SKIP_VERIFY")) // Default to false

		storageConfig = distribution.Config{
			Type: distribution.S3DriverType,
			S3: distribution.S3Config{
				Bucket:             bucket,
				Region:             os.Getenv("S3_REGION"),   // Optional, SDK might infer
				Endpoint:           os.Getenv("S3_ENDPOINT"), // Optional, for Minio etc.
				Prefix:             os.Getenv("S3_PREFIX"),   // Optional
				ForcePathStyle:     forcePathStyle,
				InsecureSkipVerify: insecureSkipVerify, // Set from env var
			},
		}
		// Note: AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) are read by the SDK automatically
		logMessage = fmt.Sprintf("Using %s storage driver with bucket %s", storageConfig.Type, storageConfig.S3.Bucket)
		if storageConfig.S3.Endpoint != "" {
			logMessage += fmt.Sprintf(" (endpoint: %s)", storageConfig.S3.Endpoint)
		}

	case string(distribution.FilesystemDriverType):
		fallthrough // Treat filesystem explicitly the same as default
	default:
		log.Println("Configuring filesystem storage driver from flags...")
		storageConfig = distribution.Config{
			Type: distribution.FilesystemDriverType,
			Filesystem: distribution.FilesystemConfig{
				RootDirectory: *storagePath,
			},
		}
		logMessage = fmt.Sprintf("Using %s storage driver at %s", storageConfig.Type, storageConfig.Filesystem.RootDirectory)
	}

	// Initialize storage driver using the factory
	storageDriver, err := storage.NewDriver(storageConfig)
	if err != nil {
		log.Fatalf("Failed to initialize storage driver: %v", err)
	}
	log.Println(logMessage) // Print the configured driver info

	// Use the enhanced http.ServeMux from Go 1.22+
	mux := http.NewServeMux()

	// Create registry instance
	reg := registry.NewRegistry(storageDriver)

	// Register handlers
	mux.HandleFunc("GET /v2/", registry.BaseV2Handler) // Base API endpoint

	// Blob handlers - Use Go 1.22+ method and path parameters
	mux.HandleFunc("GET /v2/{name}/blobs/{digest}", reg.GetBlobHandler)
	mux.HandleFunc("HEAD /v2/{name}/blobs/{digest}", reg.HeadBlobHandler)

	// Manifest handlers
	mux.HandleFunc("GET /v2/{name}/manifests/{reference}", reg.GetManifestHandler)
	mux.HandleFunc("HEAD /v2/{name}/manifests/{reference}", reg.HeadManifestHandler)

	// Blob Upload handlers
	mux.HandleFunc("POST /v2/{name}/blobs/uploads/", reg.StartBlobUploadHandler)
	mux.HandleFunc("GET /v2/{name}/blobs/uploads/{uuid}", reg.GetBlobUploadHandler) // Add GET handler for upload status
	mux.HandleFunc("PATCH /v2/{name}/blobs/uploads/{uuid}", reg.PatchBlobUploadHandler)
	mux.HandleFunc("PUT /v2/{name}/blobs/uploads/{uuid}", reg.PutBlobUploadHandler) // Note: Query params handled in handler

	// Manifest push handler
	mux.HandleFunc("PUT /v2/{name}/manifests/{reference}", reg.PutManifestHandler)

	// Tag listing handler
	mux.HandleFunc("GET /v2/{name}/tags/list", reg.GetTagsHandler)

	// Referrers listing handler
	mux.HandleFunc("GET /v2/{name}/referrers/{digest}", reg.GetReferrersHandler) // Note: Query params handled in handler

	// Delete handlers
	mux.HandleFunc("DELETE /v2/{name}/manifests/{reference}", reg.DeleteManifestHandler)
	mux.HandleFunc("DELETE /v2/{name}/blobs/{digest}", reg.DeleteBlobHandler)

	log.Printf("Starting OCI Distribution Registry server on %s", *addr)

	// Start the HTTP server
	server := &http.Server{
		Addr:    *addr, // Use the flag value
		Handler: mux,
		// Set reasonable timeouts
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second, // Allow longer for potential large blob uploads/downloads
		IdleTimeout:  60 * time.Second,
	}

	err = server.ListenAndServe() // Use = instead of := as err is already declared
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
