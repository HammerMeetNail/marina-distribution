package main

import (
	"flag" // Import the flag package
	"log"
	"net/http"
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

	// Create storage configuration based on flags
	// For now, we only support filesystem, hardcoding the type.
	// A more advanced setup might use a config file (e.g., YAML) parsed with Viper.
	storageConfig := distribution.Config{
		Type: distribution.FilesystemDriverType,
		Filesystem: distribution.FilesystemConfig{
			RootDirectory: *storagePath,
		},
		// Add placeholders for other configs if needed later
	}

	// Initialize storage driver using the factory
	storageDriver, err := storage.NewDriver(storageConfig)
	if err != nil {
		log.Fatalf("Failed to initialize storage driver: %v", err)
	}
	log.Printf("Using %s storage driver at %s", storageConfig.Type, storageConfig.Filesystem.RootDirectory)

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
