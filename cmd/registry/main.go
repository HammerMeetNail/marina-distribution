package main

import (
	"log"
	"net/http"
	"time"

	"github.com/HammerMeetNail/marina-distribution/internal/registry"
	"github.com/HammerMeetNail/marina-distribution/internal/storage/filesystem"
)

func main() {
	addr := ":5000"                  // Default address and port
	storageRoot := "./registry-data" // Default storage location

	// Initialize storage driver
	storageDriver, err := filesystem.NewDriver(storageRoot)
	if err != nil {
		log.Fatalf("Failed to initialize filesystem storage driver at %s: %v", storageRoot, err)
	}
	log.Printf("Using filesystem storage driver at %s", storageRoot)

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

	// Delete handlers
	mux.HandleFunc("DELETE /v2/{name}/manifests/{reference}", reg.DeleteManifestHandler)
	mux.HandleFunc("DELETE /v2/{name}/blobs/{digest}", reg.DeleteBlobHandler)

	// TODO: Add handlers for other endpoints (referrers)

	log.Printf("Starting OCI Distribution Registry server on %s", addr)

	// Start the HTTP server
	server := &http.Server{
		Addr:    addr,
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
