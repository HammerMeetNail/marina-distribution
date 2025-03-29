package main

import (
	"log"
	"net/http"

	"github.com/HammerMeetNail/marina-distribution/internal/registry"
)

func main() {
	addr := ":5000" // Default address and port

	// Basic routing using net/http ServeMux
	mux := http.NewServeMux()

	// Register the /v2/ handler
	mux.HandleFunc("/v2/", registry.BaseV2Handler)

	// TODO: Add handlers for other endpoints as they are implemented

	log.Printf("Starting OCI Distribution Registry server on %s", addr)

	// Start the HTTP server
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		// TODO: Add timeouts (ReadTimeout, WriteTimeout, IdleTimeout) for production
	}

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
