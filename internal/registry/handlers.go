package registry

import (
	"log"
	"net/http"
)

// BaseV2Handler handles requests to the /v2/ endpoint.
// It confirms the registry implements the OCI Distribution Spec.
func BaseV2Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// Strictly speaking, the spec only defines GET for /v2/,
		// but registries often use it for auth checks with other methods.
		// For now, we only allow GET. Consider returning 405 Method Not Allowed later.
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		log.Printf("Received non-GET request for /v2/: %s", r.Method)
		return
	}

	// According to the spec, this header is optional and clients SHOULD NOT depend on it.
	// However, it's common practice to include it.
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
	// Spec doesn't require a body, but some clients might expect an empty JSON object.
	// Sending empty body for now.
	w.Write([]byte(""))
	log.Println("Handled GET /v2/ request successfully.")
}
