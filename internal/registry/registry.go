package registry

import (
	"log"
	"os"

	"github.com/HammerMeetNail/marina-distribution/internal/storage"
)

// Registry provides the core registry application logic,
// coordinating between handlers and the storage driver.
type Registry struct {
	driver storage.StorageDriver
	log    *log.Logger // Or a more structured logger
}

// NewRegistry creates a new Registry instance.
func NewRegistry(driver storage.StorageDriver) *Registry {
	// For now, use the standard logger writing to stderr.
	// Could be replaced with a more sophisticated logger later.
	logger := log.New(os.Stderr, "[Registry] ", log.LstdFlags)

	return &Registry{
		driver: driver,
		log:    logger,
	}
}

// TODO: Add methods for handling API requests (e.g., GetBlob, HeadBlob)
// These methods will be called by the handler functions.
