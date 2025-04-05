package storage // This package now only contains the factory

import (
	"fmt"

	"github.com/HammerMeetNail/marina-distribution/internal/storage/filesystem"
	s3 "github.com/HammerMeetNail/marina-distribution/internal/storage/s3" // Import S3 driver
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
	// Import other driver packages here when they are implemented
	// "github.com/HammerMeetNail/marina-distribution/internal/storage/gcs"
)

// NewDriver creates a new storage driver instance based on the provided configuration.
func NewDriver(config distribution.Config) (distribution.StorageDriver, error) {
	// Validate the configuration first
	// Note: Validation is now defined on distribution.Config in pkg/distribution/storage.go
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("storage configuration validation failed: %w", err)
	}

	// Instantiate the driver based on the type
	switch config.Type {
	case distribution.FilesystemDriverType:
		// Pass the specific filesystem config to its constructor
		// filesystem.NewDriver now expects distribution.FilesystemConfig
		return filesystem.NewDriver(config.Filesystem)
	case distribution.S3DriverType:
		// Instantiate the S3 driver
		return s3.NewDriver(config.S3)
	case distribution.GCSDriverType:
		// Placeholder for GCS driver instantiation
		// return gcs.NewDriver(config.GCS)
		return nil, fmt.Errorf("gcs storage driver is not yet implemented")
	default:
		// This case should technically be caught by config.Validate(),
		// but handle defensively.
		return nil, fmt.Errorf("unsupported storage driver type: %s", config.Type)
	}
}
