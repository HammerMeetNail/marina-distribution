package registry

import (
	"bytes"         // Re-add bytes import
	"context"       // Add context import
	"encoding/json" // Add json import
	"errors"        // Re-add errors import
	"fmt"           // Add fmt import
	"io"            // Add io import
	"log"
	"os"
	"sort"    // Add sort import
	"strings" // Add strings import

	// Use the storage driver interface from pkg/distribution
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
	"github.com/opencontainers/image-spec/specs-go"              // Import base specs package
	imagespec "github.com/opencontainers/image-spec/specs-go/v1" // Keep v1 alias
)

// Registry provides the core registry application logic,
// coordinating between handlers and the storage driver.
type Registry struct {
	driver distribution.StorageDriver // Use the interface from pkg/distribution
	log    *log.Logger                // Or a more structured logger
}

// NewRegistry creates a new Registry instance.
func NewRegistry(driver distribution.StorageDriver) *Registry { // Expect the interface from pkg/distribution
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

// calculateReferrersTag calculates the tag name based on the subject digest
// according to the OCI distribution spec fallback mechanism.
func calculateReferrersTag(subjectDigest distribution.Digest) (string, error) {
	if err := subjectDigest.Validate(); err != nil {
		return "", fmt.Errorf("invalid subject digest for tag calculation: %w", err)
	}

	// Split digest into algorithm and encoded parts
	parts := strings.SplitN(string(subjectDigest), ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("cannot split digest into algo/encoded: %s", subjectDigest)
	}
	algo := parts[0]
	encoded := parts[1]

	// Truncate algorithm and encoded parts
	if len(algo) > 32 {
		algo = algo[:32]
	}
	if len(encoded) > 64 {
		encoded = encoded[:64]
	}

	// Replace invalid tag characters with '-'
	// Allowed: [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}
	// We need to replace anything else in the combined string.
	// A simple approach is to replace common problematic chars. A more robust
	// approach would use a regex, but let's keep it simple for now.
	// Replace '+' and '=' which appear in the example.
	replacer := strings.NewReplacer("+", "-", "=", "-")
	tag := fmt.Sprintf("%s-%s", replacer.Replace(algo), replacer.Replace(encoded))

	// Further ensure it fits the tag format (basic check)
	if len(tag) > 128 {
		tag = tag[:128]
	}
	// Ensure first char is valid (simplistic check: prepend 't' if needed)
	if len(tag) > 0 && !((tag[0] >= 'a' && tag[0] <= 'z') || (tag[0] >= 'A' && tag[0] <= 'Z') || (tag[0] >= '0' && tag[0] <= '9') || tag[0] == '_') {
		tag = "t" + tag // Prepend 't' if first char is invalid (like '-')
		if len(tag) > 128 {
			tag = tag[:128]
		}
	}

	// TODO: Add more robust validation against the tag regex if needed.

	return tag, nil
}

// getArtifactTypeFromManifest determines the artifactType for a descriptor
// based on the manifest content, according to OCI spec rules.
func getArtifactTypeFromManifest(manifestContent []byte) (string, error) {
	var manifest struct {
		MediaType    string               `json:"mediaType"`
		ArtifactType string               `json:"artifactType"` // OCI Image Manifest field
		Config       imagespec.Descriptor `json:"config"`       // OCI Image Manifest field
	}

	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		// Don't return error, just means we can't determine type from content
		return "", nil // Not an error, just couldn't parse or find fields
	}

	// Rule: Use manifest.artifactType if present
	if manifest.ArtifactType != "" {
		return manifest.ArtifactType, nil
	}

	// Rule: If manifest.artifactType is missing/empty in an image manifest,
	// use the config descriptor's media type.
	// We identify an image manifest by checking if it has a 'config' field.
	// Note: This is a heuristic. A stricter check might involve manifest.MediaType.
	if manifest.Config.MediaType != "" {
		return manifest.Config.MediaType, nil
	}

	// Rule: If artifactType is empty/missing in an index, omit it.
	// We assume if it's not an image manifest (no config field) and no artifactType,
	// it might be an index or other type where artifactType should be omitted.
	return "", nil // Omit artifactType
}

// GetReferrers finds manifests that refer to the given subject digest.
// It returns an OCI Image Index containing descriptors of the referrers,
// a boolean indicating if filtering was applied, and any error.
func (reg *Registry) GetReferrers(ctx context.Context, repoName distribution.RepositoryName, subjectDigest distribution.Digest, artifactTypeFilter string) (*imagespec.Index, bool, error) {
	reg.log.Printf("Core: GetReferrers called for %s/%s (filter: %s)", repoName, subjectDigest, artifactTypeFilter)

	// Referrers are found *only* via the OCI tag schema fallback mechanism.
	// We no longer scan all manifests for a 'subject' field.
	foundReferrers := make(map[distribution.Digest]imagespec.Descriptor)

	// --- Check tag schema fallback ---
	referrersTagName, err := calculateReferrersTag(subjectDigest)
	if err != nil {
		reg.log.Printf("Error calculating referrers tag name for %s: %v", subjectDigest, err)
		// Don't fail, just means we can't check the tag
	} else {
		reg.log.Printf("Checking referrers tag schema: %s/%s", repoName, referrersTagName)
		tagDigest, err := reg.driver.ResolveTag(ctx, repoName, referrersTagName)
		if err == nil {
			// Tag exists
			// Fetch the index manifest pointed to by the tag
			reader, err := reg.driver.GetManifest(ctx, tagDigest)
			if err != nil {
				reg.log.Printf("Error fetching referrers index manifest %s from tag %s: %v", tagDigest, referrersTagName, err)
			} else {
				indexBytes, readErr := io.ReadAll(reader)
				reader.Close()
				if readErr != nil {
					reg.log.Printf("Error reading referrers index manifest %s from tag %s: %v", tagDigest, referrersTagName, readErr)
				} else {
					// Unmarshal the index
					var index imagespec.Index
					if err := json.Unmarshal(indexBytes, &index); err != nil {
						reg.log.Printf("Warning: Could not unmarshal referrers index %s from tag %s: %v", tagDigest, referrersTagName, err)
					} else {
						// Check media type
						if index.MediaType == imagespec.MediaTypeImageIndex {
							reg.log.Printf("Found %d descriptors in referrers tag schema index %s.", len(index.Manifests), tagDigest)
							// Add descriptors from the index, avoiding duplicates
							for _, desc := range index.Manifests {
								// Parse the string digest from the descriptor into our internal type
								descDigest := distribution.Digest(desc.Digest)
								if err := descDigest.Validate(); err != nil {
									reg.log.Printf("Warning: Invalid digest %s found in referrers tag index %s, skipping.", desc.Digest, tagDigest)
									continue // Skip invalid digest
								}

								// Check if we already found this referrer via direct subject scan
								if _, exists := foundReferrers[descDigest]; !exists {
									foundReferrers[descDigest] = desc
								}
							}
						} else {
							reg.log.Printf("Warning: Manifest %s found via tag %s is not an OCI index (mediaType: %s)", tagDigest, referrersTagName, index.MediaType)
						}
					}
				}
			}
		} else if !errors.As(err, &distribution.TagNotFoundError{}) { // Use error type from distribution
			// Log errors other than "tag not found"
			reg.log.Printf("Error resolving referrers tag %s: %v", referrersTagName, err)
		}
	}

	// --- 3. Combine, Filter ---
	// Descriptors are already combined in the foundReferrers map (deduplicated by digest)
	finalDescriptors := make([]imagespec.Descriptor, 0, len(foundReferrers))
	filteringApplied := false

	for _, desc := range foundReferrers {
		// Apply artifactType filter if provided
		if artifactTypeFilter != "" {
			filteringApplied = true // Mark that we attempted filtering
			if desc.ArtifactType == artifactTypeFilter {
				finalDescriptors = append(finalDescriptors, desc)
			}
		} else {
			// No filter, add all
			finalDescriptors = append(finalDescriptors, desc)
		}
	}

	// Sort descriptors by digest for deterministic output (optional but nice)
	sort.Slice(finalDescriptors, func(i, j int) bool {
		return finalDescriptors[i].Digest < finalDescriptors[j].Digest
	})

	// --- 4. Construct OCI Index response ---
	responseIndex := &imagespec.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: imagespec.MediaTypeImageIndex,
		Manifests: finalDescriptors,
	}

	reg.log.Printf("Core: GetReferrers returning index with %d descriptors for %s/%s (filter: %s, applied: %t)",
		len(finalDescriptors), repoName, subjectDigest, artifactTypeFilter, filteringApplied && artifactTypeFilter != "") // Only true if filter was non-empty and applied

	return responseIndex, filteringApplied && artifactTypeFilter != "", nil
}

// updateReferrersTagIndex manages the OCI Image Index manifest used for the
// tag schema fallback mechanism for the Referrers API. It ensures that when
// a manifest (`referrerManifest`) declares a `subjectDigest`, the referrer's
// descriptor is added to the index pointed to by the tag `sha256-<subjectDigest>`.
func (reg *Registry) updateReferrersTagIndex(ctx context.Context, repoName distribution.RepositoryName, subjectDigest distribution.Digest, referrerDescriptor imagespec.Descriptor) error {
	// 1. Calculate the fallback tag name
	referrersTagName, err := calculateReferrersTag(subjectDigest)
	if err != nil {
		// This should ideally not happen if subjectDigest is valid, but handle defensively
		return fmt.Errorf("failed to calculate referrers tag name for subject %s: %w", subjectDigest, err)
	}
	reg.log.Printf("Updating referrers index for subject %s using tag %s", subjectDigest, referrersTagName)

	// 2. Resolve the tag to find the current index digest (if it exists)
	currentIndexDigest, err := reg.driver.ResolveTag(ctx, repoName, referrersTagName)
	var currentIndex imagespec.Index
	currentIndexExists := false
	if err == nil {
		// Tag exists, try to fetch the current index manifest
		reader, getErr := reg.driver.GetManifest(ctx, currentIndexDigest)
		if getErr == nil {
			defer reader.Close()
			indexBytes, readErr := io.ReadAll(reader)
			if readErr == nil {
				if jsonErr := json.Unmarshal(indexBytes, &currentIndex); jsonErr == nil {
					// Successfully fetched and unmarshalled the current index
					if currentIndex.MediaType == imagespec.MediaTypeImageIndex {
						currentIndexExists = true
						reg.log.Printf("Found existing referrers index %s for tag %s", currentIndexDigest, referrersTagName)
					} else {
						reg.log.Printf("Warning: Manifest %s pointed to by referrers tag %s is not an OCI index (mediaType: %s). Creating new index.", currentIndexDigest, referrersTagName, currentIndex.MediaType)
						// Treat as non-existent, will create a new one below
					}
				} else {
					reg.log.Printf("Warning: Failed to unmarshal existing referrers index %s for tag %s: %v. Creating new index.", currentIndexDigest, referrersTagName, jsonErr)
					// Treat as non-existent
				}
			} else {
				reg.log.Printf("Warning: Failed to read existing referrers index %s for tag %s: %v. Creating new index.", currentIndexDigest, referrersTagName, readErr)
				// Treat as non-existent
			}
		} else if !errors.As(getErr, &distribution.PathNotFoundError{}) {
			// Log error if fetching failed for reasons other than not found
			reg.log.Printf("Warning: Failed to fetch existing referrers index %s for tag %s: %v. Creating new index.", currentIndexDigest, referrersTagName, getErr)
			// Treat as non-existent
		}
		// If PathNotFoundError, currentIndexExists remains false, proceed to create new index.

	} else if !errors.As(err, &distribution.TagNotFoundError{}) {
		// Log error if resolving tag failed for reasons other than not found
		reg.log.Printf("Warning: Failed to resolve referrers tag %s: %v. Cannot update index.", referrersTagName, err)
		return fmt.Errorf("failed to resolve existing referrers tag %s: %w", referrersTagName, err) // Return error, cannot proceed
	}

	// 3. Initialize a new index if none exists
	if !currentIndexExists {
		reg.log.Printf("No valid existing referrers index found for tag %s. Creating new index.", referrersTagName)
		currentIndex = imagespec.Index{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			MediaType: imagespec.MediaTypeImageIndex,
			Manifests: []imagespec.Descriptor{}, // Initialize empty slice
		}
	}

	// 4. Add or update the referrer descriptor in the index
	found := false
	for i, existingDesc := range currentIndex.Manifests {
		if existingDesc.Digest == referrerDescriptor.Digest {
			// Update existing entry if needed (e.g., annotations changed)
			// For simplicity, just replace it.
			currentIndex.Manifests[i] = referrerDescriptor
			found = true
			reg.log.Printf("Updated descriptor for %s in referrers index for tag %s", referrerDescriptor.Digest, referrersTagName)
			break
		}
	}
	if !found {
		currentIndex.Manifests = append(currentIndex.Manifests, referrerDescriptor)
		reg.log.Printf("Added descriptor for %s to referrers index for tag %s", referrerDescriptor.Digest, referrersTagName)
	}

	// 5. Marshal the updated index
	updatedIndexBytes, err := json.MarshalIndent(currentIndex, "", "  ") // Use MarshalIndent for readability
	if err != nil {
		return fmt.Errorf("failed to marshal updated referrers index for tag %s: %w", referrersTagName, err)
	}

	// 6. Calculate the digest of the updated index
	// Use SHA256 as the default/standard for index digests
	hashFunc, err := distribution.GetHashFunc(distribution.SHA256)
	if err != nil {
		return fmt.Errorf("failed to get hash function for updated referrers index: %w", err) // Should not happen
	}
	hasher := hashFunc.New()
	hasher.Write(updatedIndexBytes)
	updatedIndexDigest := distribution.NewDigest(distribution.SHA256, hasher)

	// 7. Store the updated index manifest
	_, err = reg.driver.PutManifest(ctx, updatedIndexDigest, bytes.NewReader(updatedIndexBytes))
	if err != nil {
		// Check for digest mismatch, though unlikely here
		if errors.As(err, &distribution.DigestMismatchError{}) {
			reg.log.Printf("Internal Error: Digest mismatch during PutManifest for updated referrers index %s: %v", updatedIndexDigest, err)
		}
		return fmt.Errorf("failed to store updated referrers index %s for tag %s: %w", updatedIndexDigest, referrersTagName, err)
	}
	reg.log.Printf("Stored updated referrers index %s for tag %s", updatedIndexDigest, referrersTagName)

	// 8. Update the tag to point to the new index digest
	err = reg.driver.TagManifest(ctx, repoName, referrersTagName, updatedIndexDigest)
	if err != nil {
		// Log the error, but the index was stored successfully.
		reg.log.Printf("Error updating referrers tag %s to point to new index %s: %v", referrersTagName, updatedIndexDigest, err)
		// Don't return error here, as the primary operation (storing index) succeeded.
	} else {
		reg.log.Printf("Updated referrers tag %s to point to index %s", referrersTagName, updatedIndexDigest)
	}

	return nil // Success
}
