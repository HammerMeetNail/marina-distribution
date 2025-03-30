package registry

import (
	"context"       // Add context import
	"encoding/json" // Add json import
	"errors"        // Re-add errors import
	"fmt"           // Add fmt import
	"io"            // Add io import
	"log"
	"os"
	"sort"    // Add sort import
	"strings" // Add strings import

	"github.com/HammerMeetNail/marina-distribution/internal/storage"
	"github.com/HammerMeetNail/marina-distribution/pkg/distribution"
	digest "github.com/opencontainers/go-digest"                 // Import go-digest
	"github.com/opencontainers/image-spec/specs-go"              // Import base specs package
	imagespec "github.com/opencontainers/image-spec/specs-go/v1" // Keep v1 alias
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

	foundReferrers := make(map[distribution.Digest]imagespec.Descriptor)

	// --- 1. Scan manifests for subject match ---
	allManifestDigests, err := reg.driver.ListManifestDigests(ctx, repoName) // repoName ignored by current driver
	if err != nil {
		reg.log.Printf("Error listing manifest digests: %v", err)
		// Return empty index on error listing manifests? Or return error?
		// Let's return error for now.
		return nil, false, fmt.Errorf("failed to list manifests: %w", err)
	}

	reg.log.Printf("Scanning %d potential manifest digests globally.", len(allManifestDigests))
	for _, dgst := range allManifestDigests {
		reg.log.Printf("Checking manifest: %s", dgst)
		// Fetch manifest content
		reader, err := reg.driver.GetManifest(ctx, dgst)
		if err != nil {
			reg.log.Printf("Error fetching manifest %s during scan: %v", dgst, err)
			continue // Skip this manifest
		}
		manifestBytes, readErr := io.ReadAll(reader)
		reader.Close() // Close immediately after reading
		if readErr != nil {
			reg.log.Printf("Error reading manifest %s during scan: %v", dgst, readErr)
			continue // Skip this manifest
		}

		// Unmarshal just enough to check the subject field
		var manifest struct {
			Subject      *imagespec.Descriptor `json:"subject"`
			MediaType    string                `json:"mediaType"` // Needed for descriptor
			Size         int64                 // Calculated below
			Annotations  map[string]string     `json:"annotations"`  // Needed for descriptor
			ArtifactType string                `json:"artifactType"` // Needed for artifactType calc
			Config       imagespec.Descriptor  `json:"config"`       // Needed for artifactType calc
		}
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			reg.log.Printf("Warning: Could not unmarshal manifest %s to check subject: %v", dgst, err)
			continue
		}

		// Check if subject matches
		if manifest.Subject != nil {
			manifestSubjectDigestStr := manifest.Subject.Digest.String()
			reg.log.Printf("Manifest %s has subject: %s", dgst, manifestSubjectDigestStr)
			// Parse the digest from the manifest's subject field into our internal type
			manifestSubjectDigest := distribution.Digest(manifestSubjectDigestStr)
			// Validate the parsed digest before comparing
			if err := manifestSubjectDigest.Validate(); err == nil {
				if manifestSubjectDigest == subjectDigest {
					reg.log.Printf("MATCH FOUND: Referrer %s points to subject %s", dgst, subjectDigest)
					// Create descriptor
					artifactType, _ := getArtifactTypeFromManifest(manifestBytes) // Ignore error here

					// Parse the digest string into digest.Digest type for the descriptor
					parsedDigest := digest.Digest(dgst.String())
					if err := parsedDigest.Validate(); err != nil {
						reg.log.Printf("Warning: Invalid digest %s for descriptor, skipping.", dgst.String())
						continue
					}

					desc := imagespec.Descriptor{
						MediaType:    manifest.MediaType,
						Size:         int64(len(manifestBytes)),
						Digest:       parsedDigest, // Use the parsed digest.Digest type
						ArtifactType: artifactType,
						Annotations:  manifest.Annotations,
					}
					// Use the referrer's digest as the key to handle potential duplicates from tag schema later (if re-enabled)
					if _, exists := foundReferrers[dgst]; !exists {
						foundReferrers[dgst] = desc
					} else {
						reg.log.Printf("Warning: Duplicate referrer digest %s encountered during scan.", dgst)
					}
				}
			} else {
				reg.log.Printf("Warning: Invalid digest format in subject field of manifest %s: %v", dgst, err)
			}
		} else {
			reg.log.Printf("Manifest %s has no subject field.", dgst)
		}
	}

	// --- 2. Check tag schema fallback ---
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
		} else if !errors.As(err, &storage.TagNotFoundError{}) { // This line requires 'errors' import
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
