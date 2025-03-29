package distribution

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"strings"
)

// Supported digest algorithms
const (
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

// Algorithm identifies the cryptographic algorithm used by a digest.
type Algorithm string

// String returns the string representation of the algorithm.
func (a Algorithm) String() string {
	return string(a)
}

// Available returns true if the algorithm is registered and available.
func (a Algorithm) Available() bool {
	_, ok := digestAlgorithms[a]
	return ok
}

// Hash returns the hash.Hash constructor for the algorithm.
func (a Algorithm) Hash() crypto.Hash {
	if !a.Available() {
		return 0 // Or perhaps panic? Returning 0 is safer for callers.
	}
	return digestAlgorithms[a].hash
}

// Digest represents an OCI content digest.
// It follows the format algorithm:encodedHex.
type Digest string

// Regex for digest format validation.
// algorithm      ::= algorithm-component ( + algorithm-component )*
// algorithm-component ::= [a-z0-9]+
// encoded          ::= [a-fA-F0-9]{32,}
var digestRegex = regexp.MustCompile(`^[a-z0-9]+(?:[.+_][a-z0-9]+)*:[a-fA-F0-9]{32,}$`)

// Validate checks if the digest string is valid according to the OCI spec format
// and if the algorithm is known/supported by this implementation.
func (d Digest) Validate() error {
	s := string(d)
	if !digestRegex.MatchString(s) {
		return fmt.Errorf("invalid digest format: %s", s)
	}
	algo := d.Algorithm()
	if !algo.Available() {
		// While the spec allows unknown algorithms, implementations often restrict them.
		// We will treat unknown algorithms as an error for now for stricter validation.
		return fmt.Errorf("unsupported digest algorithm: %s", algo)
	}
	// TODO: Optionally add length check based on algorithm (e.g., sha256 must be 64 hex chars)
	return nil
}

// Algorithm returns the algorithm part of the digest.
func (d Digest) Algorithm() Algorithm {
	parts := strings.SplitN(string(d), ":", 2)
	if len(parts) != 2 {
		return "" // Should not happen if Validate passes
	}
	return Algorithm(parts[0])
}

// Hex returns the encoded hex part of the digest.
func (d Digest) Hex() string {
	parts := strings.SplitN(string(d), ":", 2)
	if len(parts) != 2 {
		return "" // Should not happen if Validate passes
	}
	return parts[1]
}

// String returns the string representation of the digest.
func (d Digest) String() string {
	return string(d)
}

// NewDigest creates a new Digest string from an algorithm and a hash.Hash object.
func NewDigest(algo Algorithm, h hash.Hash) Digest {
	return Digest(fmt.Sprintf("%s:%s", algo.String(), hex.EncodeToString(h.Sum(nil))))
}

// Verifier provides an interface for verifying digests.
type Verifier interface {
	// Verify compares the current hash against the provided digest.
	Verify(d Digest) error
}

// --- Algorithm Registration ---

type digestAlgorithmInfo struct {
	name string
	hash crypto.Hash
}

var digestAlgorithms = make(map[Algorithm]digestAlgorithmInfo)

// registerDigestAlgorithm adds a supported algorithm. Panics if hash is unavailable.
func registerDigestAlgorithm(a Algorithm, h crypto.Hash) {
	if !h.Available() {
		panic(fmt.Sprintf("hash function for algorithm %q is unavailable", a))
	}
	digestAlgorithms[a] = digestAlgorithmInfo{name: string(a), hash: h}
}

func init() {
	// Register common OCI algorithms
	registerDigestAlgorithm(SHA256, crypto.SHA256)
	registerDigestAlgorithm(SHA512, crypto.SHA512)
}

// GetHashFunc returns the crypto.Hash associated with the algorithm.
// Returns an error if the algorithm is not supported/registered.
func GetHashFunc(algo Algorithm) (crypto.Hash, error) {
	info, ok := digestAlgorithms[algo]
	if !ok {
		return 0, fmt.Errorf("unsupported digest algorithm: %s", algo)
	}
	return info.hash, nil
}
