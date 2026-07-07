package support

import "github.com/google/uuid"

// RandomID returns prefix followed by a fresh random UUID. Every fixture
// this suite creates (client IDs, subject IDs, resource owners, ...) must
// go through this helper rather than a hardcoded literal — it's what makes
// the single shared Redis container (see redis.go) safe under parallel
// scenario execution: Redis-backed key schemas here are content-addressed
// by values that are unique per scenario only as long as no step
// definition hardcodes an identifier.
func RandomID(prefix string) string {
	return prefix + "-" + uuid.NewString()
}
