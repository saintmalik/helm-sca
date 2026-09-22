// Package version holds build-time identity for helm-sca.
// GoReleaser / `go build -ldflags` override these via -X.
package version

import "strings"

// Version is the semver string without a leading "v" (e.g. "0.0.1").
// Defaults to "dev" for local builds that skip ldflags.
var Version = "dev"

// Commit is the short git commit hash, if injected at build time.
var Commit = "none"

// Date is the build date (UTC), if injected at build time.
var Date = "unknown"

// String returns a human-readable version line for `helm-sca version`.
func String() string {
	v := Version
	if v == "" {
		v = "dev"
	}
	if v != "dev" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if Commit != "" && Commit != "none" {
		return "helm-sca " + v + " (" + Commit + ")"
	}
	return "helm-sca " + v
}
