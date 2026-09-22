package inventory

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	digestSuffix = regexp.MustCompile(`@sha256:[A-Fa-f0-9]{64}$`)
	tagSuffix    = regexp.MustCompile(`:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// NormalizeImageRef trims whitespace/quotes and drops empty placeholders.
func NormalizeImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.Trim(ref, `"'`)
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == "null" || strings.Contains(ref, "{{") {
		return ""
	}
	return ref
}

// RepoKey returns a de-duplication key (repository without tag/digest).
func RepoKey(ref string) string {
	ref = NormalizeImageRef(ref)
	if ref == "" {
		return ""
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > 0 {
		// Avoid treating registry port as a tag (e.g. localhost:5000/foo).
		if strings.Contains(ref[i:], "/") {
			return ref
		}
		return ref[:i]
	}
	return ref
}

// HasDigest reports whether the ref pins an image digest.
func HasDigest(ref string) bool {
	return digestSuffix.MatchString(ref)
}

// ConfidenceRank returns a comparable rank (higher is better).
func ConfidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Dedupe merges findings, preferring higher confidence and digest-pinned refs.
func Dedupe(findings []ImageFinding) []ImageFinding {
	best := map[string]ImageFinding{}
	order := []string{}

	for _, f := range findings {
		name := NormalizeImageRef(f.Name)
		if name == "" {
			continue
		}
		f.Name = name
		key := RepoKey(name)
		if key == "" {
			key = name
		}
		existing, ok := best[key]
		if !ok {
			best[key] = f
			order = append(order, key)
			continue
		}
		if shouldReplace(existing, f) {
			best[key] = f
		}
	}

	out := make([]ImageFinding, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

func shouldReplace(old, neu ImageFinding) bool {
	or, nr := ConfidenceRank(old.Confidence), ConfidenceRank(neu.Confidence)
	if nr != or {
		return nr > or
	}
	od, nd := HasDigest(old.Name), HasDigest(neu.Name)
	if nd != od {
		return nd
	}
	// Prefer tagged over bare repo at same confidence.
	if tagSuffix.MatchString(neu.Name) && !tagSuffix.MatchString(old.Name) && !HasDigest(old.Name) {
		return true
	}
	return false
}

// JoinImage builds repository:tag when both parts are present.
func JoinImage(repository, tag string) string {
	repository = NormalizeImageRef(repository)
	tag = strings.TrimSpace(tag)
	if repository == "" {
		return ""
	}
	if tag == "" || strings.Contains(tag, "{{") {
		return repository
	}
	if strings.HasPrefix(tag, "sha256:") {
		return repository + "@" + tag
	}
	return fmt.Sprintf("%s:%s", repository, tag)
}

// BaseName returns the last path segment of an image (for display).
func BaseName(ref string) string {
	ref = NormalizeImageRef(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > 0 && strings.Contains(ref[:i], "/") {
		ref = ref[:i]
	}
	return path.Base(ref)
}
