package distribution

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxVersionLen caps version string input before parsing.
const maxVersionLen = 64

// Version is a parsed SemVer release version: vMAJOR.MINOR.PATCH[-PRERELEASE].
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

func (v Version) String() string {
	if v.Prerelease != "" {
		return fmt.Sprintf("v%d.%d.%d-%s", v.Major, v.Minor, v.Patch, v.Prerelease)
	}
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseVersion parses a strict SemVer string with a leading 'v'.
//
// Rules:
//   - Must start with 'v' followed by non-negative integers MAJOR.MINOR.PATCH.
//   - Leading zeros on numeric identifiers are rejected (e.g. v01.0.0).
//   - Optional prerelease after a hyphen: dot-separated identifiers made of
//     [0-9A-Za-z-], with leading zeros rejected on purely numeric identifiers.
//   - Build metadata (+...) is not accepted: releases are content-addressed
//     by signature and hash, not by opaque build metadata tags.
//   - Input length is bounded.
func ParseVersion(s string) (Version, error) {
	if len(s) == 0 {
		return Version{}, errors.New("version is empty")
	}
	if len(s) > maxVersionLen {
		return Version{}, fmt.Errorf("version length %d exceeds max %d", len(s), maxVersionLen)
	}
	if s[0] != 'v' {
		return Version{}, fmt.Errorf("version %q must start with 'v'", s)
	}
	rest := s[1:]
	prerelease := ""
	if idx := strings.IndexByte(rest, '-'); idx >= 0 {
		prerelease = rest[idx+1:]
		rest = rest[:idx]
		if prerelease == "" {
			return Version{}, fmt.Errorf("version %q has empty prerelease", s)
		}
		if err := validatePrerelease(prerelease); err != nil {
			return Version{}, fmt.Errorf("version %q prerelease: %w", s, err)
		}
	}

	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q must have exactly MAJOR.MINOR.PATCH", s)
	}
	major, err := parseNumericPart(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("version %q major: %w", s, err)
	}
	minor, err := parseNumericPart(parts[1])
	if err != nil {
		return Version{}, fmt.Errorf("version %q minor: %w", s, err)
	}
	patch, err := parseNumericPart(parts[2])
	if err != nil {
		return Version{}, fmt.Errorf("version %q patch: %w", s, err)
	}

	return Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
	}, nil
}

func parseNumericPart(p string) (int, error) {
	if p == "" {
		return 0, errors.New("empty")
	}
	if len(p) > 1 && p[0] == '0' {
		return 0, fmt.Errorf("leading zero in %q", p)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return 0, fmt.Errorf("non-digit in %q", p)
		}
	}
	n, err := strconv.ParseInt(p, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func validatePrerelease(pre string) error {
	for _, id := range strings.Split(pre, ".") {
		if id == "" {
			return errors.New("empty identifier in prerelease")
		}
		numeric := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			switch {
			case c >= '0' && c <= '9':
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-':
				numeric = false
			default:
				return fmt.Errorf("invalid character %q in prerelease identifier %q", c, id)
			}
		}
		if numeric && len(id) > 1 && id[0] == '0' {
			return fmt.Errorf("leading zero in numeric prerelease identifier %q", id)
		}
	}
	return nil
}

// CompareVersions returns -1 if a < b, 0 if a == b, +1 if a > b according to
// the SemVer 2.0.0 specification (§11).
func CompareVersions(a, b Version) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	// A normal version has greater precedence than a prerelease version.
	if a.Prerelease == "" && b.Prerelease != "" {
		return 1
	}
	if a.Prerelease != "" && b.Prerelease == "" {
		return -1
	}
	if a.Prerelease == b.Prerelease {
		return 0
	}
	// Both have prereleases: compare dot-separated identifiers.
	aParts := strings.Split(a.Prerelease, ".")
	bParts := strings.Split(b.Prerelease, ".")
	n := len(aParts)
	if len(bParts) < n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		ap, bp := aParts[i], bParts[i]
		if ap == bp {
			continue
		}
		aIsNum := isDigits(ap)
		bIsNum := isDigits(bp)
		switch {
		case aIsNum && bIsNum:
			if len(ap) != len(bp) {
				if len(ap) < len(bp) {
					return -1
				}
				return 1
			}
			if ap < bp {
				return -1
			}
			if ap > bp {
				return 1
			}
		case aIsNum && !bIsNum:
			return -1 // Numeric identifiers have lower precedence.
		case !aIsNum && bIsNum:
			return 1
		default:
			if ap < bp {
				return -1
			}
			return 1
		}
	}
	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}

func isDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
