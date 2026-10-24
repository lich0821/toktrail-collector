package distribution

import "testing"

func TestParseVersionValid(t *testing.T) {
	for _, s := range []string{
		"v0.0.0", "v1.2.3", "v10.20.30", "v0.1.0-test.1", "v1.0.0-alpha.1", "v1.0.0-rc.1",
		"v2147483647.0.0", "v0.2147483647.0", "v0.0.2147483647",
		"v1.0.0-99999999999999999999",
	} {
		if _, err := ParseVersion(s); err != nil {
			t.Errorf("ParseVersion(%q) unexpected error: %v", s, err)
		}
	}
}

func TestParseVersionInvalid(t *testing.T) {
	for _, s := range []string{
		"", "dev", "1.2.3", "v1.2", "v1.2.3.4", "v01.2.3", "v1.02.3", "v1.2.03",
		"v1.2.3-", "v 1.2.3", "v1.2.x", "v1..2", "v1.2.3-pre!", "v1.2.3-pre..1",
		"v1.2.3-pre_1", "v99999999999999999999.0.0", "v1.2.3-pre-with-dots..",
		"v2147483648.0.0", "v0.2147483648.0", "v0.0.2147483648",
	} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q) accepted invalid version", s)
		}
	}
}

func TestParseVersionLengthLimits(t *testing.T) {
	long := "v1.2.3-" + manyChars('a', maxVersionLen)
	if _, err := ParseVersion(long); err == nil {
		t.Error("oversized version accepted")
	}
	fits := "v1.2.3-" + manyChars('a', maxVersionLen-len("v1.2.3-"))
	if _, err := ParseVersion(fits); err != nil {
		t.Errorf("max-length version rejected: %v", err)
	}
}

func manyChars(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "v1.0.0", 0},
		{"v1.0.0", "v2.0.0", -1},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.0.0", "v1.0.1", -1},
		{"v1.0.0", "v1.0.0-rc.1", 1}, // release > prerelease
		{"v1.0.0-alpha", "v1.0.0-beta", -1},
		{"v1.0.0-alpha.1", "v1.0.0-alpha.2", -1},
		{"v1.0.0-alpha.2", "v1.0.0-alpha.10", -1},
		{"v1.0.0-alpha.1", "v1.0.0-alpha.beta", -1}, // numeric < alphanumeric
		{"v1.0.0-alpha.1.2", "v1.0.0-alpha.1", 1},   // more identifiers > fewer
		{"v1.0.0-2", "v1.0.0-10", -1},
		// SemVer numeric identifiers beyond int64 range:
		{"v1.0.0-99999999999999999999", "v1.0.0-100000000000000000000", -1},  // 20 digits < 21 digits
		{"v1.0.0-100000000000000000000", "v1.0.0-99999999999999999999", 1},   // 21 digits > 20 digits
		{"v1.0.0-100000000000000000000", "v1.0.0-100000000000000000001", -1}, // same length lexical
		{"v1.0.0-100000000000000000000", "v1.0.0-alpha", -1},                 // numeric < alphanumeric
		{"v1.0.0-alpha", "v1.0.0-100000000000000000000", 1},                  // alphanumeric > numeric
		{"v1.0.0-100000000000000000000", "v1.0.0-100000000000000000000", 0},  // identical
		{"v2147483647.0.0", "v2147483647.0.0", 0},
		{"v2147483646.0.0", "v2147483647.0.0", -1},
	}
	for _, c := range cases {
		a, errA := ParseVersion(c.a)
		b, errB := ParseVersion(c.b)
		if errA != nil || errB != nil {
			t.Fatalf("parse %q/%q: %v %v", c.a, c.b, errA, errB)
		}
		if got := CompareVersions(a, b); got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionRoundTrip(t *testing.T) {
	for _, s := range []string{"v1.2.3", "v0.1.0-test.1"} {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", s, err)
		}
		if v.String() != s {
			t.Errorf("round trip: got %q, want %q", v.String(), s)
		}
	}
}
