package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func StringAny(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func UintAny(v any) (uint64, bool) {
	switch n := v.(type) {
	case json.Number:
		// Strict decimal-integer parsing: rejects fractions, exponents,
		// signs, and values outside uint64 without float64 rounding.
		return ParseUint(n.String())
	case string:
		return ParseUint(strings.TrimSpace(n))
	default:
		return 0, false
	}
}

func ShortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// ValidateModel validates the wire representation without altering a recorded identifier.
func ValidateModel(value any) error {
	if value == nil {
		return nil
	}
	model, ok := value.(string)
	if !ok || !utf8.ValidString(model) || len(model) > 128 || strings.TrimSpace(model) == "" {
		return fmt.Errorf("model must be a nonempty UTF-8 string of at most 128 bytes or null")
	}
	for _, r := range model {
		if unicode.IsControl(r) {
			return fmt.Errorf("model must not contain control characters")
		}
	}
	return nil
}

func ValidateRecord(record Record) error {
	if err := ValidateModel(record["model"]); err != nil {
		return err
	}
	for _, key := range []string{"recordKey", "kind", "occurredAt", "tool", "adapterVersion", "sourceType"} {
		if strings.TrimSpace(StringField(record, key)) == "" {
			return fmt.Errorf("missing %s", key)
		}
	}
	kind := StringField(record, "kind")
	if kind != "delta" && kind != "cumulative" {
		return fmt.Errorf("invalid kind %q", kind)
	}
	if _, err := time.Parse(time.RFC3339, StringField(record, "occurredAt")); err != nil {
		return fmt.Errorf("invalid occurredAt: %w", err)
	}
	for _, key := range []string{"input", "cacheRead", "cacheWrite", "output"} {
		if err := validateDecimalOrNull(record, key); err != nil {
			return err
		}
	}
	return nil
}

func validateDecimalOrNull(record Record, key string) error {
	v, ok := record[key]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s must be decimal string or null", key)
	}
	if _, ok := ParseUint(s); !ok {
		return fmt.Errorf("%s must be decimal string or null", key)
	}
	return nil
}

func IncludeTokens(record Record) (uint64, bool) {
	input, ok1 := DecimalField(record, "input")
	cacheRead, ok2 := DecimalField(record, "cacheRead")
	cacheWrite, ok3 := DecimalField(record, "cacheWrite")
	output, ok4 := DecimalField(record, "output")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return 0, false
	}
	total, ok := AddUint64Checked(input, cacheRead)
	if !ok {
		return 0, false
	}
	total, ok = AddUint64Checked(total, cacheWrite)
	if !ok {
		return 0, false
	}
	total, ok = AddUint64Checked(total, output)
	if !ok {
		return 0, false
	}
	return total, true
}

func ExcludeTokens(record Record) (uint64, bool) {
	input, ok1 := DecimalField(record, "input")
	output, ok2 := DecimalField(record, "output")
	if !ok1 || !ok2 {
		return 0, false
	}
	total, ok := AddUint64Checked(input, output)
	if !ok {
		return 0, false
	}
	return total, true
}

func OptionalInclude(record Record) *uint64 {
	v, ok := IncludeTokens(record)
	if !ok {
		return nil
	}
	return &v
}

func OptionalExclude(record Record) *uint64 {
	v, ok := ExcludeTokens(record)
	if !ok {
		return nil
	}
	return &v
}

func DecimalField(record Record, key string) (uint64, bool) {
	v, ok := record[key]
	if !ok || v == nil {
		return 0, false
	}
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	return ParseUint(s)
}

func ParseUint(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var out uint64
	for idx, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		if idx == 0 && r == '0' && len(s) > 1 {
			return 0, false
		}
		digit := uint64(r - '0')
		if out > (^uint64(0)-digit)/10 {
			return 0, false
		}
		out = out*10 + digit
	}
	return out, true
}

func StringField(record Record, key string) string {
	v, _ := record[key].(string)
	return strings.TrimSpace(v)
}

func OccurredAt(record Record) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, StringField(record, "occurredAt"))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func AddUint64(target **uint64, value uint64) error {
	if *target == nil {
		v := value
		*target = &v
		return nil
	}
	sum, ok := AddUint64Checked(**target, value)
	if !ok {
		return fmt.Errorf("sum %d + %d exceeds uint64", **target, value)
	}
	**target = sum
	return nil
}

func AddUint64Checked(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

func SortedTools(tools map[string]int) []string {
	keys := make([]string, 0, len(tools))
	for key := range tools {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
