// Package grants stores the collector's local source/input grant config.
//
// A grant is an explicit, user-selected (source, input) pair plus an
// enabled flag. Grants exist ONLY to feed the periodic scheduled
// collection entry (`toktrail periodic`); they never change the manual
// commands, which keep requiring explicit --source/--input flags. There is
// no default scanning: with no enabled grants the periodic entry collects
// nothing and performs zero network requests.
package grants

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"toktrail-collector/internal/source/registry"
)

const configFileName = "grants.json"

// Grant is one explicit local-read grant: a compiled-in adapter source and
// an absolute local input path the user selected for scheduled collection.
type Grant struct {
	Source   string    `json:"source"`
	Input    string    `json:"input"`
	Enabled  bool      `json:"enabled"`
	AddedAt  time.Time `json:"addedAt,omitempty"`
	EditedAt time.Time `json:"editedAt,omitempty"`
}

// Config is the on-disk grant store.
type Config struct {
	Version int     `json:"version"`
	Grants  []Grant `json:"grants"`
}

// Store reads and writes the grant config under a state directory.
type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

func (s Store) Path() string { return filepath.Join(s.dir, configFileName) }

// KnownSources lists the compiled-in adapter source ids. The set is fixed
// at compile time (first version has no dynamic plugins).
func KnownSources() []string {
	return registry.KnownSources()
}

// IsKnownSource reports whether id is a compiled-in adapter source.
func IsKnownSource(id string) bool {
	return registry.IsKnownSource(strings.TrimSpace(id))
}

// ValidateGrant checks a grant before it is persisted: known compiled-in
// source and an absolute input path. Existence/readability of the input is
// checked separately by ValidateInput so callers can distinguish a config
// problem from a runtime one.
func ValidateGrant(source, input string) error {
	source = strings.TrimSpace(source)
	if !IsKnownSource(source) {
		return fmt.Errorf("unknown source %q; compiled-in sources: %s", source, strings.Join(KnownSources(), ", "))
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return errors.New("input path is required")
	}
	if !filepath.IsAbs(input) {
		return fmt.Errorf("input path %q must be absolute", input)
	}
	return nil
}

// ValidateInput checks that the granted input path still exists (and is
// readable for the local adapter). It performs local filesystem checks
// only.
func ValidateInput(input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return errors.New("input path is required")
	}
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("input %q is not accessible: %w", input, err)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return fmt.Errorf("input %q is neither a regular file nor a directory", input)
	}
	return nil
}

func (s Store) Load() (Config, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return Config{Version: 1}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("invalid source grant config %s: %w", s.Path(), err)
	}
	if cfg.Version != 1 {
		return Config{}, fmt.Errorf("unsupported source grant config version %d in %s", cfg.Version, s.Path())
	}
	for idx, grant := range cfg.Grants {
		if err := ValidateGrant(grant.Source, grant.Input); err != nil {
			return Config{}, fmt.Errorf("grant %d: %w", idx, err)
		}
	}
	return cfg, nil
}

func (s Store) save(cfg Config) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	cfg.Version = 1
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}

// Enable upserts a grant as enabled. It validates the grant and the input
// path before writing anything.
func (s Store) Enable(source, input string) (Grant, error) {
	if err := ValidateGrant(source, input); err != nil {
		return Grant{}, err
	}
	if err := ValidateInput(input); err != nil {
		return Grant{}, err
	}
	cfg, err := s.Load()
	if err != nil {
		return Grant{}, err
	}
	source = strings.TrimSpace(source)
	input = filepath.Clean(strings.TrimSpace(input))
	now := time.Now().UTC()
	for idx := range cfg.Grants {
		if cfg.Grants[idx].Source == source && cfg.Grants[idx].Input == input {
			cfg.Grants[idx].Enabled = true
			cfg.Grants[idx].EditedAt = now
			grant := cfg.Grants[idx]
			return grant, s.save(cfg)
		}
	}
	grant := Grant{Source: source, Input: input, Enabled: true, AddedAt: now}
	cfg.Grants = append(cfg.Grants, grant)
	return grant, s.save(cfg)
}

// Disable marks a grant disabled. The (source, input) pair stays recorded
// so re-enabling is a single explicit step; disabled grants are never
// collected by the periodic entry.
func (s Store) Disable(source, input string) (Grant, bool, error) {
	cfg, err := s.Load()
	if err != nil {
		return Grant{}, false, err
	}
	source = strings.TrimSpace(source)
	input = filepath.Clean(strings.TrimSpace(input))
	for idx := range cfg.Grants {
		if cfg.Grants[idx].Source == source && cfg.Grants[idx].Input == input {
			cfg.Grants[idx].Enabled = false
			cfg.Grants[idx].EditedAt = time.Now().UTC()
			grant := cfg.Grants[idx]
			return grant, true, s.save(cfg)
		}
	}
	return Grant{}, false, nil
}

// Enabled returns the enabled grants in config order.
func (s Store) Enabled() ([]Grant, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}
	var out []Grant
	for _, grant := range cfg.Grants {
		if grant.Enabled {
			out = append(out, grant)
		}
	}
	return out, nil
}
