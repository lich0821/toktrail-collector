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
	"syscall"
	"time"

	"toktrail-collector/internal/source/registry"
)

const (
	configFileName       = "grants.json"
	legacyConfigFileName = "sources.json"
)

var linkFile = os.Link

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

func (s Store) LegacyPath() string { return filepath.Join(s.dir, legacyConfigFileName) }

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

func isTrulyAbsent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return false, err
}

func (s Store) loadFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("invalid source grant config %s: %w", path, err)
	}
	if cfg.Version != 1 {
		return Config{}, fmt.Errorf("unsupported source grant config version %d in %s", cfg.Version, path)
	}
	for idx, grant := range cfg.Grants {
		if err := ValidateGrant(grant.Source, grant.Input); err != nil {
			return Config{}, fmt.Errorf("grant %d: %w", idx, err)
		}
	}
	return cfg, nil
}

// Load reads and parses the grant config. It is strictly read-only and never
// creates or modifies files on disk. If grants.json is truly absent, it falls
// back to validated legacy sources.json; an existing grants.json (even if
// empty or disabled) always wins.
func (s Store) Load() (Config, error) {
	absent, err := isTrulyAbsent(s.Path())
	if err != nil {
		return Config{}, err
	}
	if !absent {
		return s.loadFile(s.Path())
	}
	legacyAbsent, err := isTrulyAbsent(s.LegacyPath())
	if err != nil {
		return Config{}, err
	}
	if legacyAbsent {
		return Config{Version: 1}, nil
	}
	return s.loadFile(s.LegacyPath())
}

// MigrateLegacy validates any legacy sources.json and atomically publishes a
// complete private 0600 grants.json without replacing any existing current file.
// Caller must hold the collector runlock. The legacy sources.json is retained
// untouched on disk. If current grants.json already exists or appears
// concurrently during publication, the authoritative current file is
// loaded/validated instead and never clobbered.
func (s Store) MigrateLegacy() error {
	absent, err := isTrulyAbsent(s.Path())
	if err != nil {
		return err
	}
	if !absent {
		_, err := s.loadFile(s.Path())
		return err
	}

	legacyAbsent, err := isTrulyAbsent(s.LegacyPath())
	if err != nil {
		return err
	}
	if legacyAbsent {
		return nil
	}

	cfg, err := s.loadFile(s.LegacyPath())
	if err != nil {
		return err
	}
	if cfg.Grants == nil {
		cfg.Grants = []Grant{}
	}

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	cfg.Version = 1
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	f, err := os.CreateTemp(s.dir, "grants.*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}

	err = linkFile(tmpName, s.Path())
	if err == nil {
		remErr := os.Remove(tmpName)
		tmpName = ""
		if remErr != nil {
			return remErr
		}
		return nil
	}

	_ = os.Remove(tmpName)
	tmpName = ""

	if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
		_, loadErr := s.loadFile(s.Path())
		return loadErr
	}

	return err
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
	f, err := os.CreateTemp(s.dir, "grants.*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.Path()); err != nil {
		return err
	}
	tmpName = ""
	return nil
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
	if err := s.MigrateLegacy(); err != nil {
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
		if cfg.Grants[idx].Source == source && filepath.Clean(cfg.Grants[idx].Input) == input {
			cfg.Grants[idx].Enabled = true
			cfg.Grants[idx].EditedAt = now
			grant := cfg.Grants[idx]
			if err := s.save(cfg); err != nil {
				return Grant{}, err
			}
			return grant, nil
		}
	}
	grant := Grant{Source: source, Input: input, Enabled: true, AddedAt: now}
	cfg.Grants = append(cfg.Grants, grant)
	if err := s.save(cfg); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// Disable marks a grant disabled. The (source, input) pair stays recorded
// so re-enabling is a single explicit step; disabled grants are never
// collected by the periodic entry.
func (s Store) Disable(source, input string) (Grant, bool, error) {
	if err := ValidateGrant(source, input); err != nil {
		return Grant{}, false, err
	}
	if err := s.MigrateLegacy(); err != nil {
		return Grant{}, false, err
	}
	cfg, err := s.Load()
	if err != nil {
		return Grant{}, false, err
	}
	source = strings.TrimSpace(source)
	input = filepath.Clean(strings.TrimSpace(input))
	for idx := range cfg.Grants {
		if cfg.Grants[idx].Source == source && filepath.Clean(cfg.Grants[idx].Input) == input {
			cfg.Grants[idx].Enabled = false
			cfg.Grants[idx].EditedAt = time.Now().UTC()
			grant := cfg.Grants[idx]
			if err := s.save(cfg); err != nil {
				return Grant{}, false, err
			}
			return grant, true, nil
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
