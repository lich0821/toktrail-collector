// Package runlock serializes CLI access to a collector state directory.
// Locks are held by the operating system and released when the process exits,
// including after a crash. The lock file remains in place to keep its inode
// stable across successive owners.
package runlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrBusy = errors.New("collector state is in use by another process; retry after it exits")

type Lock struct{ file *os.File }

func Acquire(dir string) (*Lock, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("collector state directory is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create collector state directory: %w", err)
	}
	name := filepath.Join(dir, ".collector.lock")
	if info, err := os.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("collector lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect collector lock: %w", err)
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open collector lock: %w", err)
	}
	if err = lockFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return &Lock{file: file}, nil
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := unlockFile(file)
	closeErr := file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
