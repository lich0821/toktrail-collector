//go:build windows

package runlock

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	lockFileEx   = kernel32.NewProc("LockFileEx")
	unlockFileEx = kernel32.NewProc("UnlockFileEx")
)

func lockFile(file *os.File) error {
	var overlapped syscall.Overlapped
	// LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK; lock byte zero.
	ok, _, err := lockFileEx.Call(file.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if ok != 0 {
		return nil
	}
	if err == syscall.Errno(33) { // ERROR_LOCK_VIOLATION
		return ErrBusy
	}
	return fmt.Errorf("lock collector state: %w", err)
}

func unlockFile(file *os.File) error {
	var overlapped syscall.Overlapped
	ok, _, err := unlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if ok != 0 {
		return nil
	}
	return fmt.Errorf("unlock collector state: %w", err)
}
