package runlock

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveLockAndIndependentDirectories(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Acquire(dir); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("same directory must be busy: %v", err)
	}
	other, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	if _, err := os.Stat(filepath.Join(dir, ".collector.lock")); err != nil {
		t.Fatalf("lock inode must remain after close: %v", err)
	}
}

func TestLockProcessHelper(t *testing.T) {
	mode := os.Getenv("TOKTRAIL_LOCK_HELPER")
	if mode == "" {
		return
	}
	lock, err := Acquire(os.Getenv("TOKTRAIL_LOCK_DIRECTORY"))
	if errors.Is(err, ErrBusy) {
		os.Exit(23)
	}
	if err != nil {
		os.Exit(24)
	}
	_ = lock // deliberately rely on OS process-exit cleanup
	if mode == "hold" {
		os.Stdout.WriteString("locked\n")
		<-time.After(30 * time.Second)
		os.Exit(25)
	}
	os.Exit(0)
}

func lockHelper(t *testing.T, dir, mode string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLockProcessHelper$")
	cmd.Env = append(os.Environ(), "TOKTRAIL_LOCK_HELPER="+mode, "TOKTRAIL_LOCK_DIRECTORY="+dir)
	return cmd
}

func TestAnotherProcessCannotEnterAndNormalExitReleasesLock(t *testing.T) {
	dir := t.TempDir()
	lock, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lockHelper(t, dir, "probe").Run(); err == nil {
		t.Fatal("other process entered locked directory")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
		t.Fatalf("expected busy exit 23, got %v", err)
	}
	lock.Close()
	if err := lockHelper(t, dir, "probe").Run(); err != nil {
		t.Fatal(err)
	}
	// The child intentionally exited without Close; ownership must be gone.
	reopened, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestKilledProcessReleasesLock(t *testing.T) {
	dir := t.TempDir()
	cmd := lockHelper(t, dir, "hold")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child not ready: %q, %v", line, err)
	}
	if lock, err := Acquire(dir); !errors.Is(err, ErrBusy) {
		if lock != nil {
			lock.Close()
		}
		t.Fatalf("child lock must be busy: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed helper unexpectedly succeeded")
	}
	reopened, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}
