package runlock

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRC2_ConcurrentRunlock_MutualExclusion_Acceptance verifies that under high concurrent contention,
// exactly one goroutine obtains the exclusive runlock, all others receive ErrBusy, and releasing
// the lock cleanly hands off availability to subsequent contenders.
func TestRC2_ConcurrentRunlock_MutualExclusion_Acceptance(t *testing.T) {
	dir := t.TempDir()

	const concurrency = 25

	// Round 1: High concurrency race
	var startBarrier = make(chan struct{})
	var wg sync.WaitGroup
	var acquiredCount atomic.Int32
	var busyCount atomic.Int32
	var unexpectedErr atomic.Pointer[error]
	var heldLock *Lock
	var lockMu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier // synchronize start
			l, err := Acquire(dir)
			if err == nil {
				acquiredCount.Add(1)
				lockMu.Lock()
				heldLock = l
				lockMu.Unlock()
			} else if errors.Is(err, ErrBusy) {
				busyCount.Add(1)
			} else {
				unexpectedErr.Store(&err)
			}
		}()
	}

	// Trigger all goroutines at the same instant
	close(startBarrier)
	wg.Wait()

	if errPtr := unexpectedErr.Load(); errPtr != nil {
		t.Fatalf("unexpected error during concurrent acquire: %v", *errPtr)
	}

	if acquired := acquiredCount.Load(); acquired != 1 {
		t.Fatalf("expected exactly 1 lock acquisition across %d contenders, got %d", concurrency, acquired)
	}
	if busy := busyCount.Load(); busy != concurrency-1 {
		t.Fatalf("expected %d ErrBusy responses, got %d", concurrency-1, busy)
	}

	// Hold the lock for a moment and release
	lockMu.Lock()
	if heldLock == nil {
		t.Fatal("held lock is nil despite acquiredCount == 1")
	}
	if err := heldLock.Close(); err != nil {
		t.Fatalf("failed to close held lock: %v", err)
	}
	lockMu.Unlock()

	// Round 2: Immediate contention race after release
	startBarrier2 := make(chan struct{})
	acquiredCount.Store(0)
	busyCount.Store(0)
	unexpectedErr.Store(nil)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier2
			l, err := Acquire(dir)
			if err == nil {
				acquiredCount.Add(1)
				lockMu.Lock()
				heldLock = l
				lockMu.Unlock()
			} else if errors.Is(err, ErrBusy) {
				busyCount.Add(1)
			} else {
				unexpectedErr.Store(&err)
			}
		}()
	}

	close(startBarrier2)
	wg.Wait()

	if errPtr := unexpectedErr.Load(); errPtr != nil {
		t.Fatalf("unexpected error in round 2: %v", *errPtr)
	}
	if acquired := acquiredCount.Load(); acquired != 1 {
		t.Fatalf("expected exactly 1 lock acquisition in round 2, got %d", acquired)
	}
	if busy := busyCount.Load(); busy != concurrency-1 {
		t.Fatalf("expected %d ErrBusy responses in round 2, got %d", concurrency-1, busy)
	}

	lockMu.Lock()
	if heldLock != nil {
		heldLock.Close()
	}
	lockMu.Unlock()
}

// TestRC2_Runlock_MultiProcessContention_Acceptance tests cross-process mutual exclusion.
// When an external process holds the runlock, concurrent callers within the collector
// process are all consistently rejected with ErrBusy. Once the external process exits,
// the lock becomes immediately available.
func TestRC2_Runlock_MultiProcessContention_Acceptance(t *testing.T) {
	dir := t.TempDir()

	cmd := lockHelper(t, dir, "hold")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	// Wait for helper to acquire the lock and output "locked\n"
	// Use strings.TrimSpace to reliably handle both Unix (\n) and Windows (\r\n) line endings.
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "locked" {
		t.Fatalf("helper failed to lock: line=%q, err=%v, stderr=%s", line, err, stderr.String())
	}

	// Now launch 10 concurrent goroutines: all must fail with ErrBusy
	const callers = 10
	var wg sync.WaitGroup
	var busyCount atomic.Int32
	var errCount atomic.Int32

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := Acquire(dir)
			if err == nil {
				l.Close()
				errCount.Add(1)
			} else if errors.Is(err, ErrBusy) {
				busyCount.Add(1)
			} else {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if busy := busyCount.Load(); busy != callers {
		t.Fatalf("expected all %d callers to get ErrBusy while helper holds lock, got %d", callers, busy)
	}

	// Terminate helper process
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_ = cmd.Wait()

	// Wait up to 3 seconds for OS (especially Windows kernel file handle cleanup) to release lock
	var releasedLock *Lock
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		releasedLock, err = Acquire(dir)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to acquire lock after helper exit: %v", err)
	}
	releasedLock.Close()
}
