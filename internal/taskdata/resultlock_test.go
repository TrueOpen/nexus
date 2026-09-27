package taskdata

import (
	"sync"
	"testing"
)

// The Finalize lock of a task serializes its callers and leaves no entry behind once the last
// caller releases it, so a long-running Builder does not keep one per task.
func TestResultLockIsReleasedAfterLastCaller(t *testing.T) {
	s := &Service{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	inside := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			unlock := s.lockResult("session", []string{"task-a", "task-b"}[i%2])
			defer unlock()
			if i%2 == 0 {
				mu.Lock()
				inside++
				if inside > 1 {
					t.Error("two Finalize calls of one task ran at once")
				}
				mu.Unlock()
				mu.Lock()
				inside--
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if n := len(s.resultLocks); n != 0 {
		t.Fatalf("%d lock entries left after every caller released", n)
	}
}
