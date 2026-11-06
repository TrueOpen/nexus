package buildersync

import "sync"

// watchers signal the tasks whose member streams applied items.
type watchers struct {
	mu   sync.Mutex
	next uint64
	byID map[string]map[uint64]chan struct{}
}

// Watch returns a channel that receives a value whenever a batch applied items of the task (its
// replica may have changed), and the function that stops the watch. Changes in a row may arrive as
// one value; read Replica after.
func (r *Receiver) Watch(taskID string) (<-chan struct{}, func()) {
	w := &r.watch
	ch := make(chan struct{}, 1)
	w.mu.Lock()
	w.next++
	id := w.next
	if w.byID == nil {
		w.byID = map[string]map[uint64]chan struct{}{}
	}
	if w.byID[taskID] == nil {
		w.byID[taskID] = map[uint64]chan struct{}{}
	}
	w.byID[taskID][id] = ch
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if set := w.byID[taskID]; set != nil {
			delete(set, id)
			if len(set) == 0 {
				delete(w.byID, taskID)
			}
		}
	}
}

func (w *watchers) notify(taskID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ch := range w.byID[taskID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
