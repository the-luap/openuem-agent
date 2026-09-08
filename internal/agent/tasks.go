package agent

import "sync"

// taskGroup joins admitted scheduler work even if the scheduler's own shutdown
// deadline expires. Closing admission is serialized with WaitGroup.Add so a
// scheduled callback cannot acquire a released identity during shutdown.
type taskGroup struct {
	mu     sync.Mutex
	closed bool
	work   sync.WaitGroup
}

func (g *taskGroup) wrap(task func()) func() {
	return func() {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return
		}
		g.work.Add(1)
		g.mu.Unlock()
		defer g.work.Done()
		task()
	}
}

func (g *taskGroup) close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

func (g *taskGroup) wait() { g.work.Wait() }
