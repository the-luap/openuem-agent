package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CommandSession retains one execution identity for an entire command sequence.
// Call Close after use. Run invokes the executable directly and discards output;
// command output must not disclose a registration credential through logs.
type CommandSession struct {
	prepare func(*exec.Cmd)
	baseEnv []string
	env     []string
	close   func() error
}

func (s *CommandSession) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}

func (s *CommandSession) Run(ctx context.Context, executable string, args, extraEnv []string) error {
	cmd, err := s.command(ctx, executable, args, extraEnv)
	if err != nil {
		return err
	}
	// Nil streams use the null device, without pipes, buffers or output logs.
	err = cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (s *CommandSession) command(ctx context.Context, executable string, args, extraEnv []string) (*exec.Cmd, error) {
	if ctx == nil || !filepath.IsAbs(executable) {
		return nil, errors.New("command context and absolute executable required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	base := s.baseEnv
	if base == nil {
		base = os.Environ()
	}
	cmd.Env = commandEnvironment(base, s.env, extraEnv)
	if s.prepare != nil {
		s.prepare(cmd)
	}
	return cmd, nil
}

var ErrCommandOutput = errors.New("command output exceeded its limit")

// Output captures stdout only. Both output streams share a byte budget; crossing
// it cancels the owned command. Failed, truncated or canceled output is never
// returned, and stderr is neither retained nor logged.
func (s *CommandSession) Output(parent context.Context, executable string, args, extraEnv []string, limit int) ([]byte, error) {
	if parent == nil || limit < 1 || limit > 1<<20 {
		return nil, ErrCommandOutput
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	cmd, err := s.command(ctx, executable, args, extraEnv)
	if err != nil {
		return nil, err
	}
	output := &commandOutput{limit: limit, cancel: cancel}
	cmd.Stdout = commandStream{output: output, keep: true}
	cmd.Stderr = commandStream{output: output}
	err = cmd.Run()
	if output.exceeded {
		return nil, ErrCommandOutput
	}
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if err != nil {
		return nil, err
	}
	return output.data, nil
}

type commandOutput struct {
	mu           sync.Mutex
	limit, total int
	data         []byte
	exceeded     bool
	cancel       context.CancelFunc
}
type commandStream struct {
	output *commandOutput
	keep   bool
}

func (w commandStream) Write(p []byte) (int, error) {
	b := w.output
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exceeded {
		return len(p), nil
	}
	if len(p) > b.limit-b.total {
		b.exceeded = true
		b.cancel()
		return len(p), nil
	}
	b.total += len(p)
	if w.keep {
		b.data = append(b.data, p...)
	}
	return len(p), nil
}

func commandEnvironment(base, identity, extra []string) []string {
	env := make([]string, 0, len(base)+len(identity)+len(extra))
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		// NetBird environment variables override even explicit command flags.
		if !strings.HasPrefix(strings.ToUpper(key), "NB_") {
			env = append(env, item)
		}
	}
	env = append(env, identity...)
	return append(env, extra...)
}
