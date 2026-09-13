package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if ctx == nil || !filepath.IsAbs(executable) {
		return errors.New("command context and absolute executable required")
	}
	if err := ctx.Err(); err != nil {
		return err
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
	// Nil streams use the null device, without pipes, buffers or output logs.
	err := cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
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
