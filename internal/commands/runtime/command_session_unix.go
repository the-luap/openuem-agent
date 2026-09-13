//go:build linux || darwin

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// NewCommandSession resolves the local desktop identity once. Lookup failure
// never falls back to a more privileged identity. With no desktop, commands use
// the service identity. No login shell or user-controlled PATH is involved.
func NewCommandSession(parent context.Context) (*CommandSession, error) {
	if parent == nil {
		return nil, errors.New("command context required")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/who")
	cmd.WaitDelay = time.Second
	output := &sessionOutput{}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil || output.overflow {
		return nil, errors.New("could not resolve command session")
	}
	name, err := sessionUsername(output.text.String(), runtime.GOOS)
	if err != nil {
		return nil, err
	}
	session := &CommandSession{}
	var credential *syscall.Credential
	if name != "" {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return nil, err
		}
		if uint64(os.Geteuid()) != uid || uint64(os.Getegid()) != gid {
			credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		}
		session.env = []string{"USER=" + u.Username, "LOGNAME=" + u.Username, "HOME=" + u.HomeDir}
	}
	session.prepare = func(cmd *exec.Cmd) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential, Setpgid: true}
		cmd.Cancel = func() error {
			err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
	}
	return session, nil
}

type sessionOutput struct {
	text     strings.Builder
	overflow bool
}

func (b *sessionOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.text.Len()+n > 64<<10 {
		b.overflow = true
		return n, nil
	}
	b.text.Write(p)
	return n, nil
}

func sessionUsername(output, platform string) (string, error) {
	selected := ""
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		match := platform == "darwin" && fields[1] == "console"
		if platform == "linux" {
			for _, field := range fields[1:] {
				if field == "seat0" || field == ":0" || field == "(:0)" {
					match = true
				}
			}
		}
		if !match || fields[0] == "gdm" || fields[0] == "sddm" {
			continue
		}
		if selected != "" && selected != fields[0] {
			return "", errors.New("command session is ambiguous")
		}
		selected = fields[0]
	}
	return selected, nil
}
