package report

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
	commandruntime "github.com/open-uem/openuem-agent/internal/commands/runtime"
)

var ErrNetbirdState = errors.New("NetBird status could not be confirmed")

// NetbirdExecutable is the supported installation path for both commands and
// inventory. An inherited PATH cannot select a different executable.
func NetbirdExecutable() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\Program Files\NetBird\netbird.exe`
	case "darwin":
		return "/usr/local/bin/netbird"
	default:
		return "/usr/bin/netbird"
	}
}

func RetrieveNetbirdInfo() (*nats.Netbird, error) {
	return RetrieveNetbirdInfoContext(context.Background())
}

func RetrieveNetbirdInfoContext(parent context.Context) (*nats.Netbird, error) {
	if parent == nil {
		return nil, ErrNetbirdState
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	present, err := netbirdPresent(NetbirdExecutable())
	if err != nil || ctx.Err() != nil {
		return nil, ErrNetbirdState
	}
	if !present {
		return &nats.Netbird{}, nil
	}
	session, err := commandruntime.NewCommandSession(ctx)
	if err != nil {
		return nil, ErrNetbirdState
	}
	defer session.Close()
	return collectNetbird(ctx, NetbirdExecutable(), session.Output)
}

// RetrieveNetbirdInfoWithSession retains the action's identity and deadline while
// collecting its resulting state. It never starts a new desktop lookup.
func RetrieveNetbirdInfoWithSession(parent context.Context, session *commandruntime.CommandSession) (*nats.Netbird, error) {
	if parent == nil || session == nil {
		return nil, ErrNetbirdState
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	return collectNetbird(ctx, NetbirdExecutable(), session.Output)
}

func netbirdPresent(executable string) (bool, error) {
	info, err := os.Stat(executable)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return false, ErrNetbirdState
	}
	return true, nil
}

type netbirdOutput func(context.Context, string, []string, []string, int) ([]byte, error)

func collectNetbird(ctx context.Context, executable string, output netbirdOutput) (*nats.Netbird, error) {
	run := func(limit int, args ...string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrNetbirdState
		}
		data, err := output(ctx, executable, args, []string{"LC_ALL=C", "LANG=C"}, limit)
		if err != nil || ctx.Err() != nil || len(data) > limit || !utf8.Valid(data) {
			return nil, ErrNetbirdState
		}
		return data, nil
	}
	version, err := run(4096, "version")
	if err != nil {
		return nil, err
	}
	versionText := strings.TrimSpace(string(version))
	if !netbirdstate.ValidText(versionText) {
		return nil, ErrNetbirdState
	}
	data := &nats.Netbird{Installed: true, Version: versionText}
	service, err := run(4096, "service", "status")
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(string(service))) {
	case "netbird service status: running":
		data.ServiceStatus = "netbird.service_running"
	case "netbird service status: stopped":
		data.ServiceStatus = "netbird.service_stopped"
		return data, nil
	default:
		return nil, ErrNetbirdState
	}
	status, err := run(1<<20, "status", "--json")
	if err != nil {
		return nil, err
	}
	if err = netbirdOverview(status, data); err != nil {
		return nil, err
	}
	profiles, err := run(256<<10, "profile", "list")
	if err != nil {
		return nil, err
	}
	options, format, err := netbirdProfiles(profiles)
	if err != nil {
		return nil, err
	}
	if format == "names" {
		// The current name-only table permits duplicate display names. Query its
		// supported ID column before making those entries selectable.
		profiles, err = run(256<<10, "profile", "list", "--show-id")
		if err != nil {
			return nil, err
		}
		options, format, err = netbirdProfiles(profiles)
		if err != nil || format != "ids" {
			return nil, ErrNetbirdState
		}
	}
	if err = netbirdstate.Validate(options); err != nil {
		return nil, ErrNetbirdState
	}
	data.ProfileDetails = options
	for _, profile := range options {
		data.Profiles = append(data.Profiles, profile.Handle())
	}
	return data, nil
}
