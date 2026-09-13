package netbird

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/openuem-agent/internal/commands/report"
	commandruntime "github.com/open-uem/openuem-agent/internal/commands/runtime"
)

var (
	ErrInvalidAction     = errors.New("invalid NetBird action request")
	ErrActionUnconfirmed = errors.New("NetBird action could not be confirmed; refresh its state before retrying")
)

type actionStep struct{ args, env []string }
type actionRunner func(context.Context, string, []string, []string) error

// A valid 2 KiB URL and 512-byte key can expand sixfold under JSON escaping.
const maxActionMessage = 16 << 10

func actionValue(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return strings.TrimSpace(value) == value
}

func actionSteps(operation string, request nats.NetbirdSettings) ([]actionStep, error) {
	if !netbirdapi.ValidBase(request.ManagementURL) {
		return nil, ErrInvalidAction
	}
	url := []string{"--management-url", request.ManagementURL}
	step := func(operation string) actionStep { return actionStep{args: append([]string{operation}, url...)} }
	switch operation {
	case "up", "down":
		if request.OneOffKey != "" || request.Profile != "" {
			return nil, ErrInvalidAction
		}
		return []actionStep{step(operation)}, nil
	case "register":
		if !actionValue(request.OneOffKey, 512) || request.Profile != "" {
			return nil, ErrInvalidAction
		}
		up := step("up")
		// NetBird supports flag values through NB_* environment variables. Keep
		// the one-off key out of argv, shell text and agent response/log output.
		up.env = []string{"NB_SETUP_KEY=" + request.OneOffKey}
		return []actionStep{step("down"), up}, nil
	case "switchprofile":
		if !actionValue(request.Profile, 256) || request.OneOffKey != "" {
			return nil, ErrInvalidAction
		}
		selectArgs := append([]string{"profile", "select"}, url...)
		selectArgs = append(selectArgs, "--", request.Profile)
		return []actionStep{{args: selectArgs}, step("up")}, nil
	default:
		return nil, ErrInvalidAction
	}
}

// Decode the exact legacy wire fields, rejecting duplicate keys and trailing
// values as well as unknown fields, invalid UTF-8 and oversized messages.
func decodeAction(data []byte) (nats.NetbirdSettings, error) {
	var request nats.NetbirdSettings
	if len(data) == 0 || len(data) > maxActionMessage || !utf8.Valid(data) {
		return request, ErrInvalidAction
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return request, ErrInvalidAction
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return request, ErrInvalidAction
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return request, ErrInvalidAction
		}
		seen[key] = true
		var value string
		// A string token rejects null, which Decode(&string) otherwise accepts.
		raw, err := d.Token()
		if err != nil {
			return request, ErrInvalidAction
		}
		value, ok = raw.(string)
		if !ok {
			return request, ErrInvalidAction
		}
		switch key {
		case "key":
			request.OneOffKey = value
		case "management_url":
			request.ManagementURL = value
		case "profile":
			request.Profile = value
		default:
			return request, ErrInvalidAction
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return request, ErrInvalidAction
	}
	if _, err := d.Token(); err != io.EOF {
		return request, ErrInvalidAction
	}
	return request, nil
}

func runAction(ctx context.Context, executable string, steps []actionStep, run actionRunner) error {
	for _, step := range steps {
		if ctx.Err() != nil {
			return ErrActionUnconfirmed
		}
		if err := run(ctx, executable, step.args, step.env); err != nil || ctx.Err() != nil {
			return ErrActionUnconfirmed
		}
	}
	return nil
}

func performAction(operation string, request nats.NetbirdSettings) (*nats.Netbird, error) {
	return performActionContext(context.Background(), operation, request)
}

func performActionContext(parent context.Context, operation string, request nats.NetbirdSettings) (*nats.Netbird, error) {
	steps, err := actionSteps(operation, request)
	if err != nil {
		return nil, err
	}
	timeout := time.Minute
	if operation == "switchprofile" {
		timeout = 2 * time.Minute
	}
	if parent == nil {
		return nil, ErrActionUnconfirmed
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	session, err := commandruntime.NewCommandSession(ctx)
	if err != nil {
		return nil, ErrActionUnconfirmed
	}
	defer session.Close()
	if err = runAction(ctx, getNetbirdBin(), steps, session.Run); err != nil {
		return nil, err
	}
	result, err := report.RetrieveNetbirdInfoWithSession(ctx, session)
	if err != nil {
		return nil, ErrActionUnconfirmed
	}
	return result, nil
}

func actionFromData(operation string, data []byte) (*nats.Netbird, error) {
	request, err := decodeAction(data)
	if err != nil {
		return nil, err
	}
	return performAction(operation, request)
}

func Register(data []byte) (*nats.Netbird, error)    { return actionFromData("register", data) }
func NetbirdUp(data []byte) (*nats.Netbird, error)   { return actionFromData("up", data) }
func NetbirdDown(data []byte) (*nats.Netbird, error) { return actionFromData("down", data) }
func SwitchProfileData(data []byte) (*nats.Netbird, error) {
	return actionFromData("switchprofile", data)
}
func SwitchProfile(request nats.NetbirdSettings) (*nats.Netbird, error) {
	return performAction("switchprofile", request)
}

func getNetbirdBin() string { return report.NetbirdExecutable() }

// ExecuteAction applies the broker service lifetime to execution and observation.
func ExecuteAction(ctx context.Context, operation string, data []byte) (*nats.Netbird, error) {
	request, err := decodeAction(data)
	if err != nil {
		return nil, err
	}
	return performActionContext(ctx, operation, request)
}
