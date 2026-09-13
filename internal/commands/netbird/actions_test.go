package netbird

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	nats "github.com/open-uem/nats"
)

func TestActionLiteralArgumentsAndSecretIsolation(t *testing.T) {
	profile := "office; $(touch injected) `id` & quoted \"name\""
	url := "https://management.example.test:8443/api"
	steps, err := actionSteps("switchprofile", nats.NetbirdSettings{Profile: profile, ManagementURL: url})
	if err != nil {
		t.Fatal(err)
	}
	want := []actionStep{{args: []string{"profile", "select", "--management-url", url, "--", profile}}, {args: []string{"up", "--management-url", url}}}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("unexpected command arguments: %#v", steps)
	}
	key := "owned-key-with-$()-and-quotes\""
	steps, err = actionSteps("register", nats.NetbirdSettings{OneOffKey: key, ManagementURL: url})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 || steps[0].args[0] != "down" || steps[1].args[0] != "up" || len(steps[0].env) != 0 || !reflect.DeepEqual(steps[1].env, []string{"NB_SETUP_KEY=" + key}) {
		t.Fatal("registration sequence or key environment changed")
	}
	for _, step := range steps {
		for _, arg := range step.args {
			if strings.Contains(arg, key) || strings.Contains(arg, "setup-key") {
				t.Fatal("key entered command arguments")
			}
		}
	}
	steps, err = actionSteps("switchprofile", nats.NetbirdSettings{Profile: "--setup-key=untrusted", ManagementURL: url})
	if err != nil || steps[0].args[len(steps[0].args)-2] != "--" {
		t.Fatal("profile can become a flag")
	}
}

func TestActionRequestValidationBeforeExecution(t *testing.T) {
	valid := nats.NetbirdSettings{ManagementURL: "https://management.example.test"}
	for _, operation := range []string{"up", "down", "register", "switchprofile"} {
		for _, url := range []string{"", "http://management.example.test", "https://user:password@example.test", "https://example.test/?query=1", "https://example.test/#fragment", "https://example.test/../other", "https://example.test/\n", strings.Repeat("x", 2049)} {
			request := valid
			request.ManagementURL = url
			if _, err := actionSteps(operation, request); !errors.Is(err, ErrInvalidAction) {
				t.Fatalf("accepted invalid URL for %s", operation)
			}
		}
	}
	for _, operation := range []string{"register", "switchprofile"} {
		limit := 512
		if operation == "switchprofile" {
			limit = 256
		}
		for _, value := range []string{"", " bad", "bad ", "bad\x00", "bad\r\n", "bad\x7f", string([]byte{0xff}), strings.Repeat("a", limit+1)} {
			request := valid
			if operation == "register" {
				request.OneOffKey = value
			} else {
				request.Profile = value
			}
			if _, err := actionSteps(operation, request); !errors.Is(err, ErrInvalidAction) {
				t.Fatalf("accepted invalid %s value", operation)
			}
		}
	}
	for _, operation := range []string{"up", "down", "register", "switchprofile", "unknown"} {
		request := valid
		request.Profile = "profile"
		request.OneOffKey = "key"
		if _, err := actionSteps(operation, request); !errors.Is(err, ErrInvalidAction) {
			t.Fatalf("accepted incompatible fields for %s", operation)
		}
	}
	// Exported wire entry points must reject malformed input before resolving a
	// desktop identity, launching NetBird, or collecting a device report.
	for _, call := range []func([]byte) (*nats.Netbird, error){Register, NetbirdUp, NetbirdDown, SwitchProfileData} {
		result, err := call([]byte(`{"management_url":"http://invalid.example.test"}`))
		if result != nil || !errors.Is(err, ErrInvalidAction) {
			t.Fatal("invalid input reached execution")
		}
	}
}

func TestActionWireRejectsAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `{}`, `{"management_url":null}`, `{"management_url":1}`, `{"management_url":{}}`, `{"management_url":"https://example.test","management_url":"https://other.test"}`, `{"key":"first","key":"second"}`, `{"Management_URL":"https://example.test"}`, `{"unknown":"value"}`, `{"profile":true}`, `{"profile":"one"} {"profile":"two"}`, `{"profile":"one",}`, string([]byte{'{', 0xff, '}'}), strings.Repeat(" ", maxActionMessage+1)} {
		request, err := decodeAction([]byte(raw))
		if raw == `{}` {
			_, err = actionSteps("up", request)
		}
		if !errors.Is(err, ErrInvalidAction) {
			t.Fatalf("accepted invalid JSON: %q", raw)
		}
	}
	want := nats.NetbirdSettings{ManagementURL: "https://example.test", Profile: "office"}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeAction(raw)
	if err != nil || got != want {
		t.Fatal("legacy wire compatibility failed")
	}
}

func TestActionWireAllowsEscapedMaximumFields(t *testing.T) {
	base := "https://example.test/"
	want := nats.NetbirdSettings{ManagementURL: base + strings.Repeat("&", 2048-len(base)), OneOffKey: strings.Repeat("<", 512)}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 4096 || len(raw) > maxActionMessage {
		t.Fatal("fixture did not exercise JSON expansion")
	}
	got, err := decodeAction(raw)
	if err != nil || got != want {
		t.Fatal("valid maximum fields were rejected after JSON escaping")
	}
	if _, err := actionSteps("register", got); err != nil {
		t.Fatal(err)
	}
}

func TestActionStopsAfterFailureOrCancellation(t *testing.T) {
	steps, err := actionSteps("register", nats.NetbirdSettings{ManagementURL: "https://example.test", OneOffKey: "owned-key"})
	if err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{0, 1, 2} {
		calls := 0
		err := runAction(context.Background(), "/owned/netbird", steps, func(_ context.Context, _ string, args, env []string) error {
			calls++
			if calls == failAt {
				return errors.New("secret process output must stay private")
			}
			return nil
		})
		if failAt == 0 {
			if err != nil || calls != 2 {
				t.Fatal("successful sequence changed")
			}
		} else if !errors.Is(err, ErrActionUnconfirmed) || calls != failAt {
			t.Fatal("failed command was retried or following command ran")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err = runAction(ctx, "/owned/netbird", steps, func(ctx context.Context, _ string, args, env []string) error { calls++; cancel(); return nil })
	if !errors.Is(err, ErrActionUnconfirmed) || calls != 1 {
		t.Fatal("cancellation did not stop sequence")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err = runAction(ctx, "/owned/netbird", steps, func(ctx context.Context, _ string, args, env []string) error { <-ctx.Done(); return ctx.Err() })
	if !errors.Is(err, ErrActionUnconfirmed) {
		t.Fatal("deadline not classified as unconfirmed")
	}
}
