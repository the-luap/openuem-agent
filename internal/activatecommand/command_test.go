package activatecommand

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestActivationCLIRequiresExplicitDirectoryAndNeverEchoesUnknownValues(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "identity")
	secret := "fixture-secret-argument"
	for _, args := range [][]string{{"activate"}, {"activate", "-identity-directory", "relative"}, {"activate", "-identity-directory", directory, "-identity-directory", directory}, {"activate", "-identity-directory", directory, secret}, {"activate", "-invitation", secret}} {
		var out, diag bytes.Buffer
		handled, code := handle(context.Background(), args, &out, &diag, func(context.Context, Options) (Result, error) {
			t.Fatal("invalid command reached activation")
			return Result{}, nil
		})
		if !handled || code != 2 || out.Len() != 0 || strings.Contains(diag.String(), secret) {
			t.Fatal("invalid CLI admission or diagnostic")
		}
	}
	var out, diag bytes.Buffer
	_, code := handle(context.Background(), []string{"activate", "-identity-directory", directory}, &out, &diag, func(_ context.Context, o Options) (Result, error) {
		if o.IdentityDirectory != directory {
			t.Fatal("directory changed")
		}
		return Result{Registered: true, DeviceID: fixtureDeviceID, TenantID: 3, SiteID: 4}, errors.Join(ErrStart, errors.New(secret))
	})
	if code != 1 || !strings.Contains(out.String(), `"registered":true`) || !strings.Contains(out.String(), `"running":false`) || strings.Contains(out.String()+diag.String(), secret) {
		t.Fatal("partial activation result or redaction failed")
	}
	for _, args := range [][]string{nil, {"serve"}, {"enroll"}} {
		if handled, _ := Handle(context.Background(), args, &out, &diag); handled {
			t.Fatal("activation claimed another command")
		}
	}
}

func TestActivationHelpAndCancellationDoNotClaimRunning(t *testing.T) {
	var out, diag bytes.Buffer
	_, code := handle(context.Background(), []string{"activate", "-help"}, &out, &diag, func(context.Context, Options) (Result, error) {
		t.Fatal("help activated service")
		return Result{}, nil
	})
	if code != 0 || !strings.Contains(out.String(), "Register and start") || diag.Len() != 0 {
		t.Fatal("invalid help")
	}
	out.Reset()
	_, code = handle(context.Background(), []string{"activate", "-identity-directory", t.TempDir()}, &out, &diag, func(context.Context, Options) (Result, error) { return Result{}, context.Canceled })
	if code != 130 || out.Len() != 0 || !strings.Contains(diag.String(), "inspect native service status") {
		t.Fatal("cancellation misstated service state")
	}
}
