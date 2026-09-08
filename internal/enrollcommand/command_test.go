package enrollcommand

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

func commandArgs(o Options) []string {
	args := []string{"enroll", "-origin", o.Origin, "-tenant-id", strconv.Itoa(o.TenantID), "-site-id", strconv.Itoa(o.SiteID), "-invitation-file", o.InvitationFile, "-release-keys-file", o.ReleaseKeysFile, "-identity-directory", o.IdentityDirectory, "-staging-directory", o.StagingDirectory}
	if o.AcceptManagement {
		args = append(args, "-accept-management")
	}
	return args
}

func TestCommandRequiresExplicitConsentAndNeverEchoesArgumentsOrPrivateErrors(t *testing.T) {
	f := newCommandFixture(t)
	const secret = "isolated-sensitive-argument"
	for _, args := range [][]string{
		{"enroll", "-invitation", secret},
		{"enroll", "-tenant-id", secret},
		append(commandArgs(f.options), secret),
		commandArgs(func() Options { o := f.options; o.AcceptManagement = false; return o }()),
	} {
		var out, diagnostics bytes.Buffer
		handled, code := handle(context.Background(), args, &out, &diagnostics, func(context.Context, Options) (Result, error) {
			t.Fatal("invalid arguments invoked enrollment")
			return Result{}, nil
		})
		if !handled || code != 2 || out.Len() != 0 || strings.Contains(diagnostics.String(), secret) || !strings.Contains(diagnostics.String(), "consent") {
			t.Fatal("invalid command exposed input or omitted useful guidance")
		}
	}
	for _, err := range []error{errors.New(secret), fmt.Errorf("%s: %w", secret, ErrEnrollment), context.Canceled} {
		var out, diagnostics bytes.Buffer
		handled, code := handle(context.Background(), commandArgs(f.options), &out, &diagnostics, func(context.Context, Options) (Result, error) { return Result{}, err })
		if !handled || code == 0 || out.Len() != 0 || strings.Contains(diagnostics.String(), secret) {
			t.Fatal("private failure details escaped the command")
		}
		if errors.Is(err, context.Canceled) && code != 130 {
			t.Fatal("cancellation lost its exit status")
		}
	}
}

func TestCommandHelpDispatchAndPublicSuccessOutput(t *testing.T) {
	for _, args := range [][]string{nil, {"service"}, {"--openuem-verify-installer-signature"}} {
		if handled, _ := Handle(context.Background(), args, io.Discard, io.Discard); handled {
			t.Fatal("enrollment intercepted another entry point")
		}
	}
	var out, diagnostics bytes.Buffer
	if handled, code := Handle(context.Background(), []string{"enroll", "-help"}, &out, &diagnostics); !handled || code != 0 || diagnostics.Len() != 0 || !strings.Contains(out.String(), "management actions") {
		t.Fatal("help required native enrollment or omitted consent")
	}
	f := newCommandFixture(t)
	out.Reset()
	expected := Result{IdentityReady: true, DeviceID: "isolated-public-device", Organization: "Isolated organization", Site: "Isolated site", TenantID: 3, SiteID: 4, ReleaseDigest: f.release.Digest(), Release: "0.12.0"}
	if handled, code := handle(context.Background(), commandArgs(f.options), &out, &diagnostics, func(_ context.Context, o Options) (Result, error) {
		if o != f.options {
			t.Error("CLI changed the explicitly authorized options")
		}
		return expected, nil
	}); !handled || code != 0 || diagnostics.Len() != 0 {
		t.Fatal("successful enrollment was not reported")
	}
	var actual Result
	if err := json.Unmarshal(out.Bytes(), &actual); err != nil || actual != expected || strings.Contains(out.String(), f.config.Invitation) {
		t.Fatal("public result was malformed or contained the invitation", err)
	}
	out.Reset()
	if _, code := handle(context.Background(), commandArgs(f.options), &out, &diagnostics, func(context.Context, Options) (Result, error) { return expected, ErrCleanup }); code == 0 || out.Len() == 0 || !strings.Contains(diagnostics.String(), "enrollment completed") {
		t.Fatal("cleanup failure concealed the completed identity")
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("isolated output failure") }

func TestCommandOutputFailureDoesNotClaimEnrollmentWasRolledBack(t *testing.T) {
	f := newCommandFixture(t)
	var diagnostics bytes.Buffer
	_, code := handle(context.Background(), commandArgs(f.options), failedWriter{}, &diagnostics, func(context.Context, Options) (Result, error) { return Result{IdentityReady: true}, nil })
	if code == 0 || !strings.Contains(diagnostics.String(), "Enrollment finished") || strings.Contains(diagnostics.String(), "isolated output failure") {
		t.Fatal("failed output obscured durable enrollment")
	}
}
