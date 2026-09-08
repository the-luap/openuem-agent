package macbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCommandRejectsAmbiguousArgumentsWithoutTouchingOutput(t *testing.T) {
	o := fixtureOptions(t)
	valid := []string{"-agent", o.Agent, "-output", o.Output, "-version", o.Version, "-build", "42", "-architecture", o.Architecture}
	for _, args := range [][]string{nil, {"-agent", "relative-secret-path"}, append(append([]string{}, valid...), "-build", "43"), append(append([]string{}, valid...), "extra-secret"), {"-invitation", "private-token"}, {"-build", "0042"}} {
		var out, diagnostics bytes.Buffer
		code := command(context.Background(), args, &out, &diagnostics, func(context.Context, Options) (Result, error) {
			t.Fatal("invalid input reached filesystem assembly")
			return Result{}, nil
		})
		if code != 2 || out.Len() != 0 || strings.Contains(diagnostics.String(), "secret") || strings.Contains(diagnostics.String(), "private-token") {
			t.Fatal("invalid arguments were accepted or exposed")
		}
	}
	var out, diagnostics bytes.Buffer
	called := false
	code := command(context.Background(), valid, &out, &diagnostics, func(ctx context.Context, got Options) (Result, error) {
		called = true
		if got != o {
			t.Fatal("build arguments changed")
		}
		return Result{Published: true, Path: o.Output, RequiresReleaseSigning: true}, errors.New("raw error with private path")
	})
	var result Result
	if code != 1 || !called || json.Unmarshal(out.Bytes(), &result) != nil || !result.Published || !result.RequiresReleaseSigning || strings.Contains(diagnostics.String(), "private path") {
		t.Fatal("partial build lost its publication state or exposed a raw error")
	}
}

func TestCommandHelpAndCancellation(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if code := command(context.Background(), []string{"-help"}, &out, &diagnostics, func(context.Context, Options) (Result, error) { t.Fatal("help invoked assembly"); return Result{}, nil }); code != 0 || !strings.Contains(out.String(), "signing may change its bytes") {
		t.Fatal("help lost the signing-order requirement")
	}
	o := fixtureOptions(t)
	args := []string{"-agent", o.Agent, "-output", o.Output, "-version", o.Version, "-build", "42", "-architecture", o.Architecture}
	out.Reset()
	if code := command(context.Background(), args, &out, &diagnostics, func(context.Context, Options) (Result, error) { return Result{}, context.Canceled }); code != 130 || out.Len() != 0 {
		t.Fatal("cancellation reported a published bundle")
	}
}
