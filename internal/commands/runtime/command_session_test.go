package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCommandSessionOwnedProcess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NB_SETUP_KEY", "inherited-wrong-key")
	t.Setenv("NB_MANAGEMENT_URL", "https://wrong.example.test")
	t.Setenv("nb_profile", "wrong-profile")
	session := &CommandSession{}
	args := []string{"-test.run=TestCommandSessionChild", "--", "literal", "--profile", "literal; $(touch forbidden) `id` & \"quoted\""}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := session.Run(ctx, executable, args, []string{"OPENUEM_COMMAND_CHILD=1", "NB_SETUP_KEY=owned-key"}); err != nil {
		t.Fatal(err)
	}
	args = []string{"-test.run=TestCommandSessionChild", "--", "failure"}
	err = session.Run(ctx, executable, args, []string{"OPENUEM_COMMAND_CHILD=1"})
	if err == nil || strings.Contains(err.Error(), "owned-private-output") {
		t.Fatal("failure output was exposed or ignored")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = session.Run(ctx, executable, []string{"-test.run=TestCommandSessionChild", "--", "wait"}, []string{"OPENUEM_COMMAND_CHILD=1"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatal("process did not respect deadline")
	}
	if err := session.Run(context.Background(), "relative-binary", nil, nil); err == nil {
		t.Fatal("relative executable accepted")
	}
}

func TestCommandSessionChild(t *testing.T) {
	if os.Getenv("OPENUEM_COMMAND_CHILD") != "1" {
		return
	}
	i := 0
	for i < len(os.Args) && os.Args[i] != "--" {
		i++
	}
	if i+1 >= len(os.Args) {
		os.Exit(91)
	}
	switch os.Args[i+1] {
	case "literal":
		want := []string{"--profile", "literal; $(touch forbidden) `id` & \"quoted\""}
		if !reflect.DeepEqual(os.Args[i+2:], want) || os.Getenv("NB_SETUP_KEY") != "owned-key" || os.Getenv("NB_MANAGEMENT_URL") != "" || os.Getenv("nb_profile") != "" {
			os.Exit(92)
		}
	case "failure":
		for i := 0; i < 4096; i++ {
			fmt.Fprintln(os.Stdout, strings.Repeat("owned-private-output", 256))
			fmt.Fprintln(os.Stderr, "owned-private-output")
		}
		os.Exit(93)
	case "wait":
		time.Sleep(time.Minute)
	default:
		os.Exit(94)
	}
	os.Exit(0)
}

func TestCommandSessionEnvironmentUsesSelectedIdentity(t *testing.T) {
	t.Setenv("OPENUEM_SESSION_SERVICE_ONLY", "service-profile")
	got := commandEnvironment([]string{"USERPROFILE=selected-profile", "NB_SETUP_KEY=inherited", "nb_management_url=https://wrong.test"}, []string{"HOME=selected-home"}, []string{"NB_SETUP_KEY=owned-key"})
	want := []string{"USERPROFILE=selected-profile", "HOME=selected-home", "NB_SETUP_KEY=owned-key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("selected identity environment was replaced or inherited configuration survived")
	}
}
