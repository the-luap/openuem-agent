//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"runtime"

	"github.com/open-uem/openuem-agent/internal/activatecommand"
	"github.com/open-uem/openuem-agent/internal/enrollcommand"
	"github.com/open-uem/openuem-agent/internal/logger"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
	"github.com/open-uem/openuem-agent/internal/runtimeoptions"
	"github.com/open-uem/openuem-agent/internal/windowssoftware"
	"golang.org/x/sys/windows/svc"
)

func main() {
	if handled, code := windowssoftware.HandlePreflightHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if handled, code := windowssoftware.HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if handled, code := packagesignature.HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if handled, code := enrollcommand.Handle(context.Background(), os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	if handled, code := activatecommand.Handle(context.Background(), os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}

	// the agent will use two CPUs at maximum
	runtime.GOMAXPROCS(2)

	options, start, code := runtimeoptions.Read(os.Args[1:], os.Stdout, os.Stderr)
	if !start {
		os.Exit(code)
	}

	// Instantiate logger
	l := logger.New()

	// Instantiate service
	s := NewService(l, options)

	// Run service
	err := svc.Run("openuem-agent", s)
	if err != nil {
		log.Fatalf("could not run service: %v", err)
	}
}
