//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"runtime"

	"github.com/open-uem/openuem-agent/internal/enrollcommand"
	"github.com/open-uem/openuem-agent/internal/logger"
	"github.com/open-uem/openuem-agent/internal/packagesignature"
	"golang.org/x/sys/windows/svc"
)

func main() {
	if handled, code := packagesignature.HandleHelper(os.Args[1:]); handled {
		os.Exit(code)
	}
	if handled, code := enrollcommand.Handle(context.Background(), os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}

	// the agent will use two CPUs at maximum
	runtime.GOMAXPROCS(2)

	// Instantiate logger
	l := logger.New()

	// Instantiate service
	s := NewService(l)

	// Run service
	err := svc.Run("openuem-agent", s)
	if err != nil {
		log.Fatalf("could not run service: %v", err)
	}
}
