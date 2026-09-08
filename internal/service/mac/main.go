//go:build darwin

package main

import (
	"context"
	"os"

	"github.com/open-uem/openuem-agent/internal/enrollcommand"
	"github.com/open-uem/openuem-agent/internal/logger"
	"github.com/open-uem/openuem-agent/internal/runtimeoptions"
)

func main() {
	if handled, code := enrollcommand.Handle(context.Background(), os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	options, start, code := runtimeoptions.Read(os.Args[1:], os.Stdout, os.Stderr)
	if !start {
		os.Exit(code)
	}

	// Instantiate logger
	l := logger.New()

	// Instantiate service
	s := NewService(l, options)

	if err := s.Execute(); err != nil {
		os.Exit(1)
	}
}
