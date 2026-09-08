//go:build darwin

package main

import (
	"context"
	"os"

	"github.com/open-uem/openuem-agent/internal/enrollcommand"
	"github.com/open-uem/openuem-agent/internal/logger"
)

func main() {
	if handled, code := enrollcommand.Handle(context.Background(), os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	// Instantiate logger
	l := logger.New()

	// Instantiate service
	s := NewService(l)

	s.Execute()
}
