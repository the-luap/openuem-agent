//go:build linux

package main

import (
	"github.com/open-uem/openuem-agent/internal/logger"
	"os"
)

func main() {
	// Instantiate logger
	l := logger.New()

	// Instantiate service
	s := NewService(l)

	if err := s.Execute(); err != nil {
		os.Exit(1)
	}
}
