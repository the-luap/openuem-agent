//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-agent/internal/agent"
	"github.com/open-uem/openuem-agent/internal/logger"
	"github.com/open-uem/openuem-agent/internal/runtimeoptions"
	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
)

type OpenUEMService struct {
	Logger  *logger.OpenUEMLogger
	factory lifecycle.Factory
}

func NewService(l *logger.OpenUEMLogger, options runtimeoptions.Options) *OpenUEMService {
	return &OpenUEMService{Logger: l, factory: func(ctx context.Context) (lifecycle.Runtime, error) {
		var a *agent.Agent
		var err error
		if options.IdentityDirectory != "" {
			a, err = agent.NewIndividual(ctx, options.IdentityDirectory)
		} else {
			a, err = agent.New(ctx)
		}
		if err != nil {
			return nil, err
		}
		return a, nil
	}}
}

func (s *OpenUEMService) Execute() error {
	// Install handlers before opening protected state or starting any agent work.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer s.Logger.Close()
	err := lifecycle.Run(ctx, s.factory, func(phase lifecycle.Phase) {
		switch phase {
		case lifecycle.Ready:
			log.Print("[INFO]: agent service initialized")
		case lifecycle.Stopping:
			log.Print("[INFO]: agent service is stopping")
		}
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	if err != nil {
		log.Print("[ERROR]: agent service initialization failed")
	}
	return err
}
