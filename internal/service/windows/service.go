//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/open-uem/openuem-agent/internal/agent"
	"github.com/open-uem/openuem-agent/internal/logger"
	"github.com/open-uem/openuem-agent/internal/runtimeoptions"
	"github.com/open-uem/openuem-agent/internal/service/lifecycle"
	"golang.org/x/sys/windows/svc"
)

type OpenUEMService struct {
	Logger  *logger.OpenUEMLogger
	factory lifecycle.Factory
}

func NewService(l *logger.OpenUEMLogger, options runtimeoptions.Options) *OpenUEMService {
	return &OpenUEMService{Logger: l, factory: func(ctx context.Context) (lifecycle.Runtime, error) {
		return agent.NewServiceRuntime(ctx, options.IdentityDirectory)
	}}
}

func (s *OpenUEMService) Execute(args []string, controls <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	defer s.Logger.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	phases := make(chan lifecycle.Phase)
	finished := make(chan error, 1)
	go func() { finished <- lifecycle.Run(ctx, s.factory, func(phase lifecycle.Phase) { phases <- phase }) }()
	status := svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30000}
	// Report finite local initialization/cleanup progress. Network recovery uses
	// an initialized controller that accepts controls, not endless StartPending.
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	requestStop := func() {
		cancel()
		if status.State != svc.StopPending {
			status = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000}
			changes <- status
		}
	}
	for {
		select {
		case <-heartbeat.C:
			if status.State == svc.StartPending || status.State == svc.StopPending {
				status.CheckPoint++
				changes <- status
			}
		case phase := <-phases:
			switch phase {
			case lifecycle.Initializing:
				if ctx.Err() != nil {
					continue
				}
				status = svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30000}
			case lifecycle.Ready:
				if ctx.Err() != nil {
					continue
				}
				log.Print("[INFO]: agent service initialized")
				if status.State == svc.Running {
					continue
				}
				status = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			case lifecycle.Recovering:
				if ctx.Err() != nil {
					continue
				}
				log.Print("[WARN]: service controller is running; agent identity recovery is pending")
				status = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			case lifecycle.Stopping:
				if status.State == svc.StopPending {
					continue
				}
				status = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 30000}
			}
			changes <- status
		case control, open := <-controls:
			if !open {
				controls = nil
				requestStop()
				continue
			}
			switch control.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				log.Print("[INFO]: service stop requested")
				requestStop()
			default:
				log.Print("[WARN]: unsupported service control ignored")
			}
		case err := <-finished:
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Print("[ERROR]: agent service initialization failed")
				return true, 1
			}
			// svc.Run publishes Stopped only after all owned cleanup has finished.
			return false, 0
		}
	}
}
