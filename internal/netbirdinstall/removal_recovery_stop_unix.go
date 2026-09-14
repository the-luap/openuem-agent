//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

type removalRecoveryStopBackend struct {
	job       removalJobReader
	bootout   func(context.Context) error
	signal    func(context.Context, removalProcess, bool) error
	quiet     func(context.Context, []removalProcess) (bool, error)
	quiescent func(context.Context, string) error
}

// Only a separately admitted recovery owner may call this mutator. The public
// command service does not expose recovery until its journal contract is wired.
func stopNativeRemovalRecovery(ctx context.Context, expected *removalRecoveryOwnership) error {
	if !nativeRemovalExecutionAvailable() || expected == nil || expected.processes == nil {
		return ErrRemoval
	}
	requestID := expected.processes.requestID
	return stopRemovalRecoveryRuntime(ctx, expected, removalRecoveryStopBackend{
		job: nativeRemovalJob,
		bootout: func(ctx context.Context) error {
			return runNativeInstaller(ctx, "/bin/launchctl", []string{"bootout", "system/netbird"})
		},
		signal: func(ctx context.Context, process removalProcess, force bool) error {
			return nativeSignalRemovalRecoveryProcess(ctx, requestID, process, force)
		},
		quiet: func(ctx context.Context, processes []removalProcess) (bool, error) {
			return removalRecoveryProcessesQuiet(ctx, requestID, processes)
		},
		quiescent: nativeRemovalQuiescent,
	})
}

func stopRemovalRecoveryRuntime(ctx context.Context, expected *removalRecoveryOwnership, backend removalRecoveryStopBackend) error {
	if ctx == nil || ctx.Err() != nil || expected == nil || expected.files == nil || expected.files.manifest == nil || expected.processes == nil || !netbirdcommand.ValidDigest(expected.digest) || backend.job == nil || backend.bootout == nil || backend.signal == nil || backend.quiet == nil || backend.quiescent == nil {
		return ErrRemoval
	}
	requestID := expected.files.manifest.manifest.RequestID
	if !netbirdcommand.ValidRequestID(requestID) || expected.processes.requestID != requestID || len(expected.processes.processes) > 128 {
		return ErrRemoval
	}
	seen := map[uint32]bool{}
	daemonMatched := expected.job.PID == 0
	for _, process := range expected.processes.processes {
		if !process.validRecovery(requestID) || seen[process.PID] {
			return ErrRemoval
		}
		seen[process.PID] = true
		if process.PID == expected.job.PID {
			daemonMatched = removalRecoveryProcessIdentifier(requestID, process.Path) == "netbird" && process.Audit[1] == 0 && process.Audit[3] == 0
		}
	}
	if !daemonMatched {
		return ErrRemoval
	}
	cli, ok := expected.files.manifest.manifest.Objects[removalCLI]
	if !ok {
		return ErrRemoval
	}
	job, err := inspectRemovalLaunchd(ctx, !cli.Missing, backend.job)
	if err != nil || job != expected.job {
		return ErrRemoval
	}
	if job.Loaded {
		if backend.bootout(ctx) != nil {
			return ErrRemoval
		}
		if waitRemoval(ctx, 5*time.Second, func() (bool, error) {
			current, err := inspectRemovalLaunchd(ctx, !cli.Missing, backend.job)
			return !current.Loaded, err
		}) != nil {
			return ErrRemoval
		}
	}
	for _, process := range expected.processes.processes {
		if backend.signal(ctx, process, false) != nil {
			return ErrRemoval
		}
	}
	if err := waitRemoval(ctx, 3*time.Second, func() (bool, error) { return backend.quiet(ctx, expected.processes.processes) }); err != nil {
		if ctx.Err() != nil || !errors.Is(err, errRemovalWait) {
			return ErrRemoval
		}
		for _, process := range expected.processes.processes {
			if backend.signal(ctx, process, true) != nil {
				return ErrRemoval
			}
		}
		if waitRemoval(ctx, 3*time.Second, func() (bool, error) { return backend.quiet(ctx, expected.processes.processes) }) != nil {
			return ErrRemoval
		}
	}
	return backend.quiescent(ctx, "/Applications/"+removalStagePrefix+requestID+"/"+removalApp)
}
