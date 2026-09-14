//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

type removalExecutionBackend struct {
	observe   func(context.Context) (*removalOwnership, error)
	stop      func(context.Context, *removalOwnership) error
	quiescent func(context.Context, string) error
	forget    func(context.Context) error
	absent    func(context.Context) error
}

func prepareNativeRemoval(ctx context.Context, requestID string, descriptor packageapi.Removal) (*Removal, error) {
	return prepareRemoval(ctx, "/", 0, requestID, descriptor, removalExecutionBackend{
		observe:   inspectNativeRemovalOwnership,
		stop:      stopNativeRemoval,
		quiescent: nativeRemovalQuiescent,
		forget: func(ctx context.Context) error {
			return runNativeInstaller(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--forget", "io.netbird.client"})
		},
		absent: func(ctx context.Context) error {
			return verifyNativeRemovalAbsence(ctx, "/", 0, readNativePackage, nativeRemovalQuiescent)
		},
	})
}

func prepareRemoval(ctx context.Context, root string, owner uint32, requestID string, descriptor packageapi.Removal, backend removalExecutionBackend) (*Removal, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !netbirdcommand.ValidRequestID(requestID) || !descriptor.Valid() || backend.observe == nil || backend.stop == nil || backend.quiescent == nil || backend.forget == nil || backend.absent == nil {
		return nil, ErrRemoval
	}
	observed, err := backend.observe(ctx)
	if err != nil || observed == nil || observed.files == nil || observed.processes == nil || observed.descriptor != descriptor || !executableRemovalFiles(observed.files.objects) || removalNoStages(ctx, root, owner) != nil {
		return nil, ErrRemoval
	}
	var held []*os.File
	closeHeld := func() error {
		var result error
		for _, file := range held {
			if file.Close() != nil {
				result = ErrRemoval
			}
		}
		held = nil
		return result
	}
	objects, data, err := removalFileSnapshot(ctx, root, owner, &held)
	for _, value := range data {
		clear(value)
	}
	if err != nil || !reflect.DeepEqual(objects, observed.files.objects) {
		closeHeld()
		return nil, ErrRemoval
	}
	var stage *removalStaging
	return &Removal{
		run: func(ctx context.Context) error {
			current, err := backend.observe(ctx)
			if err != nil || current == nil || current.descriptor != descriptor || ctx.Err() != nil {
				return ErrRemoval
			}
			stage, err = newRemovalStaging(ctx, root, owner, requestID, current)
			if err != nil {
				return ErrRemoval
			}
			if backend.stop(ctx, current) != nil || stage.move(ctx) != nil {
				return ErrRemoval
			}
			stagedApp := filepath.Join(stage.path, removalApp)
			if backend.quiescent(ctx, stagedApp) != nil || stage.verify(ctx) != nil || stage.verifyReceipts(ctx) != nil || stage.purge(ctx) != nil {
				return ErrRemoval
			}
			if stage.verifyReceipts(ctx) != nil || backend.forget(ctx) != nil || stage.sourcesAbsent(ctx) != nil || backend.quiescent(ctx, stagedApp) != nil || stage.finish(ctx) != nil || backend.absent(ctx) != nil {
				return ErrRemoval
			}
			return nil
		},
		close: func() error {
			err := closeHeld()
			if stage != nil && stage.close() != nil {
				err = ErrRemoval
			}
			return err
		},
	}, nil
}

func nativeInspectRemoval(ctx context.Context) (packageapi.Removal, bool, error) {
	if removalNoStages(ctx, "/", 0) != nil {
		return packageapi.Removal{}, false, ErrRemoval
	}
	if observed, err := inspectNativeRemovalOwnership(ctx); err == nil {
		return observed.descriptor, false, nil
	}
	if verifyNativeRemovalAbsence(ctx, "/", 0, readNativePackage, nativeRemovalQuiescent) == nil {
		return packageapi.Removal{}, true, nil
	}
	return packageapi.Removal{}, false, ErrRemoval
}

func stopNativeRemoval(ctx context.Context, expected *removalOwnership) error {
	job, err := inspectRemovalLaunchd(ctx, !expected.files.objects[removalCLI].Missing, nativeRemovalJob)
	if err != nil || job != expected.job {
		return ErrRemoval
	}
	if job.Loaded {
		if runNativeInstaller(ctx, "/bin/launchctl", []string{"bootout", "system/netbird"}) != nil {
			return ErrRemoval
		}
		if waitRemoval(ctx, 5*time.Second, func() (bool, error) {
			state, err := inspectRemovalLaunchd(ctx, true, nativeRemovalJob)
			return !state.Loaded, err
		}) != nil {
			return ErrRemoval
		}
	}
	for _, process := range expected.processes.processes {
		if nativeSignalRemovalProcess(ctx, process, false) != nil {
			return ErrRemoval
		}
	}
	if err := waitRemoval(ctx, 3*time.Second, func() (bool, error) { return removalProcessesQuiet(ctx, expected.processes.processes) }); err != nil {
		if ctx.Err() != nil || !errors.Is(err, errRemovalWait) {
			return ErrRemoval
		}
		for _, process := range expected.processes.processes {
			if nativeSignalRemovalProcess(ctx, process, true) != nil {
				return ErrRemoval
			}
		}
		if waitRemoval(ctx, 3*time.Second, func() (bool, error) { return removalProcessesQuiet(ctx, expected.processes.processes) }) != nil {
			return ErrRemoval
		}
	}
	return nativeRemovalQuiescent(ctx, "")
}

var errRemovalWait = errors.New("the owned NetBird processes did not exit before the deadline")

func waitRemoval(ctx context.Context, limit time.Duration, check func() (bool, error)) error {
	if ctx == nil || ctx.Err() != nil || check == nil {
		return ErrRemoval
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		done, err := check()
		if err != nil || ctx.Err() != nil {
			return ErrRemoval
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrRemoval
		case <-deadline.C:
			return errRemovalWait
		case <-ticker.C:
		}
	}
}

func nativeRemovalQuiescent(ctx context.Context, stagedApp string) error {
	for round := 0; round < 2; round++ {
		job, err := inspectRemovalLaunchd(ctx, true, nativeRemovalJob)
		if err != nil || job.Loaded || removalNoProcesses(ctx, stagedApp, nativeRemovalPIDs, nativeRemovalPIDPath) != nil {
			return ErrRemoval
		}
	}
	return nil
}

func removalNoProcesses(ctx context.Context, stagedApp string, list func(context.Context) ([]int, error), path func(context.Context, int) (string, error)) error {
	if ctx == nil || ctx.Err() != nil || list == nil || path == nil || stagedApp != "" && (!filepath.IsAbs(stagedApp) || filepath.Clean(stagedApp) != stagedApp) {
		return ErrRemoval
	}
	pids, err := list(ctx)
	if err != nil || len(pids) == 0 || len(pids) > maxRemovalPIDs {
		return ErrRemoval
	}
	seen := make(map[int]bool)
	for _, pid := range pids {
		if pid < 0 || pid > 2147483647 || seen[pid] || ctx.Err() != nil {
			return ErrRemoval
		}
		seen[pid] = true
		if pid == 0 {
			continue
		}
		name, err := path(ctx, pid)
		if err == errRemovalProcessGone {
			continue
		}
		if err != nil || name == "" || name == removalCLIExecutable || name == removalUIExecutable || stagedApp != "" && (name == filepath.Join(stagedApp, "Contents/MacOS/netbird") || name == filepath.Join(stagedApp, "Contents/MacOS/netbird-ui")) {
			return ErrRemoval
		}
	}
	if !seen[1] {
		return ErrRemoval
	}
	return nil
}

func verifyNativeRemovalAbsence(ctx context.Context, root string, owner uint32, read packageReader, quiet func(context.Context, string) error) error {
	if ctx == nil || ctx.Err() != nil || read == nil || quiet == nil {
		return ErrRemoval
	}
	for round := 0; round < 2; round++ {
		if removalSourcesAbsent(ctx, root, owner, true) != nil || quiet(ctx, "") != nil {
			return ErrRemoval
		}
		if present, err := nativeRemovalReceiptPresent(ctx, read); err != nil || present {
			return ErrRemoval
		}
	}
	if ctx.Err() != nil {
		return ErrRemoval
	}
	return nil
}
