//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

type removalRecoveryOwnership struct {
	files     *removalRecoveryFiles
	processes *removalRecoveryProcesses
	receipts  *removalRecoveryReceipts
	job       removalLaunchdEvidence
	digest    string
}

func (*removalRecoveryOwnership) String() string {
	return "[private NetBird removal recovery ownership]"
}
func (r *removalRecoveryOwnership) GoString() string           { return r.String() }
func (*removalRecoveryOwnership) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

type removalRecoveryOwnershipBackend struct {
	files     func(context.Context, *[]*os.File) (*removalRecoveryFiles, error)
	processes func(context.Context) (*removalRecoveryProcesses, error)
	job       removalJobReader
	read      packageReader
}

func inspectNativeRemovalRecoveryOwnership(ctx context.Context, requestID string, descriptor packageapi.Removal) (*removalRecoveryOwnership, error) {
	if !InstallationSupported() || !removalProcessesSupported() || descriptor.Platform != "macos" || descriptor.Architecture != runtime.GOARCH {
		return nil, ErrRemoval
	}
	return inspectRemovalRecoveryOwnership(ctx, requestID, descriptor, removalRecoveryOwnershipBackend{
		files: func(ctx context.Context, held *[]*os.File) (*removalRecoveryFiles, error) {
			return inspectRemovalRecoveryFilesHeld(ctx, "/", 0, requestID, descriptor, held)
		},
		processes: func(ctx context.Context) (*removalRecoveryProcesses, error) {
			return inspectNativeRemovalRecoveryProcesses(ctx, requestID)
		},
		job: nativeRemovalJob, read: readNativePackage,
	})
}

// Two complete rounds bind current files, OS receipts, typed launchd and exact
// original/staged process instances. The original file handles stay open across
// both rounds. This private evidence neither releases a journal nor runs recovery.
func inspectRemovalRecoveryOwnership(parent context.Context, requestID string, descriptor packageapi.Removal, backend removalRecoveryOwnershipBackend) (*removalRecoveryOwnership, error) {
	if parent == nil || parent.Err() != nil || !netbirdcommand.ValidRequestID(requestID) || !descriptor.Valid() || descriptor.Platform != "macos" || backend.files == nil || backend.processes == nil || backend.job == nil || backend.read == nil {
		return nil, ErrRemoval
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	var held []*os.File
	defer func() {
		for _, file := range held {
			_ = file.Close()
		}
	}()
	var before *removalRecoveryOwnership
	for round := 0; round < 2; round++ {
		var retain *[]*os.File
		if round == 0 {
			retain = &held
		}
		files, err := backend.files(ctx, retain)
		if err != nil || files == nil || files.manifest == nil || files.manifest.manifest.RequestID != requestID || files.manifest.manifest.Descriptor != descriptor || !netbirdcommand.ValidDigest(files.digest) {
			return nil, ErrRemoval
		}
		cli, ok := files.manifest.manifest.Objects[removalCLI]
		if !ok {
			return nil, ErrRemoval
		}
		receipts, err := inspectRemovalRecoveryReceipts(ctx, files, backend.read)
		if err != nil {
			return nil, ErrRemoval
		}
		// The original owned job may still refer to a CLI link already moved.
		// No staged executable is accepted as an alternate launchd configuration.
		job, err := inspectRemovalLaunchd(ctx, !cli.Missing, backend.job)
		if err != nil {
			return nil, ErrRemoval
		}
		processes, err := backend.processes(ctx)
		if err != nil || processes == nil || processes.requestID != requestID || !netbirdcommand.ValidDigest(processes.digest) || ctx.Err() != nil {
			return nil, ErrRemoval
		}
		if job.PID > 0 {
			matched := false
			for _, process := range processes.processes {
				if process.PID == job.PID {
					matched = process.validRecovery(requestID) && removalRecoveryProcessIdentifier(requestID, process.Path) == "netbird" && process.Audit[1] == 0 && process.Audit[3] == 0
				}
			}
			if !matched {
				return nil, ErrRemoval
			}
		}
		current := &removalRecoveryOwnership{files: files, processes: processes, receipts: receipts, job: job}
		if round == 0 {
			before = current
		} else if !reflect.DeepEqual(before, current) {
			return nil, ErrRemoval
		}
	}
	data, err := json.Marshal(struct {
		RequestID, Files, Processes, Receipts string
		Job                                   removalLaunchdEvidence
	}{requestID, before.files.digest, before.processes.digest, before.receipts.digest, before.job})
	if err != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-recovery-ownership/v1\x00"), data...))
	clear(data)
	before.digest = hex.EncodeToString(hash[:])
	return before, nil
}
