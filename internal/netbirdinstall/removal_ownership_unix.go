//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

type removalOwnership struct {
	files      *removalFileEvidence
	processes  *removalProcessEvidence
	job        removalLaunchdEvidence
	descriptor packageapi.Removal
}

func (*removalOwnership) String() string               { return "[private native NetBird removal ownership]" }
func (p *removalOwnership) GoString() string           { return p.String() }
func (*removalOwnership) MarshalJSON() ([]byte, error) { return nil, errRemovalProcesses }

type removalOwnershipBackend struct {
	files     func(context.Context) (*removalFileEvidence, error)
	processes func(context.Context) (*removalProcessEvidence, error)
	job       removalJobReader
}

// Only a configured removal owner may expose this complete observed
// descriptor. This private inspection does not admit, stop or remove anything.
func inspectNativeRemovalOwnership(ctx context.Context) (*removalOwnership, error) {
	if !InstallationSupported() || !removalProcessesSupported() {
		return nil, errRemovalProcesses
	}
	return inspectRemovalOwnership(ctx, removalOwnershipBackend{inspectNativeRemovalFiles, inspectNativeRemovalProcesses, nativeRemovalJob})
}

func inspectRemovalOwnership(parent context.Context, backend removalOwnershipBackend) (*removalOwnership, error) {
	if parent == nil || parent.Err() != nil || backend.files == nil || backend.processes == nil || backend.job == nil {
		return nil, errRemovalProcesses
	}
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	files, err := backend.files(ctx)
	if err != nil || files == nil || files.digest == "" {
		return nil, errRemovalProcesses
	}
	cli, ok := files.objects[removalCLI]
	if !ok {
		return nil, errRemovalProcesses
	}
	job, err := inspectRemovalLaunchd(ctx, !cli.Missing, backend.job)
	if err != nil {
		return nil, errRemovalProcesses
	}
	processes, err := backend.processes(ctx)
	if err != nil || processes == nil || processes.digest == "" {
		return nil, errRemovalProcesses
	}
	if job.PID > 0 {
		matched := false
		for _, p := range processes.processes {
			if p.PID == job.PID {
				matched = p.valid() && p.Path == removalCLIExecutable && p.Audit[1] == 0 && p.Audit[3] == 0
			}
		}
		if !matched {
			return nil, errRemovalProcesses
		}
	}
	afterFiles, err := backend.files(ctx)
	if err != nil || afterFiles == nil || afterFiles.digest != files.digest || ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	afterJob, err := inspectRemovalLaunchd(ctx, !cli.Missing, backend.job)
	if err != nil || afterJob != job {
		return nil, errRemovalProcesses
	}
	afterProcesses, err := backend.processes(ctx)
	if err != nil || afterProcesses == nil || afterProcesses.digest != processes.digest || ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	data, err := json.Marshal(struct {
		Files, Processes string
		Job              removalLaunchdEvidence
	}{files.digest, processes.digest, job})
	if err != nil {
		return nil, errRemovalProcesses
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/native-removal-state/v1\x00"), data...))
	clear(data)
	descriptor := packageapi.Removal{Schema: packageapi.Schema, Platform: "macos", Architecture: files.architecture, Format: "pkg", PackageID: "io.netbird.client", Version: files.version, StateDigest: hex.EncodeToString(hash[:])}
	if !descriptor.Valid() {
		return nil, errRemovalProcesses
	}
	return &removalOwnership{files, processes, job, descriptor}, nil
}
