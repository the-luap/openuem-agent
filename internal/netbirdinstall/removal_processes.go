package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"
)

var errRemovalProcesses = errors.New("the NetBird native process ownership could not be verified")
var errRemovalProcessGone = errors.New("the native process no longer exists")

const (
	removalCLIExecutable = "/Applications/NetBird.app/Contents/MacOS/netbird"
	removalUIExecutable  = "/Applications/NetBird.app/Contents/MacOS/netbird-ui"
	maxRemovalPIDs       = 8192
)

// A PID only locates a candidate. Audit is the kernel's complete process token,
// including the process generation; it must never be synthesized from a PID.
type removalProcess struct {
	PID                                 uint32
	Audit                               [8]uint32
	StartedSeconds, StartedMicroseconds uint64
	Path, CodeHash                      string
}

type removalProcessEvidence struct {
	processes []removalProcess
	digest    string
}

func (*removalProcessEvidence) String() string               { return "[private NetBird process ownership]" }
func (p *removalProcessEvidence) GoString() string           { return p.String() }
func (*removalProcessEvidence) MarshalJSON() ([]byte, error) { return nil, errRemovalProcesses }

type removalProcessBackend struct {
	list    func(context.Context) ([]int, error)
	path    func(context.Context, int) (string, error)
	inspect func(context.Context, int, string) (removalProcess, error)
}

func inspectNativeRemovalProcesses(ctx context.Context) (*removalProcessEvidence, error) {
	if !removalProcessesSupported() {
		return nil, errRemovalProcesses
	}
	return inspectRemovalProcesses(ctx, removalProcessBackend{nativeRemovalPIDs, nativeRemovalPIDPath, nativeRemovalProcess})
}

// Two complete candidate scans must agree. Gone unrelated candidates may be
// skipped; inaccessible processes and disappearing matched candidates cannot
// produce evidence. Empty process evidence alone never proves package absence.
func inspectRemovalProcesses(parent context.Context, backend removalProcessBackend) (*removalProcessEvidence, error) {
	if parent == nil || parent.Err() != nil || backend.list == nil || backend.path == nil || backend.inspect == nil {
		return nil, errRemovalProcesses
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	first, err := removalProcessSnapshot(ctx, backend)
	if err != nil {
		return nil, errRemovalProcesses
	}
	second, err := removalProcessSnapshot(ctx, backend)
	if err != nil || !reflect.DeepEqual(first, second) || ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	data, err := json.Marshal(second)
	if err != nil {
		return nil, errRemovalProcesses
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-processes/v1\x00"), data...))
	clear(data)
	return &removalProcessEvidence{second, hex.EncodeToString(hash[:])}, nil
}

func removalProcessSnapshot(ctx context.Context, backend removalProcessBackend) ([]removalProcess, error) {
	if ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	pids, err := backend.list(ctx)
	if err != nil || len(pids) == 0 || len(pids) > maxRemovalPIDs {
		return nil, errRemovalProcesses
	}
	seen := make(map[int]bool, len(pids))
	result := make([]removalProcess, 0)
	for _, pid := range pids {
		if pid < 0 || pid > 2147483647 || seen[pid] || ctx.Err() != nil {
			return nil, errRemovalProcesses
		}
		seen[pid] = true
		if pid == 0 {
			continue
		} // The kernel has no userspace executable.
		path, err := backend.path(ctx, pid)
		if errors.Is(err, errRemovalProcessGone) {
			continue
		}
		if err != nil || path == "" {
			return nil, errRemovalProcesses
		}
		if path != removalCLIExecutable && path != removalUIExecutable {
			continue
		}
		proof, err := backend.inspect(ctx, pid, path)
		if err != nil || !proof.valid() || proof.PID != uint32(pid) || proof.Path != path || len(result) >= 128 {
			return nil, errRemovalProcesses
		}
		result = append(result, proof)
	}
	if !seen[1] {
		return nil, errRemovalProcesses
	}
	slices.SortFunc(result, func(a, b removalProcess) int {
		if a.PID < b.PID {
			return -1
		}
		if a.PID > b.PID {
			return 1
		}
		return 0
	})
	return result, nil
}

func (p removalProcess) valid() bool {
	hash, err := hex.DecodeString(p.CodeHash)
	return p.PID > 1 && p.PID <= 2147483647 && p.Audit[5] == p.PID && p.Audit[7] != 0 && p.StartedSeconds > 0 && p.StartedMicroseconds < 1_000_000 && (p.Path == removalCLIExecutable || p.Path == removalUIExecutable) && err == nil && (len(hash) == 20 || len(hash) == 32) && hex.EncodeToString(hash) == p.CodeHash
}
