//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
)

type removalRecoveryProcesses struct {
	requestID string
	processes []removalProcess
	digest    string
}

func (*removalRecoveryProcesses) String() string {
	return "[private NetBird removal recovery processes]"
}
func (p *removalRecoveryProcesses) GoString() string           { return p.String() }
func (*removalRecoveryProcesses) MarshalJSON() ([]byte, error) { return nil, errRemovalProcesses }

// The original request derives the only permitted staging location. This is
// deliberately separate from fresh removal, whose process paths stay fixed.
func removalRecoveryProcessIdentifier(requestID, path string) string {
	if !netbirdcommand.ValidRequestID(requestID) {
		return ""
	}
	stage := "/Applications/" + removalStagePrefix + requestID
	switch path {
	case removalCLIExecutable, stage + removalCLIExecutable:
		return "netbird"
	case removalUIExecutable, stage + removalUIExecutable:
		return "io.netbird.client"
	default:
		return ""
	}
}

func (p removalProcess) validRecovery(requestID string) bool {
	return removalRecoveryProcessIdentifier(requestID, p.Path) != "" && p.validAt(p.Path)
}

func inspectNativeRemovalRecoveryProcesses(ctx context.Context, requestID string) (*removalRecoveryProcesses, error) {
	if !removalProcessesSupported() {
		return nil, errRemovalProcesses
	}
	return inspectRemovalRecoveryProcesses(ctx, requestID, removalProcessBackend{
		list: nativeRemovalPIDs, path: nativeRemovalPIDPath,
		inspect: func(ctx context.Context, pid int, path string) (removalProcess, error) {
			return nativeRemovalRecoveryProcess(ctx, requestID, pid, path)
		},
	})
}

func inspectRemovalRecoveryProcesses(parent context.Context, requestID string, backend removalProcessBackend) (*removalRecoveryProcesses, error) {
	if parent == nil || parent.Err() != nil || !netbirdcommand.ValidRequestID(requestID) {
		return nil, errRemovalProcesses
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	matches := func(path string) bool { return removalRecoveryProcessIdentifier(requestID, path) != "" }
	first, err := removalProcessSnapshotAt(ctx, backend, matches)
	if err != nil {
		return nil, errRemovalProcesses
	}
	second, err := removalProcessSnapshotAt(ctx, backend, matches)
	if err != nil || !reflect.DeepEqual(first, second) || ctx.Err() != nil {
		return nil, errRemovalProcesses
	}
	data, err := json.Marshal(struct {
		RequestID string
		Processes []removalProcess
	}{requestID, second})
	if err != nil {
		return nil, errRemovalProcesses
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-recovery-processes/v1\x00"), data...))
	clear(data)
	return &removalRecoveryProcesses{requestID, second, hex.EncodeToString(hash[:])}, nil
}
