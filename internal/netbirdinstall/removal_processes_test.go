package netbirdinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func ownedRemovalProcess(pid uint32, path string) removalProcess {
	p := removalProcess{PID: pid, Path: path, StartedSeconds: 1789360000, StartedMicroseconds: 123, CodeHash: strings.Repeat("a", 40)}
	p.Audit[5], p.Audit[7] = pid, 29
	return p
}

func TestRemovalProcessEvidenceRequiresTwoCompleteStableNativeScans(t *testing.T) {
	queries, proofs := 0, 0
	backend := removalProcessBackend{
		list: func(context.Context) ([]int, error) {
			queries++
			if queries%2 == 1 {
				return []int{45, 1, 0, 46}, nil
			}
			return []int{0, 46, 1, 45}, nil
		},
		path: func(ctx context.Context, pid int) (string, error) {
			if pid == 45 {
				return removalCLIExecutable, nil
			}
			if pid == 46 {
				return removalUIExecutable, nil
			}
			return "/sbin/launchd", nil
		},
		inspect: func(ctx context.Context, pid int, path string) (removalProcess, error) {
			proofs++
			return ownedRemovalProcess(uint32(pid), path), nil
		},
	}
	first, err := inspectRemovalProcesses(t.Context(), backend)
	if err != nil || len(first.processes) != 2 || len(first.digest) != 64 || queries != 2 || proofs != 4 {
		t.Fatal("complete native process ownership missing", err)
	}
	second, err := inspectRemovalProcesses(t.Context(), backend)
	if err != nil || first.digest != second.digest {
		t.Fatal("enumeration order changed ownership", err)
	}
	if data, err := json.Marshal(first); err == nil || len(data) != 0 {
		t.Fatal("private process evidence serialized")
	}
	for _, value := range []string{fmt.Sprint(first), fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", first)} {
		if strings.Contains(value, "Applications") || strings.Contains(value, first.digest) {
			t.Fatal("private native process evidence escaped")
		}
	}
}

func TestRemovalProcessInspectionRejectsPartialAmbiguousOrChangedEvidence(t *testing.T) {
	for _, kind := range []string{"list-failure", "empty-list", "over-limit", "duplicate-pid", "negative-pid", "invalid-pid", "path-failure", "empty-path", "inspection-failure", "matched-disappears", "changed-pid", "changed-path", "missing-token", "wrong-token-pid", "missing-generation", "missing-start", "invalid-microseconds", "invalid-code-hash", "changed-generation", "changed-code-hash", "changed-start", "new-process", "lost-process", "inaccessible-unrelated", "too-many-matches"} {
		t.Run(kind, func(t *testing.T) {
			lists := 0
			backend := removalProcessBackend{
				list: func(context.Context) ([]int, error) {
					lists++
					switch kind {
					case "list-failure":
						return nil, errors.New("owned private process diagnostics")
					case "empty-list":
						return nil, nil
					case "over-limit":
						return make([]int, maxRemovalPIDs+1), nil
					case "duplicate-pid":
						return []int{45, 45}, nil
					case "negative-pid":
						return []int{-1}, nil
					case "invalid-pid":
						return []int{2147483647, 45}, nil
					case "too-many-matches":
						pids := make([]int, 129)
						for i := range pids {
							pids[i] = 45 + i
						}
						return pids, nil
					case "new-process":
						if lists == 2 {
							return []int{1, 45, 46}, nil
						}
					case "lost-process":
						if lists == 2 {
							return []int{1}, nil
						}
					}
					return []int{1, 45}, nil
				},
				path: func(ctx context.Context, pid int) (string, error) {
					if pid == 1 {
						if kind == "inaccessible-unrelated" {
							return "", errRemovalProcesses
						}
						return "/sbin/launchd", nil
					}
					if kind == "path-failure" || pid == 2147483647 {
						return "", errRemovalProcesses
					}
					if kind == "empty-path" {
						return "", nil
					}
					return removalCLIExecutable, nil
				},
				inspect: func(ctx context.Context, pid int, path string) (removalProcess, error) {
					p := ownedRemovalProcess(uint32(pid), path)
					switch kind {
					case "inspection-failure":
						return removalProcess{}, errRemovalProcesses
					case "matched-disappears":
						return removalProcess{}, errRemovalProcessGone
					case "changed-pid":
						p.PID++
					case "changed-path":
						p.Path = removalUIExecutable
					case "missing-token":
						p.Audit = [8]uint32{}
					case "wrong-token-pid":
						p.Audit[5]++
					case "missing-generation":
						p.Audit[7] = 0
					case "missing-start":
						p.StartedSeconds = 0
					case "invalid-microseconds":
						p.StartedMicroseconds = 1_000_000
					case "invalid-code-hash":
						p.CodeHash = strings.Repeat("A", 40)
					case "changed-generation":
						if lists == 2 {
							p.Audit[7]++
						}
					case "changed-code-hash":
						if lists == 2 {
							p.CodeHash = strings.Repeat("b", 40)
						}
					case "changed-start":
						if lists == 2 {
							p.StartedSeconds++
						}
					}
					return p, nil
				},
			}
			if result, err := inspectRemovalProcesses(t.Context(), backend); err != errRemovalProcesses || result != nil {
				t.Fatal("incomplete native process ownership accepted", kind, err)
			}
		})
	}
}

func TestRemovalProcessInspectionDoesNotUseNamesOrEmptyInventoryAsAbsence(t *testing.T) {
	proofs := 0
	backend := removalProcessBackend{
		list: func(context.Context) ([]int, error) { return []int{1, 45, 46}, nil },
		path: func(ctx context.Context, pid int) (string, error) {
			if pid == 46 {
				return "", errRemovalProcessGone
			}
			return "/owned/unrelated/netbird", nil
		},
		inspect: func(context.Context, int, string) (removalProcess, error) {
			proofs++
			return removalProcess{}, errRemovalProcesses
		},
	}
	result, err := inspectRemovalProcesses(t.Context(), backend)
	if err != nil || len(result.processes) != 0 || proofs != 0 {
		t.Fatal("same process name was treated as package ownership", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := inspectRemovalProcesses(ctx, backend); err != errRemovalProcesses || result != nil {
		t.Fatal("cancelled native inspection succeeded")
	}
}

func TestRemovalProcessInspectionCancellationJoinsNativeLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	backend := removalProcessBackend{
		list: func(context.Context) ([]int, error) { return []int{45}, nil },
		path: func(context.Context, int) (string, error) { return removalCLIExecutable, nil },
		inspect: func(context.Context, int, string) (removalProcess, error) {
			close(entered)
			<-release
			return ownedRemovalProcess(45, removalCLIExecutable), nil
		},
	}
	go func() { _, err := inspectRemovalProcesses(ctx, backend); done <- err }()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("native callback escaped cancellation joining")
	default:
	}
	close(release)
	if err := <-done; err != errRemovalProcesses {
		t.Fatal("cancelled native lookup supplied ownership", err)
	}
}
