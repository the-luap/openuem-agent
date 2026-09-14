//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func ownedRecoveryProcessBackend(paths map[int]string) removalProcessBackend {
	return removalProcessBackend{
		list: func(context.Context) ([]int, error) {
			pids := []int{0, 1}
			for pid := range paths {
				pids = append(pids, pid)
			}
			return pids, nil
		},
		path: func(ctx context.Context, pid int) (string, error) {
			if pid == 1 {
				return "/sbin/launchd", nil
			}
			return paths[pid], nil
		},
		inspect: func(ctx context.Context, pid int, path string) (removalProcess, error) {
			return ownedRemovalProcess(uint32(pid), path), nil
		},
	}
}

func TestRemovalRecoveryProcessesBindOnlyExactOriginalAndSelectedStagedPaths(t *testing.T) {
	stage := "/Applications/" + removalStagePrefix + ownedRemovalRequest
	paths := map[int]string{45: removalCLIExecutable, 46: removalUIExecutable, 47: stage + removalCLIExecutable, 48: stage + removalUIExecutable}
	backend := ownedRecoveryProcessBackend(paths)
	first, err := inspectRemovalRecoveryProcesses(t.Context(), ownedRemovalRequest, backend)
	if err != nil || first.requestID != ownedRemovalRequest || len(first.processes) != 4 || len(first.digest) != 64 {
		t.Fatal("complete recovery process evidence missing", err)
	}
	second, err := inspectRemovalRecoveryProcesses(t.Context(), ownedRemovalRequest, backend)
	if err != nil || first.digest != second.digest {
		t.Fatal("stable scan order changed recovery process evidence", err)
	}
	for index, process := range first.processes {
		if process.PID != uint32(45+index) || !process.validRecovery(ownedRemovalRequest) || process.valid() != (index < 2) {
			t.Fatal("recovery process proof broadened fresh-removal ownership")
		}
	}
	if _, err := json.Marshal(first); err == nil {
		t.Fatal("private recovery process evidence serialized")
	}
	if fmt.Sprintf("%+v %#v", first, first) != "[private NetBird removal recovery processes] [private NetBird removal recovery processes]" {
		t.Fatal("private recovery process evidence escaped")
	}
	foreign := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	for _, path := range []string{
		"/Applications/" + removalStagePrefix + foreign + removalCLIExecutable,
		stage + "/NetBird.app/Contents/MacOS/netbird", stage + removalCLIExecutable + "-other",
		stage + "/Applications/NetBird.app/Contents/other/netbird", stage + "/../" + removalCLIExecutable,
		"/owned/netbird", "/usr/local/bin/netbird",
	} {
		if removalRecoveryProcessIdentifier(ownedRemovalRequest, path) != "" || ownedRemovalProcess(45, path).validRecovery(ownedRemovalRequest) {
			t.Fatal("foreign or aliased executable became an owned recovery process")
		}
		backend := ownedRecoveryProcessBackend(map[int]string{45: path})
		backend.inspect = func(context.Context, int, string) (removalProcess, error) {
			t.Fatal("unrelated process was inspected as owned")
			return removalProcess{}, errRemovalProcesses
		}
		if v, err := inspectRemovalRecoveryProcesses(t.Context(), ownedRemovalRequest, backend); err != nil || len(v.processes) != 0 {
			t.Fatal("unrelated path was treated as package ownership", err)
		}
	}
	// Even a quiet runtime proof remains bound to its selected original request.
	empty := ownedRecoveryProcessBackend(nil)
	a, err := inspectRemovalRecoveryProcesses(t.Context(), ownedRemovalRequest, empty)
	if err != nil {
		t.Fatal(err)
	}
	b, err := inspectRemovalRecoveryProcesses(t.Context(), foreign, empty)
	if err != nil || a.digest == b.digest {
		t.Fatal("quiet process proof lost original request binding", err)
	}
}

func TestRemovalRecoveryProcessesRejectChangedPartialOrForeignKernelEvidence(t *testing.T) {
	path := "/Applications/" + removalStagePrefix + ownedRemovalRequest + removalCLIExecutable
	for _, kind := range []string{"changed-generation", "changed-code", "changed-start", "changed-path", "changed-pid", "wrong-token-pid", "no-generation", "no-start", "invalid-hash", "gone-matched", "inaccessible", "new-process", "missing-init", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			backend := ownedRecoveryProcessBackend(map[int]string{45: path})
			list := backend.list
			calls := 0
			backend.list = func(ctx context.Context) ([]int, error) {
				calls++
				if kind == "missing-init" {
					return []int{45}, nil
				}
				if kind == "new-process" && calls == 2 {
					return []int{1, 45, 46}, nil
				}
				return list(ctx)
			}
			backend.path = func(ctx context.Context, pid int) (string, error) {
				if pid == 1 {
					if kind == "inaccessible" {
						return "", errRemovalProcesses
					}
					return "/sbin/launchd", nil
				}
				return path, nil
			}
			backend.inspect = func(ctx context.Context, pid int, path string) (removalProcess, error) {
				p := ownedRemovalProcess(uint32(pid), path)
				switch kind {
				case "changed-generation":
					if calls == 2 {
						p.Audit[7]++
					}
				case "changed-code":
					if calls == 2 {
						p.CodeHash = strings.Repeat("b", 40)
					}
				case "changed-start":
					if calls == 2 {
						p.StartedSeconds++
					}
				case "changed-path":
					p.Path = removalCLIExecutable
				case "changed-pid":
					p.PID++
				case "wrong-token-pid":
					p.Audit[5]++
				case "no-generation":
					p.Audit[7] = 0
				case "no-start":
					p.StartedSeconds = 0
				case "invalid-hash":
					p.CodeHash = strings.Repeat("A", 40)
				case "gone-matched":
					return removalProcess{}, errRemovalProcessGone
				case "cancelled":
					cancel()
				}
				return p, nil
			}
			if v, err := inspectRemovalRecoveryProcesses(ctx, ownedRemovalRequest, backend); err != errRemovalProcesses || v != nil {
				t.Fatal("incomplete or changed recovery process proof accepted", err)
			}
		})
	}
	for _, id := range []string{"", "../" + ownedRemovalRequest, strings.ToUpper(ownedRemovalRequest), ownedRemovalRequest + "/../other"} {
		backend := ownedRecoveryProcessBackend(nil)
		backend.list = func(context.Context) ([]int, error) {
			t.Fatal("invalid original identity reached native process enumeration")
			return nil, nil
		}
		if v, err := inspectRemovalRecoveryProcesses(t.Context(), id, backend); err == nil || v != nil {
			t.Fatal("invalid original identity admitted")
		}
		if removalRecoveryProcessIdentifier(id, removalCLIExecutable) != "" {
			t.Fatal("invalid identity acquired even the original executable")
		}
	}
}
