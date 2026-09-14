//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRemovalOwnershipBindsFilesLoadedJobAndExactRunningProcess(t *testing.T) {
	for _, kind := range []string{"complete", "files-changed", "processes-changed", "job-changed", "files-unavailable", "processes-unavailable", "job-unavailable", "missing-daemon-process", "foreign-daemon-user", "ui-is-not-daemon", "unloaded", "loaded-waiting"} {
		t.Run(kind, func(t *testing.T) {
			fileCalls, processCalls, jobCalls := 0, 0, 0
			backend := removalOwnershipBackend{
				files: func(context.Context) (*removalFileEvidence, error) {
					fileCalls++
					if kind == "files-unavailable" {
						return nil, errRemovalFiles
					}
					digest := strings.Repeat("a", 64)
					if kind == "files-changed" && fileCalls == 2 {
						digest = strings.Repeat("b", 64)
					}
					return &removalFileEvidence{version: "0.78.1", architecture: "arm64", digest: digest, objects: map[string]removalObject{removalCLI: {Link: removalCLIExecutable}}}, nil
				},
				processes: func(context.Context) (*removalProcessEvidence, error) {
					processCalls++
					if kind == "processes-unavailable" {
						return nil, errRemovalProcesses
					}
					p := ownedRemovalProcess(45, removalCLIExecutable)
					if kind == "foreign-daemon-user" {
						p.Audit[1] = 501
					}
					if kind == "ui-is-not-daemon" {
						p.Path = removalUIExecutable
					}
					processes := []removalProcess{p}
					if kind == "missing-daemon-process" {
						processes = nil
					}
					digest := strings.Repeat("c", 64)
					if kind == "processes-changed" && processCalls == 2 {
						digest = strings.Repeat("d", 64)
					}
					return &removalProcessEvidence{processes: processes, digest: digest}, nil
				},
				job: func(context.Context) ([]byte, bool, error) {
					jobCalls++
					if kind == "job-unavailable" {
						return nil, false, errRemovalProcesses
					}
					if kind == "unloaded" {
						return nil, false, nil
					}
					data := ownedRemovalJob
					if kind == "job-changed" && jobCalls == 2 {
						data = strings.Replace(data, "info", "debug", 1)
					}
					if kind == "loaded-waiting" {
						data = strings.Replace(data, "<key>PID</key><integer>45</integer>", "", 1)
					}
					return []byte(data), true, nil
				},
			}
			result, err := inspectRemovalOwnership(t.Context(), backend)
			want := kind == "complete" || kind == "unloaded" || kind == "loaded-waiting"
			if !want {
				if err != errRemovalProcesses || result != nil {
					t.Fatal("incomplete combined native ownership accepted", kind, err)
				}
				return
			}
			if err != nil || !result.descriptor.Valid() || fileCalls != 2 || processCalls != 2 || jobCalls != 2 {
				t.Fatal("complete native ownership descriptor missing", err)
			}
			if data, err := json.Marshal(result); err == nil || len(data) != 0 {
				t.Fatal("private runtime ownership serialized")
			}
			for _, value := range []string{fmt.Sprint(result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result)} {
				if strings.Contains(value, result.descriptor.StateDigest) || strings.Contains(value, "Applications") {
					t.Fatal("private native ownership escaped")
				}
			}
		})
	}
}
