//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestRemovalRecoveryStopUsesExactReviewedJobAndProcessProofs(t *testing.T) {
	for _, kind := range []string{"loaded", "unloaded", "force-after-timeout", "changed-job", "foreign-original", "foreign-process", "foreign-daemon-user", "duplicate-process", "bootout-failure", "signal-failure", "quiet-failure", "cancelled-wait", "new-process"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			job, err := inspectRemovalLaunchd(ctx, true, func(context.Context) ([]byte, bool, error) { return []byte(ownedRemovalJob), true, nil })
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unloaded" {
				job = removalLaunchdEvidence{}
			}
			p := ownedRemovalProcess(45, "/Applications/"+removalStagePrefix+ownedRemovalRequest+removalCLIExecutable)
			expected := &removalRecoveryOwnership{
				files:     &removalRecoveryFiles{manifest: &removalManifestEvidence{manifest: removalStageManifest{RequestID: ownedRemovalRequest, Objects: map[string]removalObject{removalCLI: {Link: removalCLIExecutable}}}}},
				processes: &removalRecoveryProcesses{requestID: ownedRemovalRequest, processes: []removalProcess{p}}, job: job, digest: strings.Repeat("a", 64),
			}
			if kind == "foreign-original" {
				expected.processes.requestID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
			}
			if kind == "foreign-process" {
				expected.processes.processes[0].Path += "-foreign"
			}
			if kind == "duplicate-process" {
				expected.processes.processes = append(expected.processes.processes, p)
			}
			if kind == "foreign-daemon-user" {
				expected.processes.processes[0].Audit[1] = 501
			}
			var events []string
			stopped, forced := kind == "unloaded", false
			backend := removalRecoveryStopBackend{
				job: func(context.Context) ([]byte, bool, error) {
					events = append(events, "job")
					if stopped {
						return nil, false, nil
					}
					data := ownedRemovalJob
					if kind == "changed-job" {
						data = strings.Replace(data, "info", "debug", 1)
					}
					return []byte(data), true, nil
				},
				bootout: func(context.Context) error {
					events = append(events, "bootout")
					if kind == "bootout-failure" {
						return ErrRemoval
					}
					stopped = true
					return nil
				},
				signal: func(ctx context.Context, process removalProcess, force bool) error {
					if !stopped || process != p {
						t.Fatal("unreviewed process or still-loaded service reached signalling")
					}
					if force {
						forced = true
						events = append(events, "kill")
					} else {
						events = append(events, "term")
					}
					if kind == "signal-failure" {
						return ErrRemoval
					}
					return nil
				},
				quiet: func(ctx context.Context, processes []removalProcess) (bool, error) {
					if !reflect.DeepEqual(processes, []removalProcess{p}) {
						t.Fatal("quiet check lost complete audited process identity")
					}
					if kind == "cancelled-wait" {
						cancel()
						return false, nil
					}
					if kind == "quiet-failure" {
						return false, ErrRemoval
					}
					if kind == "force-after-timeout" && !forced {
						return false, nil
					}
					events = append(events, "quiet")
					return true, nil
				},
				quiescent: func(ctx context.Context, path string) error {
					if path != "/Applications/"+removalStagePrefix+ownedRemovalRequest+"/"+removalApp {
						t.Fatal("complete process scan used a foreign staging path")
					}
					events = append(events, "complete-scan")
					if kind == "new-process" {
						return ErrRemoval
					}
					return nil
				},
			}
			err = stopRemovalRecoveryRuntime(ctx, expected, backend)
			want := kind == "loaded" || kind == "unloaded" || kind == "force-after-timeout"
			if (err == nil) != want || forced != (kind == "force-after-timeout") {
				t.Fatal("failed stop, incomplete scan or cancellation acquired completion/force", err)
			}
			if kind == "foreign-original" || kind == "foreign-process" || kind == "foreign-daemon-user" || kind == "duplicate-process" {
				if len(events) != 0 {
					t.Fatal("invalid recovery ownership reached native callbacks")
				}
				return
			}
			if want {
				wanted := []string{"job", "bootout", "job", "term", "quiet", "complete-scan"}
				if kind == "unloaded" {
					wanted = []string{"job", "term", "quiet", "complete-scan"}
				}
				if kind == "force-after-timeout" {
					wanted = []string{"job", "bootout", "job", "term", "kill", "quiet", "complete-scan"}
				}
				if !reflect.DeepEqual(events, wanted) {
					t.Fatal("recovery stop sequence lost reviewed ownership or complete quiescence", events)
				}
			}
		})
	}
}
