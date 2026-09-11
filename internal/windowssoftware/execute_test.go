package windowssoftware

import (
	"context"
	"errors"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

type ownedInstallerStage struct {
	closed  bool
	invalid bool
}

func (*ownedInstallerStage) Path() string { return "/owned/staged-installer" }
func (s *ownedInstallerStage) Verify(context.Context) error {
	if s.closed || s.invalid {
		return ErrArtifactChanged
	}
	return nil
}
func (s *ownedInstallerStage) Close() error { s.closed = true; return nil }

func TestSoftwareExecutorSeparatesNativeFactsFromObservedState(t *testing.T) {
	for _, tc := range []struct {
		name, operation, initial, final string
		code                            uint32
		state                           string
	}{
		{"install", "install", Absent, Present, 0, "observed"}, {"remove", "remove", Present, Absent, 0, "observed"},
		{"success_without_install", "install", Absent, Absent, 0, "uncertain"}, {"success_without_remove", "remove", Present, Present, 0, "uncertain"},
		{"reboot_even_when_present", "install", Absent, Present, 3010, "restart_required"}, {"reboot_after_remove", "remove", Present, Absent, 3010, "restart_required"},
		{"failure_even_when_present", "install", Absent, Present, 1603, "failed"}, {"failed_remove", "remove", Present, Present, 1603, "failed"},
		{"unreadable_after_success", "install", Absent, Unknown, 0, "uncertain"}, {"reboot_unreadable", "install", Absent, Unknown, 3010, "restart_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := preflightPlan()
			plan.Operation = tc.operation
			if tc.operation == "remove" {
				plan.Artifact = enrollment.SoftwareArtifact{}
			}
			stage := &ownedInstallerStage{}
			run, observations := 0, 0
			ops := installerOperations{
				host: func(context.Context, enrollment.SoftwarePlan) error { return nil },
				observe: func(context.Context, Rule) (Observation, error) {
					observations++
					state := tc.initial
					if run > 0 {
						state = tc.final
					}
					o := Observation{State: state}
					if state == Present {
						o.Version = plan.Detection.Version
					}
					return o, nil
				},
				stage: func(context.Context, enrollment.SoftwarePlan, string) (installerStage, error) {
					if tc.operation == "remove" {
						t.Fatal("MSI removal downloaded an installer")
					}
					return stage, nil
				},
				inspect: func(context.Context, enrollment.SoftwarePlan, installerStage) error { return nil },
				run: func(context.Context, enrollment.SoftwarePlan, string) (installerProcess, error) {
					run++
					return installerProcess{true, &tc.code}, nil
				},
			}
			out := executeInstaller(t.Context(), plan, "/owned", func() error { return nil }, ops)
			if out.State != tc.state || out.Execution != "started" || out.ExitCode == nil || *out.ExitCode != tc.code || !out.ValidFor(plan) || run != 1 || observations != 3 {
				t.Fatal("incorrect software execution evidence", out, run, observations)
			}
			if tc.operation == "install" && !stage.closed {
				t.Fatal("staged installer not released")
			}
		})
	}
}

func TestSoftwareExecutorPreflightNeverStartsUnapprovedOrChangedState(t *testing.T) {
	for _, failure := range []string{"already_present", "already_absent", "wrong_version", "host", "download", "signature", "inspect", "stage_changed", "became_present", "became_other_version", "fresh_detection", "lease", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			plan := preflightPlan()
			if failure == "already_absent" {
				plan.Operation, plan.Artifact = "remove", enrollment.SoftwareArtifact{}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stage := &ownedInstallerStage{}
			observations, admissions := 0, 0
			ops := installerOperations{
				host: func(context.Context, enrollment.SoftwarePlan) error {
					if failure == "host" {
						return ErrPreflight
					}
					return nil
				},
				observe: func(context.Context, Rule) (Observation, error) {
					observations++
					if failure == "already_present" || failure == "became_present" && observations == 2 {
						return Observation{Present, plan.Detection.Version}, nil
					}
					if failure == "wrong_version" || failure == "became_other_version" && observations == 2 {
						return Observation{Present, "other"}, nil
					}
					if failure == "fresh_detection" && observations == 2 {
						return Observation{State: Unknown}, ErrObservation
					}
					return Observation{State: Absent}, nil
				},
				stage: func(context.Context, enrollment.SoftwarePlan, string) (installerStage, error) {
					if failure == "download" {
						return nil, ErrArtifactDownload
					}
					if failure == "signature" {
						return stage, ErrArtifactSignature
					}
					return stage, nil
				},
				inspect: func(context.Context, enrollment.SoftwarePlan, installerStage) error {
					if failure == "inspect" {
						return ErrPreflight
					}
					if failure == "stage_changed" {
						stage.invalid = true
					}
					if failure == "cancel" {
						cancel()
					}
					return nil
				},
				run: func(context.Context, enrollment.SoftwarePlan, string) (installerProcess, error) {
					t.Fatal("denied installer started")
					return installerProcess{}, nil
				},
			}
			live := func() error {
				admissions++
				if failure == "lease" && admissions > 1 {
					return errors.New("owned lease lost")
				}
				return nil
			}
			out := executeInstaller(ctx, plan, "/owned", live, ops)
			if !out.ValidFor(plan) || out.Execution != "not_started" {
				t.Fatal("invalid nonexecution evidence", out)
			}
			observed := failure == "already_present" || failure == "already_absent" || failure == "became_present"
			if (out.State == "observed") != observed {
				t.Fatal("incorrect observed-state claim", out)
			}
		})
	}
}

func TestSoftwareExecutorInterruptionNeverClaimsCompletion(t *testing.T) {
	for _, failure := range []string{"startup", "runner", "cancel", "lease", "missing_exit"} {
		t.Run(failure, func(t *testing.T) {
			plan := preflightPlan()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ran := false
			ops := installerOperations{host: func(context.Context, enrollment.SoftwarePlan) error { return nil }, observe: func(context.Context, Rule) (Observation, error) { return Observation{State: Absent}, nil }, stage: func(context.Context, enrollment.SoftwarePlan, string) (installerStage, error) {
				return &ownedInstallerStage{}, nil
			}, inspect: func(context.Context, enrollment.SoftwarePlan, installerStage) error { return nil },
				run: func(context.Context, enrollment.SoftwarePlan, string) (installerProcess, error) {
					ran = true
					if failure == "startup" {
						return installerProcess{}, ErrPreflight
					}
					if failure == "cancel" {
						cancel()
					}
					code := uint32(0)
					result := installerProcess{true, &code}
					if failure == "missing_exit" {
						result.ExitCode = nil
					}
					if failure == "runner" {
						return result, ErrPreflight
					}
					return result, nil
				},
			}
			out := executeInstaller(ctx, plan, "/owned", func() error {
				if ran && failure == "lease" {
					return ErrPreflight
				}
				return nil
			}, ops)
			want := "uncertain"
			if failure == "startup" {
				want = "not_started"
			}
			if !out.ValidFor(plan) || out.State != want {
				t.Fatal("interruption became completion", out)
			}
		})
	}
}
