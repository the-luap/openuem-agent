//go:build darwin && cgo

package macservice

/*
#cgo LDFLAGS: -framework Foundation -framework ServiceManagement
#include <stdlib.h>
#include "bridge_darwin.h"
*/
import "C"

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/open-uem/openuem-agent/internal/macbundle"
)

// Apple's Developer ID Application leaf extension distinguishes app signatures
// from installer or development certificates. Release authorization additionally
// comes from the protected agent hash verified by the activation caller.
const releaseRequirement = `=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and identifier "` + macbundle.BundleIdentifier + `" and notarized`

type frameworkService struct{ reference unsafe.Pointer }

func currentBundleService(bundle, executable string) (*frameworkService, error) {
	values := []*C.char{C.CString(bundle), C.CString(executable), C.CString(macbundle.BundleIdentifier), C.CString(macbundle.DaemonLabel + ".plist")}
	defer func() {
		for _, value := range values {
			C.free(unsafe.Pointer(value))
		}
	}()
	reference := C.openuem_app_service_open(values[0], values[1], values[2], values[3])
	if reference == nil {
		return nil, ErrAccess
	}
	return &frameworkService{reference: reference}, nil
}

func (s *frameworkService) status() (Status, error) {
	status := int(C.openuem_app_service_status(s.reference))
	if status < 0 || status > int(NotFound) {
		return NotFound, ErrRegistration
	}
	return Status(status), nil
}
func (s *frameworkService) register() error {
	if C.openuem_app_service_register(s.reference) != 1 {
		return ErrRegistration
	}
	return nil
}
func (s *frameworkService) close() error {
	if s.reference != nil {
		C.openuem_app_service_close(s.reference)
		s.reference = nil
	}
	return nil
}

func openNative(ctx context.Context, path string) (_ *Service, resultErr error) {
	if os.Geteuid() != 0 || path != filepath.Join(macbundle.InstallationPath, macbundle.ExecutableRelative) {
		return nil, ErrAccess
	}
	files, err := inspectBundle(macbundle.InstallationPath, 0)
	if err != nil {
		return nil, err
	}
	service := &Service{closeFiles: files.Close}
	defer func() {
		if resultErr != nil {
			service.Close()
		}
	}()
	service.check = func(ctx context.Context, signature bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := files.Check(); err != nil {
			return err
		}
		if signature {
			if err := verifyApp(ctx, macbundle.InstallationPath, releaseRequirement); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return files.Check()
	}
	if err := service.check(ctx, true); err != nil {
		return nil, err
	}
	native, err := currentBundleService(macbundle.InstallationPath, path)
	if err != nil {
		return nil, err
	}
	service.native = native
	if err := service.check(ctx, false); err != nil {
		return nil, err
	}
	return service, nil
}

func verifyApp(ctx context.Context, bundle, requirement string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	args := []string{"--verify", "--strict", "--all-architectures", "--deep"}
	if requirement != "" {
		args = append(args, "--test-requirement", requirement)
	}
	args = append(args, bundle)
	command := exec.CommandContext(ctx, "/usr/bin/codesign", args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = time.Second
	err := command.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return ErrSignature
	}
	return nil
}
