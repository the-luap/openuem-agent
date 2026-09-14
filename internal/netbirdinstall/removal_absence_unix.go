//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"golang.org/x/sys/unix"
)

// This evidence describes the current supported macOS package layout. It does
// not attribute absence to an earlier command, descriptor, or missing manifest.
type removalAbsenceEvidence struct {
	objects map[string]removalObject
	digest  string
}

func (*removalAbsenceEvidence) String() string               { return "[private NetBird removal absence evidence]" }
func (v *removalAbsenceEvidence) GoString() string           { return v.String() }
func (*removalAbsenceEvidence) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

type removalAbsenceBackend struct {
	read  packageReader
	quiet func(context.Context, string) error
}

func nativeInspectRemovalAbsence(ctx context.Context) (string, error) {
	v, err := inspectRemovalAbsence(ctx, "/", 0, removalAbsenceBackend{readNativePackage, nativeRemovalQuiescent}, nil)
	if err != nil {
		return "", ErrRemoval
	}
	return v.digest, nil
}

func prepareNativeRemovalAbsence(ctx context.Context, digest string) (*Removal, error) {
	return prepareRemovalAbsence(ctx, "/", 0, digest, removalAbsenceBackend{readNativePackage, nativeRemovalQuiescent})
}

// Both native rounds are followed by a filesystem snapshot. The first round's
// descriptors remain open across all queries, including the final comparison.
// An empty or malformed retained stage is still a barrier, never positive absence.
func inspectRemovalAbsence(parent context.Context, root string, owner uint32, backend removalAbsenceBackend, retain *[]*os.File) (*removalAbsenceEvidence, error) {
	if parent == nil || parent.Err() != nil || backend.read == nil || backend.quiet == nil {
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
	before, err := removalAbsenceFileSnapshot(ctx, root, owner, true, &held)
	if err != nil {
		return nil, ErrRemoval
	}
	for round := 0; round < 2; round++ {
		if backend.quiet(ctx, "") != nil {
			return nil, ErrRemoval
		}
		if present, err := nativeRemovalReceiptPresent(ctx, backend.read); err != nil || present {
			return nil, ErrRemoval
		}
		after, err := removalAbsenceFileSnapshot(ctx, root, owner, true, nil)
		if err != nil || !reflect.DeepEqual(before, after) || ctx.Err() != nil {
			return nil, ErrRemoval
		}
	}
	encoded, err := json.Marshal(before)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/macos-pkg-current-absence/v1\x00"), encoded...))
	clear(encoded)
	if retain != nil {
		*retain = append(*retain, held...)
		held = nil
	}
	return &removalAbsenceEvidence{before, hex.EncodeToString(hash[:])}, nil
}

// A separately admitted verification can use this single-use read-only owner.
// No stop, unlink, receipt forget, stage cleanup, or original replay is possible.
func prepareRemovalAbsence(ctx context.Context, root string, owner uint32, digest string, backend removalAbsenceBackend) (*Removal, error) {
	if !netbirdcommand.ValidDigest(digest) {
		return nil, ErrRemoval
	}
	var held []*os.File
	closeHeld := func() error {
		var result error
		for _, file := range held {
			if file.Close() != nil {
				result = ErrRemoval
			}
		}
		held = nil
		return result
	}
	v, err := inspectRemovalAbsence(ctx, root, owner, backend, &held)
	if err != nil || v.digest != digest {
		_ = closeHeld()
		return nil, ErrRemoval
	}
	return &Removal{
		run: func(ctx context.Context) error {
			current, err := inspectRemovalAbsence(ctx, root, owner, backend, nil)
			if err != nil || current.digest != digest || !reflect.DeepEqual(v.objects, current.objects) {
				return ErrRemoval
			}
			return nil
		},
		close: closeHeld,
	}, nil
}

// Every missing component must be ENOENT from its protected parent descriptor.
// Path-based ENOENT alone could have followed a replaced or inaccessible ancestor.
func removalAbsenceFileSnapshot(ctx context.Context, root string, owner uint32, stages bool, held *[]*os.File) (map[string]removalObject, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrRemoval
	}
	check := removalSnapshotFor(ctx, root, owner, map[string]removalObject{})
	check.held = held
	if _, err := check.object(".", false, true); err != nil {
		return nil, ErrRemoval
	}
	for _, name := range []string{removalApp, removalCLI, removalDaemon, removalReceipt + ".plist", removalReceipt + ".bom"} {
		parts := strings.Split(name, "/")
		missing := false
		for i := 1; i <= len(parts); i++ {
			part := strings.Join(parts[:i], "/")
			if missing {
				check.objects[part] = removalObject{Missing: true}
				continue
			}
			parent, err := check.parent(part)
			if err != nil {
				return nil, ErrRemoval
			}
			var info unix.Stat_t
			err = unix.Fstatat(int(parent.Fd()), filepath.Base(part), &info, unix.AT_SYMLINK_NOFOLLOW)
			closeErr := parent.Close()
			if closeErr != nil {
				return nil, ErrRemoval
			}
			if errors.Is(err, unix.ENOENT) {
				check.objects[part] = removalObject{Missing: true}
				missing = true
				continue
			}
			if err != nil || i == len(parts) {
				return nil, ErrRemoval
			}
			// Present ancestors must remain directories under the same parents.
			if _, err := check.object(part, false, true); err != nil {
				return nil, ErrRemoval
			}
		}
	}
	if stages && removalAbsenceStages(check) != nil {
		return nil, ErrRemoval
	}
	if ctx.Err() != nil {
		return nil, ErrRemoval
	}
	return check.objects, nil
}

func removalAbsenceStages(check *removalSnapshot) (result error) {
	app, ok := check.objects["Applications"]
	if !ok || check.ctx.Err() != nil {
		return ErrRemoval
	}
	if app.Missing {
		return nil
	}
	dir, err := check.open("Applications")
	if err != nil {
		return ErrRemoval
	}
	defer func() {
		if dir.Close() != nil {
			result = ErrRemoval
		}
	}()
	info, err := dir.Stat()
	acl, trusted := removalACL(dir)
	if err != nil || !sameRemovalInfo(app, info, true) || !trusted || acl != app.ACL {
		return ErrRemoval
	}
	names, readErr := dir.Readdirnames(8193)
	if readErr != nil && readErr != io.EOF || len(names) > 8192 || check.ctx.Err() != nil {
		return ErrRemoval
	}
	if slices.ContainsFunc(names, func(name string) bool { return strings.HasPrefix(name, removalStagePrefix) }) {
		return ErrRemoval
	}
	current, err := check.object("Applications", false, true)
	if err != nil || current != app {
		return ErrRemoval
	}
	return nil
}
