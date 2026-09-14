//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"golang.org/x/sys/unix"
)

// Cleanup observes a current, explicitly selected scaffold. It does not infer
// original manifest ownership or prove success of an earlier uninstall.
// A remote caller must separately prove the exact original released journal
// entry and durably admit a new cleanup operation before running this owner.
type removalStageCleanupEvidence struct {
	objects         map[string]removalObject
	digest          string
	directories     int
	manifestBytes   int64
	manifestPresent bool
}

func (*removalStageCleanupEvidence) String() string {
	return "[private NetBird removal stage cleanup evidence]"
}
func (v *removalStageCleanupEvidence) GoString() string           { return v.String() }
func (*removalStageCleanupEvidence) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

func (v *removalStageCleanupEvidence) review() RemovalStageCleanupReview {
	return RemovalStageCleanupReview{StateDigest: v.digest, DirectoryCount: v.directories, ManifestPresent: v.manifestPresent, ManifestBytes: v.manifestBytes}
}
func nativeInspectRemovalStageCleanup(ctx context.Context, originalID string) (RemovalStageCleanupReview, error) {
	v, err := inspectRemovalStageCleanup(ctx, "/", 0, originalID, removalAbsenceBackend{readNativePackage, nativeRemovalQuiescent}, nil)
	if err != nil {
		return RemovalStageCleanupReview{}, ErrRemoval
	}
	return v.review(), nil
}
func prepareNativeRemovalStageCleanup(ctx context.Context, originalID string, review RemovalStageCleanupReview) (*Removal, error) {
	return prepareRemovalStageCleanup(ctx, "/", 0, originalID, review, removalAbsenceBackend{readNativePackage, nativeRemovalQuiescent})
}

// Only the exact original UUID's private scaffold is eligible. Payloads,
// receipts, active runtime, other stages and usable manifests are preserved.
// The sole permitted regular file is bounded, owned incomplete manifest.json
// metadata. Its complete bytes are hashed into the explicit cleanup review.
func removalStageCleanupSnapshot(ctx context.Context, root string, owner uint32, originalID string, held *[]*os.File) (map[string]removalObject, error) {
	if !netbirdcommand.ValidRequestID(originalID) {
		return nil, ErrRemoval
	}
	objects, err := removalAbsenceFileSnapshot(ctx, root, owner, false, held)
	if err != nil || objects["Applications"].Missing {
		return nil, ErrRemoval
	}
	check := removalSnapshotFor(ctx, root, owner, objects)
	check.held = held
	check.remaining = maxRemovalManifestBytes
	defer clearRemovalData(check)
	prefix := filepath.Join("Applications", removalStagePrefix+originalID)
	app, err := check.open("Applications")
	if err != nil {
		return nil, ErrRemoval
	}
	names, readErr := app.Readdirnames(8193)
	closeErr := app.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(names) > 8192 {
		return nil, ErrRemoval
	}
	selected := false
	for _, name := range names {
		if strings.HasPrefix(name, removalStagePrefix) {
			if name != removalStagePrefix+originalID {
				return nil, ErrRemoval
			}
			selected = true
		}
	}
	if !selected {
		return nil, ErrRemoval
	}
	known := append(slices.Clone(removalStageParents), "manifest.json")
	for _, name := range known {
		full := filepath.Join(prefix, name)
		if check.objects[filepath.Dir(full)].Missing {
			check.objects[full] = removalObject{Missing: true}
			continue
		}
		parent, err := check.parent(full)
		if err != nil {
			return nil, ErrRemoval
		}
		var stat unix.Stat_t
		err = unix.Fstatat(int(parent.Fd()), filepath.Base(full), &stat, unix.AT_SYMLINK_NOFOLLOW)
		closeErr := parent.Close()
		if closeErr != nil {
			return nil, ErrRemoval
		}
		if errors.Is(err, unix.ENOENT) && name != "." {
			check.objects[full] = removalObject{Missing: true}
			continue
		}
		if err != nil {
			return nil, ErrRemoval
		}
		directory := name != "manifest.json"
		obj, err := check.object(full, false, directory)
		mode := uint32(0600)
		if directory {
			mode = uint32(os.ModeDir | 0700)
		}
		if err != nil || obj.UID != owner || obj.Mode != mode || obj.Flags != 0 {
			return nil, ErrRemoval
		}
		if !directory {
			file, err := check.open(full)
			if err != nil {
				return nil, ErrRemoval
			}
			data, readErr := io.ReadAll(contextReader{ctx, io.LimitReader(file, maxRemovalManifestBytes+1)})
			closeErr := file.Close()
			hash := sha256.Sum256(data)
			if readErr != nil || closeErr != nil || int64(len(data)) != obj.Size || hex.EncodeToString(hash[:]) != obj.Hash {
				clear(data)
				return nil, ErrRemoval
			}
			// Conservatively preserve any complete usable manifest, including one whose
			// current bytes are noncanonical. Manifest continuation has its own review.
			type wire removalStageManifest
			var decoded wire
			complete := json.Unmarshal(data, &decoded) == nil && validRemovalStageManifest(removalStageManifest(decoded), owner)
			clear(data)
			if complete {
				return nil, ErrRemoval
			}
		}
	}
	// Enumerate every retained directory. Unknown children cannot hide behind an
	// otherwise recognized name or a partial/missing manifest.
	for _, name := range removalStageParents {
		full := filepath.Join(prefix, name)
		if check.objects[full].Missing {
			continue
		}
		directory, err := check.open(full)
		if err != nil {
			return nil, ErrRemoval
		}
		names, readErr := directory.Readdirnames(len(known) + 1)
		closeErr := directory.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil || len(names) > len(known) {
			return nil, ErrRemoval
		}
		for _, child := range names {
			obj, ok := check.objects[filepath.Join(full, child)]
			if !ok || obj.Missing {
				return nil, ErrRemoval
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ErrRemoval
	}
	return check.objects, nil
}

func inspectRemovalStageCleanup(parent context.Context, root string, owner uint32, originalID string, backend removalAbsenceBackend, retain *[]*os.File) (*removalStageCleanupEvidence, error) {
	if parent == nil || parent.Err() != nil || backend.quiet == nil || backend.read == nil {
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
	before, err := removalStageCleanupSnapshot(ctx, root, owner, originalID, &held)
	if err != nil {
		return nil, ErrRemoval
	}
	for range 2 {
		if backend.quiet(ctx, "") != nil {
			return nil, ErrRemoval
		}
		if present, err := nativeRemovalReceiptPresent(ctx, backend.read); err != nil || present {
			return nil, ErrRemoval
		}
		after, err := removalStageCleanupSnapshot(ctx, root, owner, originalID, nil)
		if err != nil || !reflect.DeepEqual(before, after) || ctx.Err() != nil {
			return nil, ErrRemoval
		}
	}
	data, err := json.Marshal(before)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/macos-pkg-stage-cleanup/v1\x00"), data...))
	clear(data)
	v := &removalStageCleanupEvidence{objects: before, digest: hex.EncodeToString(hash[:])}
	prefix := filepath.Join("Applications", removalStagePrefix+originalID)
	for _, name := range removalStageParents {
		if !before[filepath.Join(prefix, name)].Missing {
			v.directories++
		}
	}
	manifest := before[filepath.Join(prefix, "manifest.json")]
	v.manifestPresent = !manifest.Missing
	v.manifestBytes = manifest.Size
	if retain != nil {
		*retain = append(*retain, held...)
		held = nil
	}
	return v, nil
}

// Preparation is read-only. Run is single-use and may delete only the exact
// reviewed scaffold and incomplete metadata. Close only joins and closes files.
func prepareRemovalStageCleanup(ctx context.Context, root string, owner uint32, originalID string, review RemovalStageCleanupReview, backend removalAbsenceBackend) (*Removal, error) {
	if !review.Valid() {
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
	v, err := inspectRemovalStageCleanup(ctx, root, owner, originalID, backend, &held)
	if err != nil || v.review() != review {
		_ = closeHeld()
		return nil, ErrRemoval
	}
	return &Removal{close: closeHeld, run: func(ctx context.Context) error {
		expected := maps.Clone(v.objects)
		prefix := filepath.Join("Applications", removalStagePrefix+originalID)
		names := slices.Clone(removalStageParents[1:])
		slices.Reverse(names)
		names = append(names, "manifest.json", ".")
		for _, name := range names {
			full := filepath.Join(prefix, name)
			if expected[full].Missing {
				continue
			}
			current, err := inspectRemovalStageCleanup(ctx, root, owner, originalID, backend, nil)
			if err != nil || !reflect.DeepEqual(current.objects, expected) {
				return ErrRemoval
			}
			ancestry := removalSnapshotFor(ctx, root, owner, expected)
			parent, err := ancestry.parent(full)
			if err != nil {
				return ErrRemoval
			}
			err = unlinkRemovalRecoveryObject(ctx, root, owner, full, expected[full], ancestry, full, parent)
			closeErr := parent.Close()
			if err != nil || closeErr != nil {
				return ErrRemoval
			}
			expected[full] = removalObject{Missing: true}
		}
		// Completion is a new cleanup result. A late query failure cannot be turned
		// into successful historical removal or permission to repeat the old owner.
		_, err := inspectRemovalAbsence(ctx, root, owner, backend, nil)
		return err
	}}, nil
}
