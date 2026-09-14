//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// Current file evidence does not authorize journal recovery or prove quiescence.
// It recognizes exact original objects on either side of an interrupted move or
// purge and preserves missing objects separately from unknown replacements.
type removalRecoveryFiles struct {
	manifest         *removalManifestEvidence
	source, staged   map[string]removalObject
	receipts, digest string
}

func (*removalRecoveryFiles) String() string               { return "[private NetBird removal recovery files]" }
func (v *removalRecoveryFiles) GoString() string           { return v.String() }
func (*removalRecoveryFiles) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

func inspectRemovalRecoveryFiles(parent context.Context, root string, owner uint32, requestID string, descriptor packageapi.Removal) (*removalRecoveryFiles, error) {
	if parent == nil {
		return nil, ErrRemoval
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var held []*os.File
	defer func() {
		for _, file := range held {
			_ = file.Close()
		}
	}()
	first, err := removalRecoveryFileSnapshot(ctx, root, owner, requestID, descriptor, &held)
	if err != nil {
		return nil, ErrRemoval
	}
	second, err := removalRecoveryFileSnapshot(ctx, root, owner, requestID, descriptor, nil)
	if err != nil || !reflect.DeepEqual(first, second) || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	data, err := json.Marshal(struct {
		Manifest       string
		Source, Staged map[string]removalObject
		Receipts       string
	}{second.manifest.digest, second.source, second.staged, second.receipts})
	if err != nil {
		return nil, ErrRemoval
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-recovery-files/v1\x00"), data...))
	clear(data)
	second.digest = hex.EncodeToString(hash[:])
	return second, nil
}

func removalRecoveryFileSnapshot(ctx context.Context, root string, owner uint32, requestID string, descriptor packageapi.Removal, held *[]*os.File) (*removalRecoveryFiles, error) {
	manifest, err := readRemovalStageManifestHeld(ctx, root, owner, requestID, descriptor, held)
	if err != nil {
		return nil, ErrRemoval
	}
	source := removalSnapshotFor(ctx, root, owner, map[string]removalObject{})
	source.held = held
	defer clearRemovalData(source)
	if _, err := source.object(".", false, true); err != nil {
		return nil, ErrRemoval
	}
	ancestors := slices.Collect(maps.Keys(removalManifestAncestors))
	slices.Sort(ancestors)
	for _, name := range ancestors {
		if name == "." {
			continue
		}
		if source.objects[filepath.Dir(name)].Missing {
			source.objects[name] = removalObject{Missing: true}
			continue
		}
		if _, err := source.object(name, true, true); err != nil {
			return nil, ErrRemoval
		}
	}
	if removalOnlyRecoveryStage(source, removalStagePrefix+requestID) != nil {
		return nil, ErrRemoval
	}
	for _, name := range append(slices.Clone(removalRoots), removalReceipt+".plist", removalReceipt+".bom") {
		if source.objects[filepath.Dir(name)].Missing {
			source.objects[name] = removalObject{Missing: true}
			continue
		}
		obj, err := source.object(name, true, false)
		if err != nil || name == removalApp && !obj.Missing && source.walk(name, 0) != nil {
			return nil, ErrRemoval
		}
	}
	stage := removalSnapshotFor(ctx, filepath.Join(root, "Applications", removalStagePrefix+requestID), owner, map[string]removalObject{})
	stage.held = held
	defer clearRemovalData(stage)
	for _, name := range removalStageParents {
		if name != "." && stage.objects[filepath.Dir(name)].Missing {
			stage.objects[name] = removalObject{Missing: true}
			continue
		}
		obj, err := stage.object(name, name != ".", true)
		if err != nil || !obj.Missing && (obj.Mode != uint32(os.ModeDir|0700) || obj.UID != owner) {
			return nil, ErrRemoval
		}
		if !obj.Missing && removalRecoveryStageChildren(stage, name) != nil {
			return nil, ErrRemoval
		}
	}
	for _, name := range removalRoots {
		if stage.objects[filepath.Dir(name)].Missing {
			stage.objects[name] = removalObject{Missing: true}
			continue
		}
		obj, err := stage.object(name, true, false)
		if err != nil || name == removalApp && !obj.Missing && stage.walk(name, 0) != nil {
			return nil, ErrRemoval
		}
	}
	obj, err := stage.object("manifest.json", false, false)
	if err != nil || obj != manifest.file || source.objects["."] != manifest.root || source.objects["Applications"] != manifest.source || stage.objects["."] != manifest.directory {
		return nil, ErrRemoval
	}
	v := &removalRecoveryFiles{manifest: manifest, source: source.objects, staged: stage.objects, receipts: "present"}
	if !validRemovalRecoveryFiles(v) {
		return nil, ErrRemoval
	}
	plist, bom := source.objects[removalReceipt+".plist"].Missing, source.objects[removalReceipt+".bom"].Missing
	if plist && bom {
		v.receipts = "absent"
	} else if plist || bom {
		v.receipts = "partial"
	}
	return v, nil
}

func removalOnlyRecoveryStage(source *removalSnapshot, expected string) error {
	dir, err := source.open("Applications")
	if err != nil {
		return ErrRemoval
	}
	names, readErr := dir.Readdirnames(8193)
	closeErr := dir.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(names) > 8192 || source.ctx.Err() != nil {
		return ErrRemoval
	}
	found := false
	for _, name := range names {
		if strings.HasPrefix(name, removalStagePrefix) {
			if name != expected {
				return ErrRemoval
			}
			found = true
		}
	}
	if !found {
		return ErrRemoval
	}
	return nil
}

func removalRecoveryStageChildren(s *removalSnapshot, name string) error {
	allowed := map[string][]string{
		".":            {"Applications", "Library", "usr", "manifest.json"},
		"Applications": {"NetBird.app"}, "Library": {"LaunchDaemons"},
		"Library/LaunchDaemons": {"netbird.plist"}, "usr": {"local"},
		"usr/local": {"bin"}, "usr/local/bin": {"netbird"},
	}
	dir, err := s.open(name)
	if err != nil {
		return ErrRemoval
	}
	names, readErr := dir.Readdirnames(5)
	closeErr := dir.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(names) > len(allowed[name]) || s.ctx.Err() != nil {
		return ErrRemoval
	}
	for _, child := range names {
		if !slices.Contains(allowed[name], child) {
			return ErrRemoval
		}
	}
	return nil
}

func validRemovalRecoveryFiles(v *removalRecoveryFiles) bool {
	original := v.manifest.manifest.Objects
	for _, side := range []struct {
		objects map[string]removalObject
		staged  bool
	}{{v.source, false}, {v.staged, true}} {
		for name, obj := range side.objects {
			if !removalPayload(name) && name != removalReceipt+".plist" && name != removalReceipt+".bom" || obj.Missing {
				continue
			}
			expected, ok := original[name]
			if !ok || expected.Missing {
				return false
			}
			if removalPayload(name) && side.staged && os.FileMode(obj.Mode).IsDir() {
				// Purging descendants changes directory accounting but cannot change
				// its inode, mode, owner, ACL, flags or mount identity.
				obj.Size, obj.Modified, obj.Changed, obj.Links = 0, 0, 0, 0
				expected.Size, expected.Modified, expected.Changed, expected.Links = 0, 0, 0, 0
			} else if slices.Contains(removalRoots, name) {
				// A root can have moved to staging, or been exclusively restored by
				// the original owner after a rejected subtree observation.
				expected.Changed = obj.Changed
			}
			if obj != expected {
				return false
			}
		}
	}
	for name, expected := range original {
		if !removalPayload(name) || expected.Missing {
			continue
		}
		source, atSource := v.source[name]
		staged, atStage := v.staged[name]
		if atSource && !source.Missing && atStage && !staged.Missing {
			return false
		}
		if !v.source[removalApp].Missing && (name == removalApp || strings.HasPrefix(name, removalApp+"/")) && (!atSource || source.Missing) {
			// The original app moves atomically. A source app must remain complete;
			// only its private staged counterpart may contain a partial purge.
			return false
		}
	}
	return true
}
