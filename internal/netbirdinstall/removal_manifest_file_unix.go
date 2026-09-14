//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// This is only a stable read of original manifest evidence. Remaining payloads,
// source replacements, receipts, launchd and processes need their own current
// inspection before any recovery can be offered or executed.
type removalManifestEvidence struct {
	manifest                removalStageManifest
	source, directory, file removalObject
	root                    removalObject
	digest                  string
}

func (*removalManifestEvidence) String() string               { return "[private NetBird removal manifest evidence]" }
func (m *removalManifestEvidence) GoString() string           { return m.String() }
func (*removalManifestEvidence) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

func readRemovalStageManifest(parent context.Context, root string, owner uint32, requestID string, descriptor packageapi.Removal) (*removalManifestEvidence, error) {
	if parent == nil || parent.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !netbirdcommand.ValidRequestID(requestID) || !descriptor.Valid() {
		return nil, ErrRemoval
	}
	var held []*os.File
	defer func() {
		for _, file := range held {
			_ = file.Close()
		}
	}()
	source := removalSnapshotFor(parent, root, owner, map[string]removalObject{})
	source.held = &held
	v := &removalManifestEvidence{}
	var err error
	if v.root, err = source.object(".", false, true); err != nil {
		return nil, ErrRemoval
	}
	if v.source, err = source.object("Applications", false, true); err != nil {
		return nil, ErrRemoval
	}
	name := "Applications/" + removalStagePrefix + requestID
	if v.directory, err = source.object(name, false, true); err != nil || v.directory.Mode != uint32(os.ModeDir|0700) || v.directory.UID != owner {
		return nil, ErrRemoval
	}
	stage := removalSnapshotFor(parent, filepath.Join(root, name), owner, map[string]removalObject{})
	stage.held = &held
	if obj, err := stage.object(".", false, true); err != nil || obj != v.directory {
		return nil, ErrRemoval
	}
	file, err := stage.open("manifest.json")
	if err != nil {
		return nil, ErrRemoval
	}
	held = append(held, file)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode() != 0600 || info.Size() <= 0 || info.Size() > maxRemovalManifestBytes {
		return nil, ErrRemoval
	}
	if v.file, err = stage.object("manifest.json", false, false); err != nil || v.file.Mode != 0600 || v.file.UID != owner || !sameRemovalInfo(v.file, info, false) {
		return nil, ErrRemoval
	}
	data, err := io.ReadAll(contextReader{parent, io.LimitReader(file, maxRemovalManifestBytes+1)})
	defer clear(data)
	if err != nil || int64(len(data)) != info.Size() || parent.Err() != nil {
		return nil, ErrRemoval
	}
	manifest, err := decodeRemovalStageManifest(data, owner, requestID, descriptor)
	if err != nil || manifest.Objects["."] != v.root || manifest.Objects["Applications"] != v.source {
		return nil, ErrRemoval
	}
	v.manifest = *manifest
	// Keep all first-pass descriptors until both the protected ancestry and the
	// exact manifest have been reobserved, preventing immediate inode reuse.
	for _, check := range []struct {
		snapshot *removalSnapshot
		name     string
		ancestor bool
		expected removalObject
	}{{source, ".", true, v.root}, {source, "Applications", true, v.source}, {source, name, true, v.directory}, {stage, ".", true, v.directory}, {stage, "manifest.json", false, v.file}} {
		actual, err := check.snapshot.object(check.name, false, check.ancestor)
		if err != nil || actual != check.expected {
			return nil, ErrRemoval
		}
	}
	if current, err := file.Stat(); err != nil || !sameRemovalInfo(v.file, current, false) || parent.Err() != nil {
		return nil, ErrRemoval
	}
	encoded, err := json.Marshal([]removalObject{v.root, v.source, v.directory, v.file})
	if err != nil {
		return nil, ErrRemoval
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-manifest/v1\x00"), encoded...))
	clear(encoded)
	v.digest = hex.EncodeToString(hash[:])
	return v, nil
}
