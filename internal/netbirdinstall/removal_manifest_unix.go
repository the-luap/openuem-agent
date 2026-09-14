//go:build darwin || linux

package netbirdinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

const maxRemovalManifestBytes = 2 << 20

// The local manifest preserves the existing schema-one wire bytes. It is private
// filesystem evidence, not proof of current ownership, journal admission or safe
// recovery. Only the explicit codec can serialize its object metadata.
type removalStageManifest struct {
	Schema     int
	RequestID  string
	Descriptor packageapi.Removal
	Objects    map[string]removalObject
}

func (removalStageManifest) String() string               { return "[private NetBird removal manifest]" }
func (m removalStageManifest) GoString() string           { return m.String() }
func (removalStageManifest) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

var removalManifestAncestors = map[string]bool{
	".": true, "Applications": true, "private": true, "private/var": true,
	"private/var/db": true, "private/var/db/receipts": true,
	"usr": false, "usr/local": false, "usr/local/bin": false,
	"Library": false, "Library/LaunchDaemons": false,
}

func validRemovalStageManifest(m removalStageManifest, owner uint32) bool {
	if m.Schema != 1 || !netbirdcommand.ValidRequestID(m.RequestID) || !m.Descriptor.Valid() || m.Descriptor.Platform != "macos" || len(m.Objects) == 0 || len(m.Objects) > maxRemovalObjects {
		return false
	}
	for name, required := range removalManifestAncestors {
		obj, ok := m.Objects[name]
		if !ok || required && obj.Missing {
			return false
		}
	}
	for _, name := range []string{removalCLI, removalDaemon, removalReceipt + ".plist", removalReceipt + ".bom", removalApp, removalApp + "/Contents", removalApp + "/Contents/Info.plist", removalApp + "/Contents/MacOS", removalApp + "/Contents/MacOS/netbird", removalApp + "/Contents/MacOS/netbird-ui"} {
		obj, ok := m.Objects[name]
		if !ok || obj.Missing && name != removalCLI && name != removalDaemon {
			return false
		}
	}
	for _, name := range []string{removalReceipt + ".plist", removalReceipt + ".bom", removalApp + "/Contents/Info.plist", removalApp + "/Contents/MacOS/netbird", removalApp + "/Contents/MacOS/netbird-ui"} {
		if !os.FileMode(m.Objects[name].Mode).IsRegular() {
			return false
		}
	}
	var total int64
	for name, obj := range m.Objects {
		_, ancestor := removalManifestAncestors[name]
		if name != "." && !safeRemovalPath(name) || !ancestor && !removalPayload(name) && name != removalReceipt+".plist" && name != removalReceipt+".bom" {
			return false
		}
		if strings.Count(name, "/") > 17 {
			return false
		}
		if obj.Missing {
			if obj != (removalObject{Missing: true}) || !ancestor && name != removalCLI && name != removalDaemon {
				return false
			}
			continue
		}
		if obj.UID != owner && obj.UID != 0 || obj.Inode == 0 || obj.Size < 0 || obj.ACL != "" && !netbirdcommand.ValidDigest(obj.ACL) {
			return false
		}
		mode := os.FileMode(obj.Mode)
		if name == removalCLI {
			if mode&os.ModeType != os.ModeSymlink || obj.Links != 1 || obj.Link != "/"+removalApp+"/Contents/MacOS/netbird" || obj.Hash != "" || obj.ACL != "" {
				return false
			}
		} else {
			if (!mode.IsRegular() && !mode.IsDir()) || mode.Perm()&0002 != 0 || mode.Perm()&0020 != 0 && obj.GID != 80 || mode&(os.ModeSetuid|os.ModeSetgid) != 0 || obj.Link != "" {
				return false
			}
			if mode.IsDir() {
				if obj.Hash != "" || name == removalDaemon || strings.HasPrefix(name, removalReceipt) {
					return false
				}
			} else {
				if ancestor || obj.Links != 1 || !netbirdcommand.ValidDigest(obj.Hash) || obj.Size > maxRemovalBytes {
					return false
				}
				total += obj.Size
				if total > maxRemovalBytes {
					return false
				}
			}
		}
		if ancestor && (!mode.IsDir() || obj.Size != 0 || obj.Modified != 0 || obj.Changed != 0 || obj.Links != 0) {
			return false
		}
		if name != "." {
			parent, found := m.Objects[filepath.Dir(name)]
			if !found || parent.Missing || os.FileMode(parent.Mode)&os.ModeType != os.ModeDir {
				return false
			}
		}
	}
	return executableRemovalFiles(m.Objects)
}

func encodeRemovalStageManifest(m removalStageManifest, owner uint32) ([]byte, error) {
	if !validRemovalStageManifest(m, owner) {
		return nil, ErrRemoval
	}
	type wire removalStageManifest
	data, err := json.Marshal(wire(m))
	if err != nil || len(data) > maxRemovalManifestBytes {
		clear(data)
		return nil, ErrRemoval
	}
	return data, nil
}

func decodeRemovalStageManifest(data []byte, owner uint32, requestID string, descriptor packageapi.Removal) (*removalStageManifest, error) {
	if len(data) == 0 || len(data) > maxRemovalManifestBytes || !netbirdcommand.ValidRequestID(requestID) || !descriptor.Valid() {
		return nil, ErrRemoval
	}
	type wire removalStageManifest
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil {
		return nil, ErrRemoval
	}
	m := removalStageManifest(decoded)
	if m.RequestID != requestID || m.Descriptor != descriptor {
		return nil, ErrRemoval
	}
	canonical, err := encodeRemovalStageManifest(m, owner)
	defer clear(canonical)
	// The original writer emits canonical JSON. Equality independently rejects
	// duplicate/aliased/missing fields, nulls, trailers and normalized numbers.
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, ErrRemoval
	}
	return &m, nil
}
