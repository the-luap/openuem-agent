//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/open-uem/nats/netbirdcommand"
	"golang.org/x/sys/unix"
)

const removalStagePrefix = ".openuem-netbird-removal-"

var removalStageParents = []string{".", "Applications", "usr", "usr/local", "usr/local/bin", "Library", "Library/LaunchDaemons"}
var removalRoots = []string{removalApp, removalCLI, removalDaemon}

// Failed stages are evidence, not disposable downloads. Close never removes
// their contents. Only the successful, verified execution can finish a stage.
type removalStaging struct {
	root, path, name          string
	owner                     uint32
	original, anchors, staged map[string]removalObject
	held                      []*os.File
	parent, directory         *os.File
	manifest                  removalObject
	purged                    bool
}

func (*removalStaging) String() string               { return "[private NetBird removal staging]" }
func (s *removalStaging) GoString() string           { return s.String() }
func (*removalStaging) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

func removalSnapshotFor(ctx context.Context, root string, owner uint32, objects map[string]removalObject) *removalSnapshot {
	return &removalSnapshot{ctx: ctx, root: root, owner: owner, objects: maps.Clone(objects), data: make(map[string][]byte), remaining: maxRemovalBytes}
}

func clearRemovalData(s *removalSnapshot) {
	for _, data := range s.data {
		clear(data)
	}
}

func removalPayload(name string) bool {
	return name == removalApp || strings.HasPrefix(name, removalApp+"/") || name == removalCLI || name == removalDaemon
}

func executableRemovalFiles(objects map[string]removalObject) bool {
	for name, obj := range objects {
		if removalPayload(name) && !obj.Missing && name != removalCLI && obj.Mode&0022 != 0 {
			return false
		}
	}
	return true
}

func newRemovalStaging(ctx context.Context, root string, owner uint32, requestID string, observed *removalOwnership) (*removalStaging, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !netbirdcommand.ValidRequestID(requestID) || observed == nil || observed.files == nil || !observed.descriptor.Valid() {
		return nil, ErrRemoval
	}
	// A descriptor can inspect admin-writable bundles, but execution cannot
	// safely delete them while another writer retains a directory or file fd.
	if !executableRemovalFiles(observed.files.objects) || removalNoStages(ctx, root, owner) != nil {
		return nil, ErrRemoval
	}
	s := &removalStaging{root: root, owner: owner, name: removalStagePrefix + requestID, original: maps.Clone(observed.files.objects), anchors: make(map[string]removalObject), staged: make(map[string]removalObject)}
	encoded, err := encodeRemovalStageManifest(removalStageManifest{1, requestID, observed.descriptor, s.original}, owner)
	if err != nil {
		return nil, ErrRemoval
	}
	defer clear(encoded)
	s.path = filepath.Join(root, "Applications", s.name)
	source := removalSnapshotFor(ctx, root, owner, s.original)
	parent, err := source.parent("Applications/" + s.name)
	if err != nil {
		return nil, ErrRemoval
	}
	s.parent = parent
	fail := func() (*removalStaging, error) { s.close(); return nil, ErrRemoval }
	if unix.Mkdirat(int(parent.Fd()), s.name, 0700) != nil {
		return fail()
	}
	fd, err := unix.Openat(int(parent.Fd()), s.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	s.directory = os.NewFile(uintptr(fd), s.path)
	initial := removalSnapshotFor(ctx, s.path, owner, s.anchors)
	initial.held = &s.held
	obj, err := initial.object(".", false, true)
	if err != nil || obj.UID != owner || obj.Mode != uint32(os.ModeDir|0700) {
		return fail()
	}
	s.anchors["."] = obj
	for _, name := range removalStageParents[1:] {
		initial.objects = maps.Clone(s.anchors)
		p, err := initial.parent(name)
		if err != nil {
			return fail()
		}
		err = unix.Mkdirat(int(p.Fd()), filepath.Base(name), 0700)
		syncErr := p.Sync()
		closeErr := p.Close()
		if err != nil || syncErr != nil || closeErr != nil {
			return fail()
		}
		obj, err := initial.object(name, false, true)
		if err != nil || obj.UID != owner || obj.Mode != uint32(os.ModeDir|0700) {
			return fail()
		}
		s.anchors[name] = obj
	}
	fd, err = unix.Openat(int(s.directory.Fd()), "manifest.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fail()
	}
	manifest := os.NewFile(uintptr(fd), "manifest.json")
	n, writeErr := manifest.Write(encoded)
	syncErr := manifest.Sync()
	closeErr := manifest.Close()
	if writeErr != nil || n != len(encoded) || syncErr != nil || closeErr != nil || s.directory.Sync() != nil || s.parent.Sync() != nil {
		return fail()
	}
	initial.objects = maps.Clone(s.anchors)
	s.manifest, err = initial.object("manifest.json", false, false)
	if err != nil || s.manifest.UID != owner || s.manifest.Mode != 0600 || s.guard(ctx) != nil {
		return fail()
	}
	return s, nil
}

func (s *removalStaging) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.directory == nil || s.parent == nil {
		return ErrRemoval
	}
	source := removalSnapshotFor(ctx, s.root, s.owner, s.original)
	parent, err := source.parent("Applications/" + s.name)
	if err != nil {
		return ErrRemoval
	}
	defer parent.Close()
	info, err := parent.Stat()
	held, heldErr := s.parent.Stat()
	if err != nil || heldErr != nil || !os.SameFile(info, held) {
		return ErrRemoval
	}
	check := removalSnapshotFor(ctx, s.path, s.owner, s.anchors)
	for _, name := range removalStageParents {
		obj, err := check.object(name, false, true)
		if err != nil || obj != s.anchors[name] {
			return ErrRemoval
		}
	}
	info, err = s.directory.Stat()
	if err != nil || !sameRemovalInfo(s.anchors["."], info, true) {
		return ErrRemoval
	}
	return nil
}

func (s *removalStaging) move(ctx context.Context) error {
	for _, name := range removalRoots {
		if s.guard(ctx) != nil {
			return ErrRemoval
		}
		source := removalSnapshotFor(ctx, s.root, s.owner, s.original)
		obj, err := source.object(name, true, false)
		clearRemovalData(source)
		if err != nil || obj != s.original[name] {
			return ErrRemoval
		}
		if obj.Missing {
			continue
		}
		destination := removalSnapshotFor(ctx, s.path, s.owner, s.anchors)
		from, err := source.parent(name)
		if err != nil {
			return ErrRemoval
		}
		to, err := destination.parent(name)
		if err != nil {
			from.Close()
			return ErrRemoval
		}
		err = renameRemovalExclusive(int(from.Fd()), filepath.Base(name), int(to.Fd()), filepath.Base(name))
		if err == nil {
			// Capture the entire relocated object before accepting ownership. The
			// rename's ctime update is permitted only on this moved root.
			captured, captureErr := s.capture(ctx, name)
			if captureErr != nil {
				// Restore only into the same protected, empty original slot. Never
				// overwrite a replacement or delete an object we cannot identify.
				check, checkErr := source.parent(name)
				if checkErr == nil {
					a, e1 := check.Stat()
					b, e2 := from.Stat()
					if e1 == nil && e2 == nil && os.SameFile(a, b) {
						_ = renameRemovalExclusive(int(to.Fd()), filepath.Base(name), int(from.Fd()), filepath.Base(name))
					}
					check.Close()
				}
				err = ErrRemoval
			} else {
				maps.Copy(s.staged, captured)
			}
		}
		if from.Sync() != nil || to.Sync() != nil {
			err = ErrRemoval
		}
		if from.Close() != nil {
			err = ErrRemoval
		}
		if to.Close() != nil {
			err = ErrRemoval
		}
		if err != nil {
			return ErrRemoval
		}
	}
	return s.verify(ctx)
}

func (s *removalStaging) capture(ctx context.Context, name string) (map[string]removalObject, error) {
	check := removalSnapshotFor(ctx, s.path, s.owner, s.anchors)
	check.held = &s.held
	defer clearRemovalData(check)
	if name == removalApp {
		if check.walk(name, 0) != nil {
			return nil, ErrRemoval
		}
	} else {
		if _, err := check.object(name, false, false); err != nil {
			return nil, ErrRemoval
		}
	}
	result := make(map[string]removalObject)
	for path, obj := range check.objects {
		if !removalPayload(path) {
			continue
		}
		expected, ok := s.original[path]
		if path == name {
			expected.Changed = obj.Changed
		}
		if !ok || expected != obj {
			return nil, ErrRemoval
		}
		result[path] = obj
	}
	for path, obj := range s.original {
		if !obj.Missing && (path == name || strings.HasPrefix(path, name+"/")) {
			if _, ok := result[path]; !ok {
				return nil, ErrRemoval
			}
		}
	}
	return result, nil
}

func (s *removalStaging) verify(ctx context.Context) error {
	if s.guard(ctx) != nil || s.purged {
		return ErrRemoval
	}
	check := removalSnapshotFor(ctx, s.path, s.owner, s.anchors)
	defer clearRemovalData(check)
	if check.walk(removalApp, 0) != nil {
		return ErrRemoval
	}
	for _, name := range removalRoots[1:] {
		if _, err := check.object(name, true, false); err != nil {
			return ErrRemoval
		}
	}
	for name, obj := range check.objects {
		if removalPayload(name) {
			if obj.Missing {
				if !s.original[name].Missing {
					return ErrRemoval
				}
			} else if s.staged[name] != obj {
				return ErrRemoval
			}
		}
	}
	for name, obj := range s.staged {
		if check.objects[name] != obj {
			return ErrRemoval
		}
	}
	manifest, err := check.object("manifest.json", false, false)
	if err != nil || manifest != s.manifest {
		return ErrRemoval
	}
	return nil
}

func (s *removalStaging) verifyReceipts(ctx context.Context) error {
	if s.guard(ctx) != nil {
		return ErrRemoval
	}
	check := removalSnapshotFor(ctx, s.root, s.owner, s.original)
	defer clearRemovalData(check)
	for _, suffix := range []string{".plist", ".bom"} {
		name := removalReceipt + suffix
		obj, err := check.object(name, false, false)
		if err != nil || obj != s.original[name] {
			return ErrRemoval
		}
	}
	return nil
}

func (s *removalStaging) purge(ctx context.Context) error {
	if s.verify(ctx) != nil {
		return ErrRemoval
	}
	names := slices.Collect(maps.Keys(s.staged))
	slices.SortFunc(names, func(a, b string) int {
		if n := strings.Count(b, "/") - strings.Count(a, "/"); n != 0 {
			return n
		}
		return strings.Compare(b, a)
	})
	for _, name := range names {
		if s.guard(ctx) != nil {
			return ErrRemoval
		}
		expected := s.staged[name]
		dir := expected.Mode&uint32(os.ModeDir) != 0
		check := removalSnapshotFor(ctx, s.path, s.owner, s.anchors)
		actual, err := check.object(name, false, dir)
		clearRemovalData(check)
		if dir {
			expected.Size, expected.Modified, expected.Changed, expected.Links = 0, 0, 0, 0
		}
		if err != nil || actual != expected {
			return ErrRemoval
		}
		parent, err := check.parent(name)
		if err != nil {
			return ErrRemoval
		}
		flags := 0
		if dir {
			flags = unix.AT_REMOVEDIR
		}
		err = unix.Unlinkat(int(parent.Fd()), filepath.Base(name), flags)
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if err != nil || syncErr != nil || closeErr != nil {
			return ErrRemoval
		}
	}
	s.purged = true
	return nil
}

func (s *removalStaging) sourcesAbsent(ctx context.Context) error {
	if !s.purged || s.guard(ctx) != nil {
		return ErrRemoval
	}
	return removalSourcesAbsent(ctx, s.root, s.owner, false)
}

func (s *removalStaging) finish(ctx context.Context) error {
	if !s.purged || s.guard(ctx) != nil {
		return ErrRemoval
	}
	check := removalSnapshotFor(ctx, s.path, s.owner, s.anchors)
	manifest, err := check.object("manifest.json", false, false)
	clearRemovalData(check)
	if err != nil || manifest != s.manifest {
		return ErrRemoval
	}
	root, err := check.open(".")
	if err != nil {
		return ErrRemoval
	}
	names, readErr := root.Readdirnames(5)
	closeErr := root.Close()
	slices.Sort(names)
	if readErr != nil && readErr != io.EOF || closeErr != nil || !slices.Equal(names, []string{"Applications", "Library", "manifest.json", "usr"}) {
		return ErrRemoval
	}
	// Empty-directory removal preserves any unexpected remaining entry.
	for i := len(removalStageParents) - 1; i > 0; i-- {
		name := removalStageParents[i]
		parent, err := check.parent(name)
		if err != nil {
			return ErrRemoval
		}
		err = unix.Unlinkat(int(parent.Fd()), filepath.Base(name), unix.AT_REMOVEDIR)
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if err != nil || syncErr != nil || closeErr != nil {
			return ErrRemoval
		}
	}
	if ctx.Err() != nil || unix.Unlinkat(int(s.directory.Fd()), "manifest.json", 0) != nil || s.directory.Sync() != nil || unix.Unlinkat(int(s.parent.Fd()), s.name, unix.AT_REMOVEDIR) != nil || s.parent.Sync() != nil {
		return ErrRemoval
	}
	return nil
}

func (s *removalStaging) close() error {
	var result error
	for _, file := range s.held {
		if file.Close() != nil {
			result = ErrRemoval
		}
	}
	s.held = nil
	for _, file := range []*os.File{s.directory, s.parent} {
		if file != nil && file.Close() != nil {
			result = ErrRemoval
		}
	}
	s.directory, s.parent = nil, nil
	return result
}

// Check each existing ancestor before accepting a missing leaf. In particular,
// ENOENT reached through an untrusted symlink is never positive absence.
func removalSourcesAbsent(ctx context.Context, root string, owner uint32, stages bool) error {
	_, err := removalAbsenceFileSnapshot(ctx, root, owner, stages, nil)
	return err
}

func removalNoStages(ctx context.Context, root string, owner uint32) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRemoval
	}
	check := removalSnapshotFor(ctx, root, owner, map[string]removalObject{})
	if _, err := check.object(".", false, true); err != nil {
		return ErrRemoval
	}
	app, err := check.object("Applications", true, true)
	if err != nil {
		return ErrRemoval
	}
	if app.Missing {
		return nil
	}
	dir, err := check.open("Applications")
	if err != nil {
		return ErrRemoval
	}
	names, readErr := dir.Readdirnames(8193)
	closeErr := dir.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(names) > 8192 || ctx.Err() != nil {
		return ErrRemoval
	}
	if slices.ContainsFunc(names, func(name string) bool { return strings.HasPrefix(name, removalStagePrefix) }) {
		return ErrRemoval
	}
	return nil
}
