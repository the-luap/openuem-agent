//go:build darwin || linux

package netbirdinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var errRemovalFiles = errors.New("the NetBird installed package ownership could not be verified")

const (
	removalApp        = "Applications/NetBird.app"
	removalCLI        = "usr/local/bin/netbird"
	removalDaemon     = "Library/LaunchDaemons/netbird.plist"
	removalReceipt    = "private/var/db/receipts/io.netbird.client"
	maxRemovalObjects = 1056
	maxRemovalBytes   = 256 << 20
)

// This is private filesystem evidence, not a wire Removal or proof of stopped
// processes. A complete native owner must also inspect launchd and process state
// before producing a removal descriptor or claiming absence.
type removalFileEvidence struct {
	version, architecture string
	objects               map[string]removalObject
	digest                string
}

func (*removalFileEvidence) String() string               { return "[private NetBird package ownership]" }
func (s *removalFileEvidence) GoString() string           { return s.String() }
func (*removalFileEvidence) MarshalJSON() ([]byte, error) { return nil, errRemovalFiles }

type removalObject struct {
	Device, Inode, Links    uint64
	Mode, UID, GID, Flags   uint32
	Size, Modified, Changed int64
	Hash, ACL, Link         string
	Missing                 bool
}

type removalFilesBackend struct {
	read   packageReader
	verify func(context.Context, string) error
}

// inspectNativeRemovalFiles never runs NetBird or package scripts. It is not
// connected to the service until the complete native removal owner is available.
func inspectNativeRemovalFiles(ctx context.Context) (*removalFileEvidence, error) {
	if !InstallationSupported() {
		return nil, errRemovalFiles
	}
	return inspectRemovalFiles(ctx, "/", 0, runtime.GOARCH, removalFilesBackend{readNativePackage, verifyRemovalPublisher})
}

func inspectRemovalFiles(parent context.Context, root string, owner uint32, architecture string, backend removalFilesBackend) (*removalFileEvidence, error) {
	if parent == nil || parent.Err() != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || architecture != "arm64" && architecture != "amd64" || backend.read == nil || backend.verify == nil {
		return nil, errRemovalFiles
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	// Keep first-pass descriptors open until the comparison completes. An unlink
	// followed by immediate inode reuse must not impersonate the inspected file.
	var held []*os.File
	defer func() {
		for _, file := range held {
			_ = file.Close()
		}
	}()
	before, data, err := removalFileSnapshot(ctx, root, owner, &held)
	if err != nil {
		return nil, errRemovalFiles
	}
	defer func() {
		for _, value := range data {
			clear(value)
		}
	}()
	var version string
	if backend.read(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--pkg-info-plist", "io.netbird.client"}, 32<<10, func(reader io.Reader) error {
		var err error
		version, err = nativeReceiptVersion(reader)
		return err
	}) != nil || !removalBundleIdentity(data[removalApp+"/Contents/Info.plist"], version) {
		return nil, errRemovalFiles
	}
	for _, name := range []string{"netbird", "netbird-ui"} {
		path := removalApp + "/Contents/MacOS/" + name
		if !thinMachO(data[path], architecture) || before[path].Mode&0111 == 0 {
			return nil, errRemovalFiles
		}
	}
	if !before[removalDaemon].Missing && !removalServiceIdentity(data[removalDaemon], !before[removalCLI].Missing) {
		return nil, errRemovalFiles
	}
	if backend.read(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--files", "io.netbird.client"}, 128<<10, func(reader io.Reader) error { return removalReceiptPaths(reader, before) }) != nil || backend.verify(ctx, root) != nil {
		return nil, errRemovalFiles
	}
	after, repeated, err := removalFileSnapshot(ctx, root, owner, nil)
	for _, value := range repeated {
		clear(value)
	}
	if err != nil || !reflect.DeepEqual(before, after) || ctx.Err() != nil {
		return nil, errRemovalFiles
	}
	// Canonical JSON sorts the object map. Paths and native metadata stay local;
	// even an incidental JSON/log rendering cannot expose this private snapshot.
	encoded, err := json.Marshal(struct {
		Version, Architecture string
		Objects               map[string]removalObject
	}{version, architecture, after})
	if err != nil {
		return nil, errRemovalFiles
	}
	digest := sha256.Sum256(append([]byte("openuem/netbird/removal-files/v1\x00"), encoded...))
	clear(encoded)
	return &removalFileEvidence{version, architecture, after, hex.EncodeToString(digest[:])}, nil
}

type removalSnapshot struct {
	ctx       context.Context
	root      string
	owner     uint32
	objects   map[string]removalObject
	data      map[string][]byte
	remaining int64
	held      *[]*os.File
}

func removalFileSnapshot(ctx context.Context, root string, owner uint32, held *[]*os.File) (map[string]removalObject, map[string][]byte, error) {
	s := removalSnapshot{ctx: ctx, root: root, owner: owner, objects: make(map[string]removalObject), data: make(map[string][]byte), remaining: maxRemovalBytes, held: held}
	fail := func() (map[string]removalObject, map[string][]byte, error) {
		for _, value := range s.data {
			clear(value)
		}
		return nil, nil, errRemovalFiles
	}
	if _, err := s.object(".", false, true); err != nil {
		return fail()
	}
	for _, name := range []string{"Applications", "private", "private/var", "private/var/db", "private/var/db/receipts"} {
		if _, err := s.object(name, false, true); err != nil {
			return fail()
		}
	}
	for _, suffix := range []string{".plist", ".bom"} {
		obj, err := s.object(removalReceipt+suffix, false, false)
		if err != nil || obj.Mode&uint32(os.ModeType) != 0 {
			return fail()
		}
	}
	if s.walk(removalApp, 0) != nil {
		return fail()
	}
	for _, name := range []string{removalCLI, removalDaemon} {
		parts := strings.Split(name, "/")
		missing := false
		for index := 1; index < len(parts); index++ {
			ancestor := strings.Join(parts[:index], "/")
			if missing {
				s.objects[ancestor] = removalObject{Missing: true}
				continue
			}
			obj, err := s.object(ancestor, true, true)
			if err != nil {
				return fail()
			}
			missing = obj.Missing
		}
		if missing {
			s.objects[name] = removalObject{Missing: true}
			continue
		}
		if _, err := s.object(name, true, false); err != nil {
			return fail()
		}
	}
	if len(s.objects) > maxRemovalObjects {
		return fail()
	}
	return s.objects, s.data, nil
}

func (s *removalSnapshot) walk(name string, depth int) error {
	if depth > 16 || len(s.objects) >= maxRemovalObjects {
		return errRemovalFiles
	}
	obj, err := s.object(name, false, false)
	if err != nil {
		return err
	}
	device := s.objects[removalApp].Device
	if name == removalApp {
		device = s.objects["Applications"].Device
	}
	if obj.Device != device {
		return errRemovalFiles
	}
	if obj.Mode&uint32(os.ModeDir) == 0 {
		if name == removalApp {
			return errRemovalFiles
		}
		return nil
	}
	file, err := s.open(name)
	if err != nil {
		return errRemovalFiles
	}
	opened, statErr := file.Stat()
	names, readErr := file.Readdirnames(maxRemovalObjects - len(s.objects) + 1)
	closeErr := file.Close()
	if statErr != nil || readErr != nil && readErr != io.EOF || closeErr != nil || len(names) > maxRemovalObjects-len(s.objects) || !sameRemovalInfo(obj, opened, false) {
		return errRemovalFiles
	}
	slices.Sort(names)
	for _, part := range names {
		if !safeRemovalPath(part) || strings.Contains(part, "/") || s.walk(name+"/"+part, depth+1) != nil {
			return errRemovalFiles
		}
	}
	after, err := s.object(name, false, false)
	if err != nil || after != obj {
		return errRemovalFiles
	}
	return nil
}

func (s *removalSnapshot) object(name string, optional, ancestor bool) (removalObject, error) {
	fail := func() (removalObject, error) { return removalObject{}, errRemovalFiles }
	if s.ctx.Err() != nil || len(s.objects) >= maxRemovalObjects && s.objects[name] == (removalObject{}) {
		return fail()
	}
	path := filepath.Join(s.root, name)
	info, err := os.Lstat(path)
	if optional && errors.Is(err, os.ErrNotExist) {
		obj := removalObject{Missing: true}
		s.objects[name] = obj
		return obj, nil
	}
	if err != nil {
		return fail()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != s.owner && stat.Uid != 0 || ancestor && !info.IsDir() {
		return fail()
	}
	obj := removalInfo(info, ancestor)
	if name == removalCLI {
		if info.Mode()&os.ModeSymlink == 0 || stat.Nlink != 1 {
			return fail()
		}
		parent, err := s.parent(name)
		if err != nil {
			return fail()
		}
		var target [1024]byte
		n, err := unix.Readlinkat(int(parent.Fd()), filepath.Base(name), target[:])
		closeErr := parent.Close()
		if err != nil || closeErr != nil || n == len(target) || string(target[:n]) != "/"+removalApp+"/Contents/MacOS/netbird" {
			return fail()
		}
		obj.Link = string(target[:n])
		after, err := os.Lstat(path)
		if err != nil || !sameRemovalInfo(obj, after, false) {
			return fail()
		}
		s.objects[name] = obj
		return obj, nil
	}
	if (!info.IsDir() && !info.Mode().IsRegular()) || !info.IsDir() && stat.Nlink != 1 || info.Mode().Perm()&0002 != 0 || info.Mode().Perm()&0020 != 0 && stat.Gid != 80 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || !ancestor && name == removalDaemon && !info.Mode().IsRegular() {
		return fail()
	}
	file, err := s.open(name)
	if err != nil {
		return fail()
	}
	retainedFile := false
	defer func() {
		if !retainedFile {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil || !sameRemovalInfo(obj, opened, ancestor) {
		return fail()
	}
	acl, trusted := removalACL(file)
	if !trusted {
		return fail()
	}
	obj.ACL = acl
	if info.Mode().IsRegular() {
		limit := int64(maxRemovalBytes)
		if strings.HasPrefix(name, removalReceipt) {
			limit = 4 << 20
		}
		if name == removalApp+"/Contents/Info.plist" {
			limit = 32 << 10
		}
		if name == removalDaemon {
			limit = 64 << 10
		}
		if info.Size() < 0 || info.Size() > limit || info.Size() > s.remaining {
			return fail()
		}
		hash := sha256.New()
		reader := io.TeeReader(contextReader{s.ctx, io.LimitReader(file, info.Size()+1)}, hash)
		var retained []byte
		var copied int64
		if name == removalApp+"/Contents/Info.plist" || name == removalDaemon {
			retained, err = io.ReadAll(reader)
			copied = int64(len(retained))
		} else {
			if name == removalApp+"/Contents/MacOS/netbird" || name == removalApp+"/Contents/MacOS/netbird-ui" {
				retained = make([]byte, 32)
				_, err = io.ReadFull(reader, retained)
				copied = 32
			}
			if err == nil {
				var n int64
				n, err = io.Copy(io.Discard, reader)
				copied += n
			}
		}
		if err != nil || copied != info.Size() {
			clear(retained)
			return fail()
		}
		s.remaining -= copied
		s.data[name] = retained
		obj.Hash = hex.EncodeToString(hash.Sum(nil))
	}
	after, err := os.Lstat(path)
	if err != nil || !sameRemovalInfo(obj, after, ancestor) || s.ctx.Err() != nil {
		return fail()
	}
	if s.held != nil {
		*s.held = append(*s.held, file)
		retainedFile = true
	} else if file.Close() != nil {
		return fail()
	}
	s.objects[name] = obj
	return obj, nil
}

// Traverse using owned directory descriptors. O_NOFOLLOW applies to every
// component, so replacing an intermediate directory cannot redirect a read.
func (s *removalSnapshot) parent(name string) (*os.File, error) {
	file, err := os.OpenFile(s.root, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, errRemovalFiles
	}
	parts := []string{"."}
	if dir := filepath.Dir(name); dir != "." {
		parts = append(parts, strings.Split(dir, "/")...)
	}
	current := ""
	for index, part := range parts {
		if index > 0 {
			current = filepath.Join(current, part)
			fd, err := unix.Openat(int(file.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			file.Close()
			if err != nil {
				return nil, errRemovalFiles
			}
			file = os.NewFile(uintptr(fd), current)
		}
		info, err := file.Stat()
		if err != nil || s.ctx.Err() != nil {
			file.Close()
			return nil, errRemovalFiles
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != s.owner || !info.IsDir() || info.Mode().Perm()&0002 != 0 || info.Mode().Perm()&0020 != 0 && stat.Gid != 80 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			file.Close()
			return nil, errRemovalFiles
		}
		acl, trusted := removalACL(file)
		key := current
		if key == "" {
			key = "."
		}
		if expected, found := s.objects[key]; !trusted || found && (!sameRemovalInfo(expected, info, key != removalApp && !strings.HasPrefix(key, removalApp+"/")) || expected.ACL != acl) {
			file.Close()
			return nil, errRemovalFiles
		}
	}
	return file, nil
}

func (s *removalSnapshot) open(name string) (*os.File, error) {
	parent, err := s.parent(name)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errRemovalFiles
	}
	return os.NewFile(uintptr(fd), name), nil
}

func removalInfo(info os.FileInfo, ancestor bool) removalObject {
	stat := info.Sys().(*syscall.Stat_t)
	changed, flags := removalChange(stat)
	obj := removalObject{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Links: uint64(stat.Nlink), Mode: uint32(info.Mode()), UID: stat.Uid, GID: stat.Gid, Size: info.Size(), Modified: info.ModTime().UnixNano(), Changed: changed, Flags: flags}
	if ancestor {
		obj.Size, obj.Modified, obj.Changed, obj.Links = 0, 0, 0, 0
	}
	return obj
}

func sameRemovalInfo(obj removalObject, info os.FileInfo, ancestor bool) bool {
	if info == nil {
		return false
	}
	obj.Hash, obj.ACL, obj.Link = "", "", ""
	return obj == removalInfo(info, ancestor)
}

func safeRemovalPath(name string) bool {
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) || name == "." || name == ".." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) || filepath.Clean(name) != name || strings.Contains(name, "\\") {
		return false
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func removalReceiptPaths(reader io.Reader, objects map[string]removalObject) error {
	data, err := io.ReadAll(io.LimitReader(reader, (128<<10)+1))
	if err != nil || len(data) > 128<<10 || len(data) == 0 || data[len(data)-1] != '\n' {
		return errRemovalFiles
	}
	seen := make(map[string]bool)
	for _, name := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if !safeRemovalPath(name) || seen[name] || name != "Applications" && name != removalApp && !strings.HasPrefix(name, removalApp+"/") {
			return errRemovalFiles
		}
		if _, ok := objects[name]; !ok {
			return errRemovalFiles
		}
		seen[name] = true
	}
	for name := range objects {
		if (name == removalApp || strings.HasPrefix(name, removalApp+"/")) && !seen[name] {
			return errRemovalFiles
		}
	}
	return nil
}

func removalBundleIdentity(data []byte, version string) bool {
	values, err := nativePlist(bytes.NewReader(data), 32<<10)
	if err != nil {
		return false
	}
	for key, want := range map[string]string{"CFBundleIdentifier": "io.netbird.client", "CFBundleVersion": version, "CFBundleShortVersionString": version, "CFBundleExecutable": "netbird-ui", "CFBundlePackageType": "APPL"} {
		if actual, ok := plistString(values, key); !ok || actual != want {
			return false
		}
	}
	return true
}

// Only the conventional system daemon can be reviewed. Unknown launchd keys,
// an alternate executable, chroot or user service require a different owner.
func removalServiceIdentity(data []byte, cliPresent bool) bool {
	values, err := nativePlist(bytes.NewReader(data), 64<<10)
	if err != nil {
		return false
	}
	if label, ok := plistString(values, "Label"); !ok || label != "netbird" {
		return false
	}
	args := values["ProgramArguments"]
	if args == nil || args.name != "array" || len(args.children) < 3 || len(args.children) > 64 {
		return false
	}
	for _, value := range args.children {
		if value.name != "string" || len(value.text) > 4096 || strings.ContainsAny(value.text, "\x00\r\n") {
			return false
		}
	}
	executable := args.children[0].text
	if executable != "/"+removalApp+"/Contents/MacOS/netbird" && (executable != "/"+removalCLI || !cliPresent) || args.children[1].text != "service" || args.children[2].text != "run" {
		return false
	}
	for key, value := range values {
		switch key {
		case "Label", "ProgramArguments":
		case "Disabled", "KeepAlive", "RunAtLoad", "SessionCreate":
			if value.name != "true" && value.name != "false" {
				return false
			}
		case "StandardErrorPath", "StandardOutPath":
			if value.name != "string" || !safeRemovalPath(strings.TrimPrefix(value.text, "/")) || !strings.HasPrefix(value.text, "/var/log/") {
				return false
			}
		case "UserName":
			if value.name != "string" || value.text != "root" {
				return false
			}
		case "WorkingDirectory":
			if value.name != "string" || value.text != "/" {
				return false
			}
		case "EnvironmentVariables":
			env, err := plistDictionary(value)
			if err != nil || len(env) > 64 {
				return false
			}
			for key, item := range env {
				if len(key) > 256 || strings.ContainsAny(key, "=\x00\r\n") || item.name != "string" || len(item.text) > 4096 || strings.ContainsRune(item.text, 0) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

const netbirdDeveloperRequirement = `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "TA739QLA7A"`

func verifyRemovalPublisher(ctx context.Context, root string) error {
	return verifyRemovalPublisherWith(ctx, root, readNativePackage)
}

func verifyRemovalPublisherWith(ctx context.Context, root string, read packageReader) error {
	if ctx == nil || ctx.Err() != nil || read == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errRemovalFiles
	}
	for _, target := range []struct{ path, identifier string }{{removalApp, "io.netbird.client"}, {removalApp + "/Contents/MacOS/netbird", "netbird"}} {
		args := []string{"--verify", "--deep", "--strict", "--all-architectures", "-R", "=" + netbirdDeveloperRequirement + ` and identifier "` + target.identifier + `"`, filepath.Join(root, target.path)}
		if read(ctx, "/usr/bin/codesign", args, 16<<10, func(reader io.Reader) error { _, err := io.Copy(io.Discard, reader); return err }) != nil || ctx.Err() != nil {
			return errRemovalFiles
		}
	}
	return nil
}
