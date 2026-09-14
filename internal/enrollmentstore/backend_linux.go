package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

const linuxRecordDirectory = "credentials-v1"
const linuxRecordSuffix = ".cred"
const linuxTemporaryPrefix = ".enrollment-"
const maxLinuxStateEntries = 20000

type linuxStateDirectory struct {
	path    string
	parts   []string
	parents []*os.File
	root    *os.File
}

type linuxBackend struct {
	mu           sync.RWMutex
	closed       bool
	installation *linuxStateDirectory
	directory    *linuxStateDirectory
	cipher       *linuxCredentialCipher
}

// OpenNative creates a final private installation directory and its dedicated
// credential child beneath existing trusted root-owned ancestors. It never
// repairs permissions or provisions an OS key.
func OpenNative(directory string) (NativeBackend, error) {
	if os.Geteuid() != 0 || !nativepath.Valid(directory) || directory == "/" {
		return nil, ErrUnavailable
	}
	cipher, err := openLinuxCredentialCipher()
	if err != nil {
		return nil, err
	}
	dir, err := openLinuxStateDirectory(directory)
	if err != nil {
		cipher.Close()
		return nil, err
	}
	records, err := openLinuxStateDirectory(filepath.Join(directory, linuxRecordDirectory))
	if err != nil {
		dir.close()
		cipher.Close()
		return nil, err
	}
	b := &linuxBackend{installation: dir, directory: records, cipher: cipher}
	if _, err := b.names(); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

func openLinuxStateDirectory(path string) (*linuxStateDirectory, error) {
	d := &linuxStateDirectory{path: path, parts: strings.Split(strings.TrimPrefix(path, "/"), "/")}
	accepted := false
	defer func() {
		if !accepted {
			d.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	parent := os.NewFile(uintptr(fd), "/")
	d.parents = append(d.parents, parent)
	for i, part := range d.parts {
		if !linuxLeaseDirectory(parent, false) {
			return nil, ErrUnavailable
		}
		last := i == len(d.parts)-1
		fd, err = unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if last && errors.Is(err, unix.ENOENT) {
			err = unix.Mkdirat(int(parent.Fd()), part, 0700)
			if err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, ErrUnavailable
			}
			if parent.Sync() != nil {
				return nil, ErrUnavailable
			}
			fd, err = unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if err != nil {
			return nil, ErrUnavailable
		}
		opened := os.NewFile(uintptr(fd), part)
		if last {
			d.root = opened
		} else {
			d.parents = append(d.parents, opened)
			parent = opened
		}
	}
	if !d.valid() {
		return nil, ErrUnavailable
	}
	accepted = true
	return d, nil
}

func (d *linuxStateDirectory) valid() bool {
	if d == nil || !linuxLeaseDirectory(d.root, true) || len(d.parents) != len(d.parts) {
		return false
	}
	var actual, pinned unix.Stat_t
	if unix.Lstat("/", &actual) != nil || unix.Fstat(int(d.parents[0].Fd()), &pinned) != nil || actual.Dev != pinned.Dev || actual.Ino != pinned.Ino {
		return false
	}
	for i, parent := range d.parents {
		if !linuxLeaseDirectory(parent, false) {
			return false
		}
		next := d.root
		if i+1 < len(d.parents) {
			next = d.parents[i+1]
		}
		if !linuxLeaseSame(parent, d.parts[i], next) {
			return false
		}
	}
	return true
}
func (d *linuxStateDirectory) close() error {
	if d == nil {
		return nil
	}
	var err error
	if d.root != nil {
		err = d.root.Close()
		d.root = nil
	}
	for i := len(d.parents) - 1; i >= 0; i-- {
		if e := d.parents[i].Close(); err == nil {
			err = e
		}
	}
	d.parents = nil
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (b *linuxBackend) Close() error {
	if b == nil {
		return nil
	}
	b.cipher.cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	a, c, d := b.cipher.Close(), b.directory.close(), b.installation.close()
	if a != nil || c != nil || d != nil {
		return ErrUnavailable
	}
	return nil
}

// Call while holding the backend lifetime lock. The independent service lease is
// not acquired here: concurrent enrollment processes must reload one Create winner.
func (b *linuxBackend) current() bool {
	if b.closed || !b.installation.valid() || !b.directory.valid() {
		return false
	}
	b.cipher.mu.Lock()
	defer b.cipher.mu.Unlock()
	return b.cipher.ctx.Err() == nil && b.cipher.tool.valid() && b.cipher.key.valid()
}

func linuxTemporaryName(name string) bool {
	id, ok := strings.CutPrefix(name, linuxTemporaryPrefix)
	if !ok {
		return false
	}
	id, ok = strings.CutSuffix(id, ".tmp")
	if !ok {
		return false
	}
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}
func linuxPrivateRecord(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == 0 && stat.Mode&07777 == 0600 && stat.Nlink == 1 && stat.Size >= 0 && stat.Size <= maxProtectedSize
}

// Inventory committed names without decrypting thousands of absent journal slots.
// Only canonical private crash temporaries are ignored inside the credential child.
func (b *linuxBackend) names() ([]string, error) {
	if !b.current() {
		return nil, ErrUnavailable
	}
	fd, err := unix.Openat(int(b.directory.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "identity records")
	defer file.Close()
	var records []string
	count := 0
	for {
		names, err := file.Readdirnames(128)
		for _, name := range names {
			count++
			if count > maxLinuxStateEntries {
				return nil, ErrUnavailable
			}
			temporary := linuxTemporaryName(name)
			record, canonical := strings.CutSuffix(name, linuxRecordSuffix)
			if !temporary && (!canonical || !validRecord(record)) {
				return nil, ErrUnavailable
			}
			var stat unix.Stat_t
			e := unix.Fstatat(int(b.directory.root.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
			if temporary && errors.Is(e, unix.ENOENT) {
				continue
			}
			if e != nil || !linuxPrivateRecord(stat) {
				return nil, ErrUnavailable
			}
			if temporary {
				continue
			}
			if stat.Size == 0 {
				return nil, ErrUnavailable
			}
			records = append(records, record)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	if !b.current() {
		return nil, ErrUnavailable
	}
	return records, nil
}

func (b *linuxBackend) hasSecurityRecords() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := b.names()
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if name != pendingRecord && name != identityRecord {
			return true, nil
		}
	}
	return b.runtimeEvidence()
}

// A missing credential subtree must not erase surviving operation journals or
// runtime state. Existing complete identities may still coexist with that state.
func (b *linuxBackend) runtimeEvidence() (bool, error) {
	if !b.current() {
		return false, ErrUnavailable
	}
	fd, err := unix.Openat(int(b.installation.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "installation state")
	defer file.Close()
	for {
		names, err := file.Readdirnames(128)
		for _, name := range names {
			if name == linuxRecordDirectory {
				continue
			}
			if name != serviceLeaseName {
				return true, nil
			}
			var stat unix.Stat_t
			if unix.Fstatat(int(b.installation.root.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || !linuxPrivateRecord(stat) || stat.Size != 0 {
				return false, ErrUnavailable
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, ErrUnavailable
		}
	}
	if !b.current() {
		return false, ErrUnavailable
	}
	return false, nil
}

func (b *linuxBackend) hasSoftwareRecords() (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := b.names()
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if strings.HasPrefix(name, "software-") {
			return true, nil
		}
	}
	return false, nil
}
func (b *linuxBackend) softwareRecordOrdinals() ([]int, error) {
	return b.softwareOrdinals("start", "result")
}
func (b *linuxBackend) softwareReconciliationOrdinals() ([]int, error) {
	return b.softwareOrdinals("reconciliation", "reconciliation-ack")
}
func (b *linuxBackend) softwareOrdinals(stages ...string) ([]int, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := b.names()
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	for _, name := range names {
		for _, stage := range stages {
			if suffix, ok := strings.CutPrefix(name, "software-"+stage+"-v1-"); ok {
				n, err := strconv.Atoi(suffix)
				if err != nil {
					return nil, ErrUnavailable
				}
				seen[n] = true
			}
		}
	}
	result := make([]int, 0, len(seen))
	for n := range seen {
		result = append(result, n)
	}
	slices.Sort(result)
	return result, nil
}

func (b *linuxBackend) Load(record string) ([]byte, error) {
	if !validRecord(record) {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.current() {
		return nil, ErrUnavailable
	}
	name := record + linuxRecordSuffix
	fd, err := unix.Openat(int(b.directory.root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		if _, err := b.names(); err != nil {
			return nil, err
		}
		return nil, ErrMissing
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !linuxPrivateRecord(before) || before.Size == 0 {
		return nil, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, maxProtectedSize+1))
	defer clear(data)
	if err != nil || int64(len(data)) != before.Size {
		return nil, ErrUnavailable
	}
	digest := sha256.Sum256(data)
	plaintext, err := b.cipher.protect(context.Background(), b.directory.path, record, data, false)
	if err != nil {
		return nil, err
	}
	if !b.matchesFile(name, file, before, digest) || !b.current() {
		clear(plaintext)
		return nil, ErrUnavailable
	}
	return plaintext, nil
}

func (b *linuxBackend) matchesFile(name string, file *os.File, before unix.Stat_t, digest [sha256.Size]byte) bool {
	var after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &after) != nil || !sameLinuxCredentialStamp(after, before) || !linuxPrivateRecord(after) || !linuxLeaseSame(b.directory.root, name, file) {
		return false
	}
	current, err := linuxCredentialFileDigest(file, before.Size)
	return err == nil && current == digest && unix.Fstat(int(file.Fd()), &after) == nil && sameLinuxCredentialStamp(after, before)
}

func (b *linuxBackend) Create(record string, plaintext []byte) error {
	if !validRecord(record) || len(plaintext) == 0 || len(plaintext) > maxRecordSize {
		return ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if _, err := b.names(); err != nil {
		return err
	}
	name := record + linuxRecordSuffix
	var existing unix.Stat_t
	if err := unix.Fstatat(int(b.directory.root.Fd()), name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return ErrExists
	} else if !errors.Is(err, unix.ENOENT) {
		return ErrUnavailable
	}
	data, err := b.cipher.protect(context.Background(), b.directory.path, record, plaintext, true)
	if err != nil {
		return err
	}
	defer clear(data)
	if !b.current() {
		return ErrUnavailable
	}
	temporary := linuxTemporaryPrefix + uuid.NewString() + ".tmp"
	fd, err := unix.Openat(int(b.directory.root.Fd()), temporary, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer func() {
		// Remove only our own unpublished temporary inode. Never unlink a
		// replacement, an unrelated crash fragment or a published record.
		if linuxLeaseSame(b.directory.root, temporary, file) {
			_ = unix.Unlinkat(int(b.directory.root.Fd()), temporary, 0)
		}
		file.Close()
	}()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !linuxPrivateRecord(before) || before.Size != 0 {
		return ErrUnavailable
	}
	if n, err := file.Write(data); err != nil || n != len(data) {
		return ErrUnavailable
	}
	if file.Sync() != nil || unix.Fstat(fd, &before) != nil || before.Size != int64(len(data)) || !b.matchesFile(temporary, file, before, sha256.Sum256(data)) || !b.current() {
		return ErrUnavailable
	}
	if err := unix.Renameat2(int(b.directory.root.Fd()), temporary, int(b.directory.root.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrExists
		}
		return ErrUnavailable
	}
	// A failure after exclusive publication retains the immutable record. A
	// retry must load it; it must never delete or overwrite uncertain evidence.
	if b.directory.root.Sync() != nil || !b.current() {
		return ErrUnavailable
	}
	var published unix.Stat_t
	if unix.Fstat(fd, &published) != nil || !b.matchesFile(name, file, published, sha256.Sum256(data)) {
		return ErrUnavailable
	}
	return nil
}
