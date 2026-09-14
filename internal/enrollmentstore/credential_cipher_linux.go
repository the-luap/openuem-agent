package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/open-uem/openuem-agent/internal/nativepath"
	"golang.org/x/sys/unix"
)

// This private provider requires a separately provisioned systemd host key. It
// cannot enroll an endpoint or initialize native storage on its own.
type linuxCredentialCipher struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	tool, key *linuxCredentialFile
}

type linuxCredentialFile struct {
	path    string
	parts   []string
	parents []*os.File
	file    *os.File
	stamp   unix.Stat_t
	digest  [sha256.Size]byte
}

func openLinuxCredentialFile(path string, key bool) (*linuxCredentialFile, error) {
	if os.Geteuid() != 0 || !nativepath.Valid(path) || path == "/" {
		return nil, ErrUnavailable
	}
	f := &linuxCredentialFile{path: path, parts: strings.Split(strings.TrimPrefix(path, "/"), "/")}
	accepted := false
	defer func() {
		if !accepted {
			f.close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	parent := os.NewFile(uintptr(fd), "/")
	f.parents = append(f.parents, parent)
	for i, part := range f.parts {
		if !linuxLeaseDirectory(parent, false) {
			return nil, ErrUnavailable
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(f.parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err = unix.Openat(int(parent.Fd()), part, flags, 0)
		if err != nil {
			return nil, ErrUnavailable
		}
		opened := os.NewFile(uintptr(fd), part)
		if i == len(f.parts)-1 {
			f.file = opened
		} else {
			f.parents = append(f.parents, opened)
			parent = opened
		}
	}
	if unix.Fstat(int(f.file.Fd()), &f.stamp) != nil || f.stamp.Mode&unix.S_IFMT != unix.S_IFREG || f.stamp.Uid != 0 || f.stamp.Nlink != 1 {
		return nil, ErrUnavailable
	}
	if key {
		if f.stamp.Mode&07777 != 0400 || f.stamp.Size != 4112 {
			return nil, ErrUnavailable
		}
	} else {
		if f.stamp.Mode&07022 != 0 || f.stamp.Mode&0100 == 0 || f.stamp.Size < 4 || f.stamp.Size > 32<<20 {
			return nil, ErrUnavailable
		}
		var magic [4]byte
		if _, err = f.file.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "\x7fELF" {
			return nil, ErrUnavailable
		}
	}
	f.digest, err = linuxCredentialFileDigest(f.file, f.stamp.Size)
	if err != nil {
		return nil, ErrUnavailable
	}
	if !f.valid() {
		return nil, ErrUnavailable
	}
	accepted = true
	return f, nil
}

func (f *linuxCredentialFile) valid() bool {
	if f == nil || f.file == nil || len(f.parents) != len(f.parts) {
		return false
	}
	var actual, root, pinned unix.Stat_t
	if unix.Fstat(int(f.file.Fd()), &actual) != nil || !sameLinuxCredentialStamp(actual, f.stamp) {
		return false
	}
	if unix.Lstat("/", &root) != nil || unix.Fstat(int(f.parents[0].Fd()), &pinned) != nil || root.Dev != pinned.Dev || root.Ino != pinned.Ino {
		return false
	}
	for i, parent := range f.parents {
		if !linuxLeaseDirectory(parent, false) {
			return false
		}
		next := f.file
		if i+1 < len(f.parents) {
			next = f.parents[i+1]
		}
		if !linuxLeaseSame(parent, f.parts[i], next) {
			return false
		}
	}
	digest, err := linuxCredentialFileDigest(f.file, f.stamp.Size)
	return err == nil && digest == f.digest && unix.Fstat(int(f.file.Fd()), &actual) == nil && sameLinuxCredentialStamp(actual, f.stamp)
}

func sameLinuxCredentialStamp(actual, expected unix.Stat_t) bool {
	return actual.Dev == expected.Dev && actual.Ino == expected.Ino && actual.Mode == expected.Mode && actual.Uid == expected.Uid && actual.Gid == expected.Gid && actual.Nlink == 1 && actual.Size == expected.Size && actual.Mtim == expected.Mtim && actual.Ctim == expected.Ctim
}

// Do not rely on timestamp resolution for same-inode changes. The private host
// key passes only through a bounded temporary buffer, which is always cleared.
func linuxCredentialFileDigest(file *os.File, size int64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	var block [32768]byte
	defer clear(block[:])
	hash := sha256.New()
	for offset := int64(0); offset < size; {
		length := min(int64(len(block)), size-offset)
		n, err := file.ReadAt(block[:length], offset)
		if err != nil || int64(n) != length {
			return result, ErrUnavailable
		}
		hash.Write(block[:n])
		offset += int64(n)
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func (f *linuxCredentialFile) close() error {
	if f == nil {
		return nil
	}
	var err error
	if f.file != nil {
		err = f.file.Close()
		f.file = nil
	}
	for i := len(f.parents) - 1; i >= 0; i-- {
		if e := f.parents[i].Close(); err == nil {
			err = e
		}
	}
	f.parents = nil
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func openLinuxCredentialCipher() (*linuxCredentialCipher, error) {
	tool, err := openLinuxCredentialFile("/usr/bin/systemd-creds", false)
	if err != nil {
		return nil, ErrUnavailable
	}
	key, err := openLinuxCredentialFile("/var/lib/systemd/credential.secret", true)
	if err != nil {
		tool.close()
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &linuxCredentialCipher{ctx: ctx, cancel: cancel, tool: tool, key: key}, nil
}

func (c *linuxCredentialCipher) Close() error {
	if c == nil {
		return nil
	}
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	a, b := c.tool.close(), c.key.close()
	if a != nil || b != nil {
		return ErrUnavailable
	}
	return nil
}

// Recognize the source-defined systemd host-key format identifier explicitly.
// Reject null, TPM-only, unknown and noncanonical encodings before native decrypt.
// This is a format allowlist, not a replacement for native authenticated decryption.
var linuxHostCredentialID = []byte{0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62, 0xf1, 0x9a}

func linuxHostCredential(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > maxProtectedSize {
		return nil, ErrUnavailable
	}
	flat := bytes.ReplaceAll(data, []byte("\n"), nil)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(flat)))
	defer clear(decoded)
	n, err := base64.StdEncoding.Strict().Decode(decoded, flat)
	if err != nil || n < 64 || !bytes.HasPrefix(decoded[:n], linuxHostCredentialID) {
		return nil, ErrUnavailable
	}
	canonical := make([]byte, base64.StdEncoding.EncodedLen(n))
	base64.StdEncoding.Encode(canonical, decoded[:n])
	if !bytes.Equal(flat, canonical) {
		return nil, ErrUnavailable
	}
	return canonical, nil
}

const linuxCredentialDomain = "openuem/linux-enrollment-credential/v1\x00"

func linuxCredentialName(directory, record string) (string, error) {
	if !nativepath.Valid(directory) || directory == "/" || !validRecord(record) {
		return "", ErrUnavailable
	}
	hash := sha256.Sum256([]byte(linuxCredentialDomain + directory + "\x00" + record))
	return "openuem-enrollment-" + hex.EncodeToString(hash[:]), nil
}

type linuxCredentialOutput struct {
	data  []byte
	limit int
}

func (b *linuxCredentialOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, ErrUnavailable
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (c *linuxCredentialCipher) protect(parent context.Context, directory, record string, input []byte, encrypt bool) ([]byte, error) {
	name, err := linuxCredentialName(directory, record)
	if err != nil || parent == nil || c == nil {
		return nil, ErrUnavailable
	}
	if len(input) == 0 || (encrypt && len(input) > maxRecordSize) {
		return nil, ErrUnavailable
	}
	prefix := []byte(linuxCredentialDomain + name + "\x00")
	defer clear(prefix)
	var nativeInput []byte
	if encrypt {
		nativeInput = append(append([]byte{}, prefix...), input...)
	} else {
		nativeInput, err = linuxHostCredential(input)
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	defer clear(nativeInput)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil || parent.Err() != nil || !c.tool.valid() || !c.key.valid() {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	operation := "decrypt"
	args := []string{operation, "--name=" + name, "-", "-"}
	if encrypt {
		args = []string{"encrypt", "--with-key=host", "--name=" + name, "-", "-"}
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = "systemd-creds"
	cmd.ExtraFiles = []*os.File{c.tool.file}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_LOG_TARGET=null", "SYSTEMD_LOG_LEVEL=err"}
	cmd.Stdin = bytes.NewReader(nativeInput)
	output := &linuxCredentialOutput{limit: maxProtectedSize}
	defer func() { clear(output.data) }()
	cmd.Stdout, cmd.Stderr = output, io.Discard
	cmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || ctx.Err() != nil || parent.Err() != nil || !c.tool.valid() || !c.key.valid() {
		return nil, ErrUnavailable
	}
	if encrypt {
		return linuxHostCredential(output.data)
	}
	if !bytes.HasPrefix(output.data, prefix) || len(output.data) <= len(prefix) || len(output.data) > len(prefix)+maxRecordSize {
		return nil, ErrUnavailable
	}
	return append([]byte{}, output.data[len(prefix):]...), nil
}
