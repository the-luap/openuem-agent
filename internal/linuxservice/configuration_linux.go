package linuxservice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var ErrConfiguration = errors.New("the protected Linux operational configuration is unavailable or belongs to another installation")

const (
	configurationName           = "openuem.ini"
	logName                     = "openuem-agent.log"
	maxOperationalConfiguration = 32 << 10
)

// Configuration owns the fixed operational directories and the admitted INI.
// The caller supplies the identity-bound INI validator, never arbitrary paths.
// Close releases descriptors and preserves all configuration and log evidence.
type Configuration struct {
	mu           sync.Mutex
	closed       bool
	config, logs *operationalDirectory
	file         *os.File
	validate     func([]byte) bool
}

type operationalDirectory struct {
	parent *protectedDirectory
	name   string
	file   *os.File
}

func OpenConfiguration(ctx context.Context, validate func([]byte) bool) (*Configuration, error) {
	return openConfigurationAt(ctx, ConfigurationDirectory, LogDirectory, validate)
}

func openConfigurationAt(ctx context.Context, config, logs string, validate func([]byte) bool) (_ *Configuration, resultErr error) {
	if ctx == nil || validate == nil || !validPath(config) || !validPath(logs) || config == logs || path.Base(config) != "openuem-agent" || path.Base(logs) != "openuem-agent" {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &Configuration{validate: validate}
	defer func() {
		if resultErr != nil {
			c.Close()
		}
	}()
	for _, target := range []struct {
		destination **operationalDirectory
		path        string
	}{{&c.config, config}, {&c.logs, logs}} {
		parent, err := openProtectedDirectory(path.Dir(target.path))
		if err != nil {
			return nil, ErrConfiguration
		}
		*target.destination = &operationalDirectory{parent: parent, name: path.Base(target.path)}
	}
	if _, err := c.inspect(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func (d *operationalDirectory) valid() bool {
	if d == nil || !d.parent.valid() || d.file == nil {
		return false
	}
	var current, held unix.Stat_t
	return unix.Fstat(int(d.file.Fd()), &held) == nil && unix.Fstatat(int(d.parent.root().Fd()), d.name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && held.Dev == current.Dev && held.Ino == current.Ino && held.Mode&unix.S_IFMT == unix.S_IFDIR && current.Mode&unix.S_IFMT == unix.S_IFDIR && held.Uid == 0 && held.Mode&07777 == 0700
}

func (d *operationalDirectory) inspect() (bool, error) {
	if d == nil || !d.parent.valid() {
		return false, ErrConfiguration
	}
	if d.file == nil {
		fd, err := unix.Openat(int(d.parent.root().Fd()), d.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(err, unix.ENOENT) && d.parent.valid() {
			return false, nil
		}
		if err != nil {
			return false, ErrConfiguration
		}
		d.file = os.NewFile(uintptr(fd), d.name)
	}
	if !d.valid() {
		return false, ErrConfiguration
	}
	return true, nil
}

func (d *operationalDirectory) ensure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	present, err := d.inspect()
	if err != nil {
		return err
	}
	if !present {
		if err := unix.Mkdirat(int(d.parent.root().Fd()), d.name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return ErrConfiguration
		}
	}
	if present, err := d.inspect(); err != nil || !present {
		return ErrConfiguration
	}
	if d.file.Sync() != nil || d.parent.root().Sync() != nil || !d.valid() {
		return ErrConfiguration
	}
	return ctx.Err()
}

func privateOperationalFile(st unix.Stat_t) bool {
	return st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Nlink == 1 && st.Size >= 0
}

func (d *operationalDirectory) matches(name string, file *os.File, stamp unix.Stat_t) bool {
	var held, current unix.Stat_t
	return d.valid() && privateOperationalFile(stamp) && unix.Fstat(int(file.Fd()), &held) == nil && unix.Fstatat(int(d.file.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && sameStamp(held, stamp) && sameStamp(current, stamp)
}

func (c *Configuration) readConfiguration() (bool, error) {
	present, err := c.config.inspect()
	if err != nil || !present {
		return false, err
	}
	file := c.file
	if file == nil {
		fd, err := unix.Openat(int(c.config.file.Fd()), configurationName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.ENOENT) && c.config.valid() {
			return false, nil
		}
		if err != nil {
			return false, ErrConfiguration
		}
		file = os.NewFile(uintptr(fd), configurationName)
		defer func() {
			if c.file != file {
				file.Close()
			}
		}()
	}
	var stamp unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stamp) != nil || !privateOperationalFile(stamp) || stamp.Size < 1 || stamp.Size > maxOperationalConfiguration || !c.config.matches(configurationName, file, stamp) {
		return false, ErrConfiguration
	}
	data := make([]byte, stamp.Size+1)
	n, err := file.ReadAt(data, 0)
	if !errors.Is(err, io.EOF) || int64(n) != stamp.Size || !c.validate(data[:n]) || !c.config.matches(configurationName, file, stamp) {
		return false, ErrConfiguration
	}
	c.file = file
	return true, nil
}

func (c *Configuration) inspectLog() (bool, error) {
	present, err := c.logs.inspect()
	if err != nil || !present {
		return false, err
	}
	fd, err := unix.Openat(int(c.logs.file.Fd()), logName, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) && c.logs.valid() {
		return false, nil
	}
	if err != nil {
		return false, ErrConfiguration
	}
	file := os.NewFile(uintptr(fd), logName)
	defer file.Close()
	var held, current unix.Stat_t
	// The log may be appended by the admitted running agent. Only its object
	// type, private access, single link and namespace matter; never read it.
	if !c.logs.valid() || unix.Fstat(fd, &held) != nil || unix.Fstatat(int(c.logs.file.Fd()), logName, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || !privateOperationalFile(held) || !privateOperationalFile(current) || held.Dev != current.Dev || held.Ino != current.Ino {
		return false, ErrConfiguration
	}
	return true, nil
}

// Call with mu held. This preflight never creates a directory or file.
func (c *Configuration) inspect() (bool, error) {
	if c.closed {
		return false, ErrConfiguration
	}
	present, err := c.readConfiguration()
	if err != nil {
		return false, err
	}
	log, err := c.inspectLog()
	if err != nil || (log && !present) {
		return false, ErrConfiguration
	}
	return present, nil
}

func (c *Configuration) Prepare(ctx context.Context, data []byte) error {
	if c == nil || ctx == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closed || len(data) == 0 || len(data) > maxOperationalConfiguration {
		return ErrConfiguration
	}
	data = bytes.Clone(data)
	if !c.validate(data) {
		return ErrConfiguration
	}
	if _, err := c.inspect(); err != nil {
		return err
	}
	for _, d := range []*operationalDirectory{c.config, c.logs} {
		if err := d.ensure(ctx); err != nil {
			return err
		}
	}
	if present, err := c.inspect(); err != nil {
		return err
	} else if !present {
		if err := c.publish(ctx, data); err != nil {
			return err
		}
	}
	if c.file.Sync() != nil || c.config.file.Sync() != nil {
		return ErrConfiguration
	}
	return c.verify(ctx)
}

// Publish an entire private INI without replacing an existing entry. An admitted
// concurrent winner may contain legitimate settings and is preserved as written.
func (c *Configuration) publish(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.config.valid() {
		return ErrConfiguration
	}
	name := ".openuem-config-" + uuid.NewString() + ".tmp"
	parent := int(c.config.file.Fd())
	fd, err := unix.Openat(parent, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrConfiguration
	}
	file := os.NewFile(uintptr(fd), name)
	retained := false
	defer func() {
		if !retained {
			var stamp unix.Stat_t
			if unix.Fstat(fd, &stamp) == nil && stamp.Size <= maxOperationalConfiguration && c.config.matches(name, file, stamp) {
				_ = unix.Unlinkat(parent, name, 0)
			}
			file.Close()
		}
	}()
	if n, err := file.Write(data); err != nil || n != len(data) || file.Sync() != nil {
		return ErrConfiguration
	}
	var stamp unix.Stat_t
	if unix.Fstat(fd, &stamp) != nil || !c.config.matches(name, file, stamp) {
		return ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = unix.Renameat2(parent, name, parent, configurationName, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		if present, err := c.readConfiguration(); err != nil || !present {
			return ErrConfiguration
		}
		if c.config.file.Sync() != nil {
			return ErrConfiguration
		}
		return ctx.Err()
	}
	if err != nil {
		return ErrConfiguration
	}
	c.file, retained = file, true
	if c.config.file.Sync() != nil {
		return ErrConfiguration
	}
	return ctx.Err()
}

func (c *Configuration) Verify(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrConfiguration
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.verify(ctx)
}

func (c *Configuration) verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if present, err := c.inspect(); err != nil || !present || !c.config.valid() || !c.logs.valid() {
		return ErrConfiguration
	}
	return ctx.Err()
}

func (c *Configuration) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		if c.file != nil {
			c.file.Close()
		}
		for _, d := range []*operationalDirectory{c.config, c.logs} {
			if d != nil {
				if d.file != nil {
					d.file.Close()
				}
				d.parent.close()
			}
		}
	}
	return nil
}
