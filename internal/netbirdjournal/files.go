package netbirdjournal

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-agent/internal/nativepath"
)

const lockName = ".netbird.lock"
const maxRecord = 4096

type files struct {
	directory  string
	root, lock *os.File
	identity   os.FileInfo
}

func openFiles(directory string) (*files, error) {
	if !nativepath.Valid(directory) || keyfile.CreateDirectory(directory) != nil {
		return nil, ErrUnavailable
	}
	root, err := os.Open(directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := &files{directory: directory, root: root}
	accepted := false
	defer func() {
		if !accepted {
			f.close()
		}
	}()
	f.identity, err = root.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	path := filepath.Join(directory, lockName)
	if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		created, createErr := keyfile.CreateFile(path)
		if createErr == nil {
			syncErr := created.Sync()
			closeErr := created.Close()
			if syncErr != nil || closeErr != nil {
				return nil, ErrUnavailable
			}
		}
	}
	f.lock, err = keyfile.Open(path, 1)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = lockFile(f.lock); err != nil {
		return nil, ErrUnavailable
	}
	if f.valid() != nil {
		return nil, ErrUnavailable
	}
	accepted = true
	return f, nil
}

func (f *files) valid() error {
	if f == nil || f.root == nil || f.lock == nil || keyfile.CheckDirectory(f.directory) != nil {
		return ErrUnavailable
	}
	root, err := currentFileInfo(f.directory)
	if err != nil || !os.SameFile(root, f.identity) {
		return ErrUnavailable
	}
	current, err := currentFileInfo(filepath.Join(f.directory, lockName))
	if err != nil {
		return ErrUnavailable
	}
	held, err := f.lock.Stat()
	if err != nil || !held.Mode().IsRegular() || held.Size() != 0 || !os.SameFile(current, held) || !singleLink(f.lock) {
		return ErrUnavailable
	}
	return nil
}

func (f *files) names() (map[string]bool, error) {
	if f.valid() != nil {
		return nil, ErrUnavailable
	}
	directory, err := os.Open(f.directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer directory.Close()
	found := map[string]bool{}
	starts := map[int]bool{}
	admissions := map[int]bool{}
	references := map[int]bool{}
	count := 0
	for {
		entries, err := directory.ReadDir(128)
		for _, e := range entries {
			count++
			if count > MaxAttempts*3+2 || e.Type()&os.ModeSymlink != 0 || e.IsDir() {
				return nil, ErrUnavailable
			}
			name := e.Name()
			if name == lockName {
				continue
			}
			if name == "anchor.json" {
				found[name] = true
				continue
			}
			if len(name) < 5 {
				return nil, ErrUnavailable
			}
			index, parseErr := strconv.Atoi(name[:4])
			if parseErr != nil || index < 1 || index > MaxAttempts {
				return nil, ErrUnavailable
			}
			valid := false
			for _, kind := range []string{"start", "result", "release", "withdrawal"} {
				if name == recordName(index, kind) {
					valid = true
					if kind == "start" || kind == "withdrawal" {
						if admissions[index] {
							return nil, ErrUnavailable
						}
						admissions[index] = true
						if kind == "start" {
							starts[index] = true
						}
					} else {
						references[index] = true
					}
				}
			}
			if !valid {
				return nil, ErrUnavailable
			}
			found[name] = true
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	for index := range references {
		if !starts[index] {
			return nil, ErrUnavailable
		}
	}
	return found, nil
}

func (f *files) read(name string, out any) error {
	if f.valid() != nil {
		return ErrUnavailable
	}
	file, err := keyfile.Open(filepath.Join(f.directory, name), maxRecord)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	if !singleLink(file) {
		return ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRecord+1))
	if err != nil || len(data) > maxRecord {
		return ErrUnavailable
	}
	return decodeRecord(data, out)
}

func (f *files) create(name string, value any) error {
	if f.valid() != nil || strings.ContainsAny(name, "/\\") || name == "" {
		return ErrUnavailable
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > maxRecord {
		return ErrUnavailable
	}
	temporary := filepath.Join(f.directory, ".pending-"+uuid.NewString())
	file, err := keyfile.CreateFile(temporary)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	// Incomplete files remain private and make the journal unavailable on reopen.
	// They are never interpreted as an empty slot or silently removed on failure.
	if _, err = file.Write(data); err != nil {
		return ErrUnavailable
	}
	if file.Sync() != nil || file.Close() != nil || f.valid() != nil {
		return ErrUnavailable
	}
	if publishFile(temporary, filepath.Join(f.directory, name), f.root) != nil {
		return ErrUnavailable
	}
	return f.valid()
}

func (f *files) close() error {
	var err error
	if f.lock != nil {
		err = f.lock.Close()
		f.lock = nil
	}
	if f.root != nil {
		if closeErr := f.root.Close(); err == nil {
			err = closeErr
		}
		f.root = nil
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
