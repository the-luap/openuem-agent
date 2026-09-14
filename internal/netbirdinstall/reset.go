package netbirdinstall

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment/keyfile"
	packageapi "github.com/open-uem/nats/netbirdinstall"
)

// CheckEmptyRoot verifies a failed stage left no files behind, without deleting
// replacements that Prepared.Close deliberately preserved. Only startup recovery
// may reset abandoned bytes after the prior service has relinquished ownership.
func CheckEmptyRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || keyfile.CheckDirectory(filepath.Dir(root)) != nil || keyfile.CheckDirectory(root) != nil {
		return ErrChanged
	}
	_, err := boundedEntries(root, 0)
	return err
}

// ResetRoot removes at most one abandoned preparation beneath a private root.
// The caller must hold the installation's exclusive journal lease and join all
// prior preparation users before calling this function. Ancestors must remain
// protected throughout use. Unknown, replaced or unprotected entries fail closed;
// this function never recursively removes a directory or follows a symlink.
func ResetRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || keyfile.CheckDirectory(filepath.Dir(root)) != nil || keyfile.CreateDirectory(root) != nil {
		return ErrChanged
	}
	dirs, err := boundedEntries(root, 1)
	if err != nil {
		return ErrChanged
	}
	if len(dirs) == 0 {
		return nil
	}
	entry := dirs[0]
	id := strings.TrimPrefix(entry.Name(), "netbird-package-")
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id || entry.Name() != "netbird-package-"+id || !entry.IsDir() {
		return ErrChanged
	}
	directory := filepath.Join(root, entry.Name())
	if keyfile.CheckDirectory(directory) != nil {
		return ErrChanged
	}
	files, err := boundedEntries(directory, 1)
	if err != nil {
		return ErrChanged
	}
	if len(files) == 1 {
		file := files[0]
		if file.Name() != "package.deb" && file.Name() != "package.rpm" && file.Name() != "package.pkg" {
			return ErrChanged
		}
		if !file.Mode().IsRegular() || file.Size() > packageapi.MaxPackageSize {
			return ErrChanged
		}
		path := filepath.Join(directory, file.Name())
		opened, err := keyfile.Open(path, packageapi.MaxPackageSize)
		if err != nil {
			return ErrChanged
		}
		info, statErr := opened.Stat()
		closeErr := opened.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(info, file) || !sameEntry(directory, entry) || !sameEntry(path, file) {
			return ErrChanged
		}
		if os.Remove(path) != nil {
			return ErrChanged
		}
	}
	if !sameEntry(directory, entry) || os.Remove(directory) != nil {
		return ErrChanged
	}
	return nil
}

func sameEntry(path string, before os.FileInfo) bool {
	after, err := os.Lstat(path)
	return err == nil && os.SameFile(before, after)
}

func boundedEntries(path string, max int) ([]os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.Readdir(max + 1)
	if err != nil && err != io.EOF || len(entries) > max {
		return nil, ErrChanged
	}
	return entries, nil
}
