//go:build darwin || linux

package netbirdinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/open-uem/nats/netbirdcommand"
)

type removalRecoveryReceipts struct{ kind, digest string }

func (*removalRecoveryReceipts) String() string               { return "[private NetBird removal recovery receipts]" }
func (r *removalRecoveryReceipts) GoString() string           { return r.String() }
func (*removalRecoveryReceipts) MarshalJSON() ([]byte, error) { return nil, ErrRemoval }

// Receipt files remain exact original objects in the current file evidence.
// Native listing independently distinguishes recognized BOM-backed records from
// an orphan plist. No failed command, orphan or missing file proves completion.
func inspectRemovalRecoveryReceipts(ctx context.Context, files *removalRecoveryFiles, read packageReader) (*removalRecoveryReceipts, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || files.manifest == nil || !files.manifest.manifest.Descriptor.Valid() || !netbirdcommand.ValidDigest(files.digest) || read == nil {
		return nil, ErrRemoval
	}
	plist, ok := files.source[removalReceipt+".plist"]
	if !ok {
		return nil, ErrRemoval
	}
	bom, ok := files.source[removalReceipt+".bom"]
	if !ok {
		return nil, ErrRemoval
	}
	kind, expectedFiles := "present", "present"
	if plist.Missing && bom.Missing {
		kind, expectedFiles = "absent", "absent"
	} else if plist.Missing {
		kind, expectedFiles = "bom-only", "partial"
	} else if bom.Missing {
		kind, expectedFiles = "plist-only", "partial"
	}
	if files.receipts != expectedFiles {
		return nil, ErrRemoval
	}
	present, err := nativeRemovalReceiptPresent(ctx, read)
	if err != nil || present == bom.Missing {
		return nil, ErrRemoval
	}
	if kind == "present" {
		if read(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--pkg-info-plist", "io.netbird.client"}, 32<<10, func(reader io.Reader) error {
			version, err := nativeReceiptVersion(reader)
			if err != nil || version != files.manifest.manifest.Descriptor.Version {
				return ErrRemoval
			}
			return nil
		}) != nil {
			return nil, ErrRemoval
		}
	}
	// A surviving BOM still has to enumerate the complete ORIGINAL receipt
	// payload. Remaining staged files may have been purged and are not that list.
	if present {
		if read(ctx, "/usr/sbin/pkgutil", []string{"--volume", "/", "--files", "io.netbird.client"}, 128<<10, func(reader io.Reader) error {
			return removalReceiptPaths(reader, files.manifest.manifest.Objects)
		}) != nil {
			return nil, ErrRemoval
		}
	}
	after, err := nativeRemovalReceiptPresent(ctx, read)
	if err != nil || after != present || ctx.Err() != nil {
		return nil, ErrRemoval
	}
	data, err := json.Marshal(struct{ Files, Kind string }{files.digest, kind})
	if err != nil {
		return nil, ErrRemoval
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-recovery-receipts/v1\x00"), data...))
	clear(data)
	return &removalRecoveryReceipts{kind, hex.EncodeToString(hash[:])}, nil
}
