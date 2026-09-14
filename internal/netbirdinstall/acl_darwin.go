//go:build darwin && cgo

package netbirdinstall

/*
#include <errno.h>
#include <sys/acl.h>

static int openuem_netbird_acl_readonly(int fd) {
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    // On a valid opened descriptor, ENOENT means no extended ACL is attached.
    // A missing/replaced path is rejected by the caller before this check.
    if (acl == NULL) return errno == ENOENT;
    acl_entry_t entry;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    unsigned int count = 0;
    while (result == 0) {
        if (++count > 1024) { acl_free(acl); return 0; }
        acl_tag_t tag;
        acl_permset_t perms;
        if (acl_get_tag_type(entry, &tag) != 0 || acl_get_permset(entry, &perms) != 0) { acl_free(acl); return 0; }
        if (tag == ACL_EXTENDED_ALLOW) {
            acl_perm_t writes[] = { ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
                ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER };
            for (unsigned int i = 0; i < sizeof(writes)/sizeof(writes[0]); i++) {
                if (acl_get_perm_np(perms, writes[i]) != 0) { acl_free(acl); return 0; }
            }
        } else if (tag != ACL_EXTENDED_DENY) { acl_free(acl); return 0; }
        result = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
    }
    int ended = result == -1 && errno == EINVAL;
    acl_free(acl);
    return ended;
}
*/
import "C"
import "os"

func nativeInstallerAvailable() bool { return true }

func trustedNativeACL(path string) bool {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || C.openuem_netbird_acl_readonly(C.int(file.Fd())) == 0 {
		return false
	}
	after, err := os.Lstat(path)
	return err == nil && os.SameFile(opened, after)
}
