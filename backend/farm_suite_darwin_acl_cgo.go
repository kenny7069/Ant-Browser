//go:build darwin && cgo

package backend

/*
#include <errno.h>
#include <stdlib.h>
#include <sys/acl.h>

// 1: at least one extended ACL entry, 0: none, -1: cannot inspect.
static int ant_suite_has_extended_acl(const char *path) {
	acl_t acl = acl_get_link_np(path, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return errno == ENOENT ? 0 : -1;
	}
	acl_entry_t entry;
	int found = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry) == 0;
	acl_free(acl);
	return found ? 1 : 0;
}
*/
import "C"

import "unsafe"

// suiteDarwinHasExtendedACL reports whether path (not followed if a link)
// carries any extended ACL entry.  access(2) cannot see grants such as
// writesecurity or delete, so the install tree must carry no ACL at all.
func suiteDarwinHasExtendedACL(path string) (bool, error) {
	value := C.CString(path)
	defer C.free(unsafe.Pointer(value))
	switch C.ant_suite_has_extended_acl(value) {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, ErrSuiteServiceActivation
	}
}
