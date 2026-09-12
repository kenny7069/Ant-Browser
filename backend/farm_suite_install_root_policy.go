package backend

import "fmt"

const suiteWindowsDangerousAccessMask uint32 = 0x10000000 | // GENERIC_ALL
	0x40000000 | // GENERIC_WRITE
	0x00010000 | // DELETE
	0x00040000 | // WRITE_DAC
	0x00080000 | // WRITE_OWNER
	0x00000002 | // FILE_WRITE_DATA / FILE_ADD_FILE
	0x00000004 | // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	0x00000010 | // FILE_WRITE_EA
	0x00000040 | // FILE_DELETE_CHILD
	0x00000100 // FILE_WRITE_ATTRIBUTES

type suiteInstallACEPolicy struct {
	Allowed          bool
	ObjectACE        bool
	UnknownAllowType bool
	InheritOnly      bool
	CreatorOwner     bool
	Mask             uint32
	TrustedPrincipal bool
}

type suiteInstallDACLPolicy struct {
	TrustedOwner bool
	DACLPresent  bool
	ACEs         []suiteInstallACEPolicy
}

func validateSuiteInstallDACLPolicy(policy suiteInstallDACLPolicy) error {
	if !policy.TrustedOwner || !policy.DACLPresent {
		return fmt.Errorf("%w: immutable tree owner or DACL invalid", ErrSuiteServiceActivation)
	}
	for _, ace := range policy.ACEs {
		if ace.UnknownAllowType {
			return fmt.Errorf("%w: unknown immutable tree allow ACE", ErrSuiteServiceActivation)
		}
		if !ace.Allowed || ace.Mask&suiteWindowsDangerousAccessMask == 0 || (ace.InheritOnly && ace.CreatorOwner) {
			continue
		}
		if ace.ObjectACE || !ace.TrustedPrincipal {
			return fmt.Errorf("%w: dangerous immutable tree allow ACE", ErrSuiteServiceActivation)
		}
	}
	return nil
}
