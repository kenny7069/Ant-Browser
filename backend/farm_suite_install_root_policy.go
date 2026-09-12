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

func classifySuiteInstallACEType(aceType uint8) (allowed, objectACE, unknownAllow bool) {
	switch aceType {
	case 0: // ACCESS_ALLOWED_ACE_TYPE
		return true, false, false
	case 4, 9, 11: // compound/callback allow forms are not accepted by this parser
		return false, false, true
	case 5: // object ACE has variable GUID fields and is deliberately rejected
		return false, true, true
	default:
		return false, false, false
	}
}

func validateSuiteInstallACEHeaderMaskSize(aceSize uint16) error {
	if aceSize < 8 {
		return fmt.Errorf("%w: truncated immutable tree ACE", ErrSuiteServiceActivation)
	}
	return nil
}

func validateSuiteInstallAllowedSIDLayout(aceSize uint16, revision, subAuthorityCount uint8) (uint16, error) {
	if err := validateSuiteInstallACEHeaderMaskSize(aceSize); err != nil {
		return 0, err
	}
	if revision != 1 || subAuthorityCount > 15 {
		return 0, fmt.Errorf("%w: invalid immutable tree ACE SID header", ErrSuiteServiceActivation)
	}
	sidLength := uint16(8 + 4*uint16(subAuthorityCount))
	if uint32(8)+uint32(sidLength) > uint32(aceSize) {
		return 0, fmt.Errorf("%w: immutable tree ACE SID exceeds ACE", ErrSuiteServiceActivation)
	}
	return sidLength, nil
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
