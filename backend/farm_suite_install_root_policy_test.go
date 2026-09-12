package backend

import (
	"errors"
	"testing"
)

func TestSuiteInstallDACLPolicyRejectsDangerousUntrustedRights(t *testing.T) {
	if err := validateSuiteInstallDACLPolicy(suiteInstallDACLPolicy{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{Allowed: true, Mask: 0x1200a9}}}); err != nil {
		t.Fatalf("read-only ACE rejected: %v", err)
	}
	for _, test := range []suiteInstallDACLPolicy{
		{DACLPresent: true},
		{TrustedOwner: true},
		{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{Allowed: true, Mask: 0x40000000}}},
		{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{Allowed: true, Mask: 0x00040000, TrustedPrincipal: true, ObjectACE: true}}},
		{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{UnknownAllowType: true}}},
	} {
		if err := validateSuiteInstallDACLPolicy(test); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("unsafe policy accepted: %+v err=%v", test, err)
		}
	}
	trusted := suiteInstallDACLPolicy{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{Allowed: true, Mask: suiteWindowsDangerousAccessMask, TrustedPrincipal: true}}}
	if err := validateSuiteInstallDACLPolicy(trusted); err != nil {
		t.Fatalf("trusted machine principal rejected: %v", err)
	}
	creatorOwner := suiteInstallDACLPolicy{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{Allowed: true, Mask: suiteWindowsDangerousAccessMask, InheritOnly: true, CreatorOwner: true}}}
	if err := validateSuiteInstallDACLPolicy(creatorOwner); err != nil {
		t.Fatalf("inherit-only CREATOR OWNER rejected: %v", err)
	}
}

func TestSuiteInstallDangerousMaskIncludesIndividualRights(t *testing.T) {
	for _, right := range []uint32{0x10000000, 0x40000000, 0x00010000, 0x00040000, 0x00080000, 0x2, 0x4, 0x10, 0x40, 0x100} {
		if suiteWindowsDangerousAccessMask&right == 0 {
			t.Fatalf("missing right %#x", right)
		}
	}
}

func TestSuiteInstallAmbiguousAllowACETypesFailClosed(t *testing.T) {
	for _, aceType := range []uint8{4, 5, 9, 11} {
		allowed, objectACE, unknownAllow := classifySuiteInstallACEType(aceType)
		if allowed || !unknownAllow || (aceType == 5 && !objectACE) {
			t.Fatalf("type %d classification allowed=%v object=%v unknown=%v", aceType, allowed, objectACE, unknownAllow)
		}
		policy := suiteInstallDACLPolicy{TrustedOwner: true, DACLPresent: true, ACEs: []suiteInstallACEPolicy{{UnknownAllowType: unknownAllow}}}
		if err := validateSuiteInstallDACLPolicy(policy); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("ambiguous allow ACE type %d accepted: %v", aceType, err)
		}
	}
}

func TestSuiteInstallACELayoutRejectsTruncationAndInvalidSIDHeader(t *testing.T) {
	for _, size := range []uint16{0, 4, 7} {
		if err := validateSuiteInstallACEHeaderMaskSize(size); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("short ACE size %d accepted: %v", size, err)
		}
	}
	for _, test := range []struct {
		size     uint16
		revision uint8
		count    uint8
	}{
		{size: 16, revision: 1, count: 1},
		{size: 64, revision: 2, count: 1},
		{size: 80, revision: 1, count: 16},
	} {
		if _, err := validateSuiteInstallAllowedSIDLayout(test.size, test.revision, test.count); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("invalid SID layout accepted: %+v err=%v", test, err)
		}
	}
	if length, err := validateSuiteInstallAllowedSIDLayout(20, 1, 1); err != nil || length != 12 {
		t.Fatalf("valid SID layout length=%d err=%v", length, err)
	}
}
