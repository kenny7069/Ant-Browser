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
