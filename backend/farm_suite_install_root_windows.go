//go:build windows

package backend

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validateCanonicalSuiteInstallRoot(h SuiteOwnershipHandoff) error {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if err != nil {
		return err
	}
	want := filepath.Join(programFiles, "Ant Browser Suite", "versions", filepath.Base(h.SuiteBinaryRoot))
	if !strings.EqualFold(filepath.Clean(h.SuiteBinaryRoot), filepath.Clean(want)) {
		return fmt.Errorf("%w: noncanonical Program Files root", ErrSuiteServiceActivation)
	}
	// Native write/WRITE_DAC denial and alternate-user evidence remain required
	// before this adapter may activate a task. Fail closed in this first slice.
	return fmt.Errorf("%w: native immutable-tree DACL proof unavailable", ErrSuiteServiceActivation)
}
