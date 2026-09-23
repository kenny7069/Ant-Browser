package backend

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"
)

// Release builds pin the Developer ID team with
//
//	-ldflags "-X ant-chrome/backend.suiteDarwinCodeSigningTeamID=ABCDE12345"
//
// Test builds that ad-hoc sign their payload must opt in explicitly with
// suiteDarwinAllowAdhocCodeSigning=1.  A binary built with neither refuses
// every macOS install, so a development build can never pass as a release.
var (
	suiteDarwinCodeSigningTeamID     = ""
	suiteDarwinAllowAdhocCodeSigning = ""
)

var ErrSuiteDarwinCodeSignature = errors.New("suite macOS code signature policy failed")

var suiteDarwinTeamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

type suiteDarwinSigningPolicy struct {
	TeamID     string
	AllowAdhoc bool
}

func currentSuiteDarwinSigningPolicy() suiteDarwinSigningPolicy {
	return suiteDarwinSigningPolicy{
		TeamID:     strings.TrimSpace(suiteDarwinCodeSigningTeamID),
		AllowAdhoc: strings.TrimSpace(suiteDarwinAllowAdhocCodeSigning) == "1",
	}
}

// codesignArguments returns the exact verification arguments for one code
// object.  With a pinned team the designated requirement must name it; the
// ad-hoc test policy only proves the signature seals the bytes on disk.
func (p suiteDarwinSigningPolicy) codesignArguments(object string) ([]string, error) {
	arguments := []string{"--verify", "--deep", "--strict"}
	switch {
	case p.TeamID != "":
		if !suiteDarwinTeamIDPattern.MatchString(p.TeamID) {
			return nil, fmt.Errorf("%w: pinned team identifier is malformed", ErrSuiteDarwinCodeSignature)
		}
		// Developer ID Application only: same-team Development or
		// Distribution certificates must not satisfy a release build.
		arguments = append(arguments,
			`-R=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists`+
				` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`+
				` and certificate leaf[subject.OU] = "`+p.TeamID+`"`)
	case p.AllowAdhoc:
	default:
		return nil, fmt.Errorf("%w: no signing policy compiled into this build", ErrSuiteDarwinCodeSignature)
	}
	return append(arguments, "--", object), nil
}

// suiteDarwinCodeObjects maps binary entries to the code objects codesign
// verifies: the outermost enclosing .app bundle (verified --deep, which
// covers nested frameworks, helpers and libraries) or the Mach-O itself.
func suiteDarwinCodeObjects(manifest SuiteReleaseManifest) []string {
	seen := map[string]struct{}{}
	objects := []string{}
	for _, entry := range manifest.Entries {
		if entry.Role != SuiteReleaseEntryBinary {
			continue
		}
		object := entry.Path
		segments := strings.Split(entry.Path, "/")
		for index, segment := range segments {
			if strings.HasSuffix(segment, ".app") {
				object = path.Join(segments[:index+1]...)
				break
			}
		}
		if _, ok := seen[object]; !ok {
			seen[object] = struct{}{}
			objects = append(objects, object)
		}
	}
	return objects
}

type suiteDarwinCodesignRunner func(ctx context.Context, arguments ...string) error

func runSuiteDarwinCodesign(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "/usr/bin/codesign", arguments...)
	var output suiteBoundedCommandBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil || ctx.Err() != nil || output.exceeded {
		return fmt.Errorf("%w: codesign rejected the code object", ErrSuiteDarwinCodeSignature)
	}
	return nil
}

func verifySuiteDarwinCodeSignatures(root string, manifest SuiteReleaseManifest, policy suiteDarwinSigningPolicy, run suiteDarwinCodesignRunner) error {
	if run == nil {
		return ErrSuiteDarwinCodeSignature
	}
	objects := suiteDarwinCodeObjects(manifest)
	if len(objects) == 0 {
		return fmt.Errorf("%w: release has no code objects", ErrSuiteDarwinCodeSignature)
	}
	for _, object := range objects {
		candidate, err := safeSuiteReleaseEntryPath(root, object)
		if err != nil {
			return ErrSuiteDarwinCodeSignature
		}
		arguments, err := policy.codesignArguments(candidate)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err = run(ctx, arguments...)
		cancel()
		if err != nil {
			return fmt.Errorf("%w: %s", ErrSuiteDarwinCodeSignature, object)
		}
	}
	return nil
}
