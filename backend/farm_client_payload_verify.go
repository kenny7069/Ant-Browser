package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// farmClientPinnedPayload keeps the verified filesystem object (and, on
// Windows, its parent objects) open until process creation has fixed the image.
// Linux starts through ExtraFiles and /proc/self/fd/3; Darwin retains the
// handles through its final identity check and pathname spawn.
type farmClientPinnedPayload struct {
	path       string
	extraFiles []*os.File
	close      func()
}

func (payload *farmClientPinnedPayload) Close() {
	if payload != nil && payload.close != nil {
		payload.close()
		payload.close = nil
	}
}

func verifyFarmClientPinnedFile(file *os.File, expectedHash string, expectedSize int64) error {
	if file == nil {
		return ErrFarmClientUpdateIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrFarmClientUpdateIntegrity
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, farmClientUpdateArtifactLimit+1))
	if err != nil || written != expectedSize || written > farmClientUpdateArtifactLimit || hex.EncodeToString(hasher.Sum(nil)) != expectedHash {
		return ErrFarmClientUpdateIntegrity
	}
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return ErrFarmClientUpdateIntegrity
	}
	return nil
}
