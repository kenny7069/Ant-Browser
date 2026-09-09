//go:build windows

package backend

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestFarmClientAutostartWindowsDecodesScheduledTaskXML(t *testing.T) {
	want := `<?xml version="1.0"?><Task><Settings><Enabled>true</Enabled></Settings></Task>`
	units := utf16.Encode([]rune(want))
	encoded := []byte{0xff, 0xfe}
	for _, unit := range units {
		var pair [2]byte
		binary.LittleEndian.PutUint16(pair[:], unit)
		encoded = append(encoded, pair[:]...)
	}
	if got := farmClientWindowsCommandText(encoded); got != want {
		t.Fatalf("decoded scheduled task XML = %q, want %q", got, want)
	}
	withoutBOM := append([]byte(nil), encoded[2:]...)
	if got := farmClientWindowsCommandText(withoutBOM); got != want {
		t.Fatalf("decoded BOM-less scheduled task XML = %q, want %q", got, want)
	}
	bigEndian := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		var pair [2]byte
		binary.BigEndian.PutUint16(pair[:], unit)
		bigEndian = append(bigEndian, pair[:]...)
	}
	if got := farmClientWindowsCommandText(bigEndian); got != want {
		t.Fatalf("decoded big-endian scheduled task XML = %q, want %q", got, want)
	}
	if got := farmClientWindowsCommandText([]byte(want)); got != want {
		t.Fatalf("plain scheduled task XML = %q, want %q", got, want)
	}
}
