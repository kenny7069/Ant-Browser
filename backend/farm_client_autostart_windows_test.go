//go:build windows

package backend

import (
	"encoding/binary"
	"errors"
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

func TestFarmClientAutostartWindowsUsesTaskSchedulerEnabledDefault(t *testing.T) {
	for _, test := range []struct {
		name   string
		xml    string
		active bool
	}{
		{name: "omitted means enabled", xml: `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings></Settings></Task>`, active: true},
		{name: "explicit task disable", xml: `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings><Enabled>false</Enabled></Settings></Task>`, active: false},
		{name: "explicit trigger disable", xml: `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings></Settings><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers></Task>`, active: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &farmClientWindowsAutostart{run: func(string, ...string) ([]byte, error) { return []byte(test.xml), nil }}
			status, err := manager.Status()
			if err != nil || !status.Installed || status.Active != test.active {
				t.Fatalf("status=%+v err=%v", status, err)
			}
		})
	}
	manager := &farmClientWindowsAutostart{run: func(string, ...string) ([]byte, error) { return []byte("not xml"), nil }}
	if _, err := manager.Status(); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("invalid XML error=%v", err)
	}
}
