//go:build windows

package backend

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
)

const farmClientScheduledTaskName = "Ant Farm Client"

type farmClientWindowsAutostart struct {
	userID string
	run    func(string, ...string) ([]byte, error)
}

func newFarmClientAutostartManager() farmClientAutostartManager {
	current, _ := user.Current()
	userID := ""
	if current != nil {
		userID = current.Uid
		if userID == "" {
			userID = current.Username
		}
	}
	return &farmClientWindowsAutostart{userID: userID, run: func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}}
}

func farmClientTaskXML(userID, executablePath, configPath string) []byte {
	escape := func(value string) string {
		var output bytes.Buffer
		_ = xml.EscapeText(&output, []byte(value))
		return output.String()
	}
	return []byte(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Ant Farm Client per-user background agent</Description></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + escape(userID) + `</UserId></LogonTrigger></Triggers>
<Principals><Principal id="Author"><UserId>` + escape(userID) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
<Actions Context="Author"><Exec><Command>` + escape(executablePath) + `</Command><Arguments>` + escape("-config "+syscall.EscapeArg(configPath)) + `</Arguments></Exec></Actions>
</Task>`)
}

func (m *farmClientWindowsAutostart) Install(executablePath, configPath string) error {
	if strings.TrimSpace(m.userID) == "" {
		return fmt.Errorf("%w: current Windows user unavailable", ErrFarmClientAutostart)
	}
	temporary, err := os.CreateTemp("", "ant-farm-client-task-*.xml")
	if err != nil {
		return fmt.Errorf("%w: create scheduled task staging file", ErrFarmClientAutostart)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: secure scheduled task staging file", ErrFarmClientAutostart)
	}
	// Task Scheduler XML declares UTF-16. PowerShell is not involved, so no
	// script/parser can reinterpret executable or config paths.
	utf16Value := farmClientUTF16LEWithBOM(farmClientTaskXML(m.userID, executablePath, configPath))
	if _, err := temporary.Write(utf16Value); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write scheduled task staging file", ErrFarmClientAutostart)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close scheduled task staging file", ErrFarmClientAutostart)
	}
	_, err = m.run("schtasks.exe", "/Create", "/TN", farmClientScheduledTaskName,
		"/XML", filepath.Clean(temporaryPath), "/F")
	if err != nil {
		return fmt.Errorf("%w: create per-user scheduled task", ErrFarmClientAutostart)
	}
	return nil
}

func farmClientUTF16LEWithBOM(value []byte) []byte {
	text := []rune(string(value))
	result := make([]byte, 2, 2+len(text)*2)
	result[0], result[1] = 0xff, 0xfe
	for _, character := range text {
		if character <= 0xffff {
			result = append(result, byte(character), byte(character>>8))
			continue
		}
		character -= 0x10000
		high := uint16(0xd800 + (character >> 10))
		low := uint16(0xdc00 + (character & 0x3ff))
		result = append(result, byte(high), byte(high>>8), byte(low), byte(low>>8))
	}
	return result
}

func (m *farmClientWindowsAutostart) Remove() error {
	_, err := m.run("schtasks.exe", "/Delete", "/TN", farmClientScheduledTaskName, "/F")
	if err == nil {
		return nil
	}
	status, statusErr := m.Status()
	if statusErr == nil && !status.Installed {
		return nil
	}
	return fmt.Errorf("%w: remove per-user scheduled task", ErrFarmClientAutostart)
}

func (m *farmClientWindowsAutostart) Status() (FarmClientAutostartStatus, error) {
	output, err := m.run("schtasks.exe", "/Query", "/TN", farmClientScheduledTaskName, "/XML")
	if err != nil {
		return FarmClientAutostartStatus{Method: "scheduled-task-at-logon"}, nil
	}
	normalized := strings.ToLower(farmClientWindowsCommandText(output))
	if !strings.Contains(normalized, "<task") || !strings.Contains(normalized, "<settings") {
		return FarmClientAutostartStatus{}, fmt.Errorf("%w: invalid scheduled task XML", ErrFarmClientAutostart)
	}
	// Task Scheduler omits Enabled when its schema-default value is true.
	// An explicit false on either the task settings or its logon trigger is
	// therefore the only disabled representation returned by /Query /XML.
	active := !strings.Contains(normalized, "<enabled>false</enabled>")
	return FarmClientAutostartStatus{Installed: true, Active: active, Method: "scheduled-task-at-logon"}, nil
}

func farmClientWindowsCommandText(value []byte) string {
	if len(value) < 2 {
		return string(value)
	}
	var order binary.ByteOrder = binary.LittleEndian
	utf16Encoded := value[0] == 0xff && value[1] == 0xfe
	if value[0] == 0xfe && value[1] == 0xff {
		order = binary.BigEndian
		utf16Encoded = true
	}
	if !utf16Encoded {
		zeros := [2]int{}
		for index, item := range value {
			if item == 0 {
				zeros[index%2]++
			}
		}
		utf16Encoded = zeros[0] >= len(value)/4 || zeros[1] >= len(value)/4
		if zeros[0] > zeros[1] {
			order = binary.BigEndian
		}
	}
	if !utf16Encoded {
		return string(value)
	}
	if value[0] == 0xff && value[1] == 0xfe || value[0] == 0xfe && value[1] == 0xff {
		value = value[2:]
	}
	units := make([]uint16, len(value)/2)
	for index := range units {
		units[index] = order.Uint16(value[index*2 : index*2+2])
	}
	return string(utf16.Decode(units))
}
