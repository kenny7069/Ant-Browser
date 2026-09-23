package backend

import (
	"errors"
	"strings"
	"testing"
)

func suiteWindowsTaskFixture() suiteWindowsTaskContract {
	return suiteWindowsTaskContract{TaskName: `\AntBrowserSuite-Agent-0123456789abcdef`, UserSID: "S-1-5-21-1-2-3-1001", Command: `C:\Program Files\Ant Browser Suite\versions\1.2.3\ant-farm-client.exe`, ConfigPath: `C:\Users\farmer\AppData\Local\AntSuite\config\client.yaml`}
}

func TestSuiteWindowsTaskXMLClosedContract(t *testing.T) {
	contract := suiteWindowsTaskFixture()
	raw, err := buildSuiteWindowsTaskXML(contract)
	if err != nil || matchSuiteWindowsTaskXML(raw, contract) != nil {
		t.Fatalf("round trip err=%v match=%v", err, matchSuiteWindowsTaskXML(raw, contract))
	}
	value := string(raw)
	for _, required := range []string{"InteractiveToken", "LeastPrivilege", "<LogonTrigger>", "<Enabled>false</Enabled>", `-config &#34;C:\Users`, "ant-farm-client.exe"} {
		if !strings.Contains(value, required) {
			t.Fatalf("missing %q in %s", required, value)
		}
	}
	for _, forbidden := range []string{"WorkingDirectory", "Password", "SYSTEM", "<Exec><Exec>", "/F", "-farm-agent"} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("forbidden %q in XML", forbidden)
		}
	}
	contract.Enabled = true
	enabled, _ := buildSuiteWindowsTaskXML(contract)
	if !strings.Contains(string(enabled), "<Enabled>true</Enabled>") || matchSuiteWindowsTaskXML(enabled, contract) != nil {
		t.Fatal("enabled contract mismatch")
	}
}

func TestSuiteWindowsTaskXMLRejectsDriftUnknownDuplicateAndOversize(t *testing.T) {
	contract := suiteWindowsTaskFixture()
	raw, _ := buildSuiteWindowsTaskXML(contract)
	mutations := [][]byte{
		[]byte(strings.Replace(string(raw), "LeastPrivilege", "HighestAvailable", 1)),
		[]byte(strings.Replace(string(raw), "InteractiveToken", "Password", 1)),
		[]byte(strings.Replace(string(raw), "</Exec>", "<WorkingDirectory>C:\\</WorkingDirectory></Exec>", 1)),
		[]byte(strings.Replace(string(raw), "</Actions>", "<Exec><Command>C:\\evil.exe</Command></Exec></Actions>", 1)),
		[]byte(strings.Replace(string(raw), "</Triggers>", "<BootTrigger/></Triggers>", 1)),
		[]byte(strings.Replace(string(raw), "</Settings>", "<Enabled>false</Enabled></Settings>", 1)),
		[]byte(strings.Replace(string(raw), contract.UserSID, "S-1-5-18", 1)),
		[]byte(strings.Replace(string(raw), contract.ConfigPath, `C:\other\client.yaml`, 1)),
		append([]byte("<!--x-->"), raw...),
		append([]byte("<?xml garbage?>"), raw...),
		[]byte("<Task>"),
		make([]byte, maxSuiteWindowsTaskXMLBytes+1),
	}
	for index, mutation := range mutations {
		if err := matchSuiteWindowsTaskXML(mutation, contract); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("mutation %d accepted: %v", index, err)
		}
	}
}

func TestSuiteWindowsTaskXMLAcceptsOnlyKnownSchedulerDefaults(t *testing.T) {
	contract := suiteWindowsTaskFixture()
	raw, _ := buildSuiteWindowsTaskXML(contract)
	normalized := strings.Replace(string(raw), "</RegistrationInfo>", "<Author>"+contract.UserSID+"</Author><URI>"+contract.TaskName+"</URI></RegistrationInfo>", 1)
	normalized = strings.Replace(normalized, "</Settings>", "<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><Priority>7</Priority></Settings>", 1)
	if err := matchSuiteWindowsTaskXML([]byte(normalized), contract); err != nil {
		t.Fatalf("known scheduler defaults rejected: %v", err)
	}
	drift := strings.Replace(normalized, "<Priority>7</Priority>", "<Priority>4</Priority>", 1)
	if err := matchSuiteWindowsTaskXML([]byte(drift), contract); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("dangerous normalized drift accepted: %v", err)
	}
}

func TestSuiteWindowsTaskXMLDecodesBoundedUTF16Query(t *testing.T) {
	contract := suiteWindowsTaskFixture()
	raw, _ := buildSuiteWindowsTaskXML(contract)
	encoded := suiteWindowsTaskUTF16LE(append([]byte(`<?xml version="1.0" encoding="UTF-16"?>`), raw...))
	decoded, err := decodeSuiteWindowsTaskCommandXML(encoded)
	if err != nil || matchSuiteWindowsTaskXML(decoded, contract) != nil {
		t.Fatalf("UTF-16 query decode err=%v match=%v", err, matchSuiteWindowsTaskXML(decoded, contract))
	}
	if _, err := decodeSuiteWindowsTaskCommandXML(make([]byte, maxSuiteWindowsTaskCommandOutputBytes+1)); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("oversize output=%v", err)
	}
	buffer := &suiteBoundedCommandBuffer{}
	if _, err := buffer.Write(make([]byte, maxSuiteWindowsTaskCommandOutputBytes+1)); !errors.Is(err, ErrSuiteServiceActivation) || !buffer.exceeded {
		t.Fatalf("bounded buffer err=%v exceeded=%v", err, buffer.exceeded)
	}
}

func TestSuiteWindowsTaskQueryAbsentClassificationIsExact(t *testing.T) {
	commandErr := errors.New("exit")
	if !suiteWindowsTaskQueryIsAbsent(0x80070002, commandErr) {
		t.Fatal("file-not-found HRESULT not classified absent")
	}
	for _, code := range []uint32{0, 1, 0x80070005, 0x8004130d} {
		if suiteWindowsTaskQueryIsAbsent(code, commandErr) {
			t.Fatalf("code %#x classified absent", code)
		}
	}
	if suiteWindowsTaskQueryIsAbsent(0x80070002, nil) {
		t.Fatal("successful query classified absent")
	}
}

func TestSuiteWindowsTaskContractRejectsUnsafeWindowsPaths(t *testing.T) {
	for _, path := range []string{
		`C:\..\evil\ant-farm-client.exe`, `C:\safe\file:stream\ant-farm-client.exe`,
		`C:\safe\\ant-farm-client.exe`, `C:\safe.\ant-farm-client.exe`,
		`C:\CON\ant-farm-client.exe`, `C:\safe\LPT1.txt\ant-farm-client.exe`,
		`C:/safe/ant-farm-client.exe`, `\\server\share\ant-farm-client.exe`,
	} {
		contract := suiteWindowsTaskFixture()
		contract.Command = path
		if _, err := buildSuiteWindowsTaskXML(contract); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("unsafe path accepted: %q err=%v", path, err)
		}
	}
}
