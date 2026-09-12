package backend

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

const maxSuiteWindowsTaskXMLBytes = 64 << 10
const maxSuiteWindowsTaskCommandOutputBytes = 128 << 10

const (
	suiteWindowsTaskQueryOK       uint32 = 0
	suiteWindowsTaskQueryNotFound uint32 = 0x80070002
)

type suiteWindowsTaskContract struct {
	TaskName   string
	UserSID    string
	Command    string
	ConfigPath string
	Enabled    bool
}

var suiteWindowsSIDPattern = regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+)+$`)
var suiteWindowsTaskNamePattern = regexp.MustCompile(`^\\AntBrowserSuite-Agent-[0-9a-f]{16}$`)
var suiteWindowsReservedSegment = regexp.MustCompile(`(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$`)
var suiteWindowsUTF16Declaration = regexp.MustCompile(`(?i)encoding\s*=\s*(?:"utf-16"|'utf-16')`)
var suiteWindowsXMLDeclaration = regexp.MustCompile(`(?i)^\s*version\s*=\s*(?:"1\.0"|'1\.0')(?:\s+encoding\s*=\s*(?:"UTF-8"|'UTF-8'))?(?:\s+standalone\s*=\s*(?:"(?:yes|no)"|'(?:yes|no)'))?\s*$`)

func (c suiteWindowsTaskContract) validate() error {
	if !suiteWindowsTaskNamePattern.MatchString(c.TaskName) || !suiteWindowsSIDPattern.MatchString(c.UserSID) {
		return ErrSuiteServiceActivation
	}
	for _, value := range []string{c.Command, c.ConfigPath} {
		if !suiteWindowsAbsolutePath(value) || strings.ContainsAny(value, "\"\x00\r\n") {
			return ErrSuiteServiceActivation
		}
	}
	if !strings.EqualFold(windowsPathBase(c.Command), "ant-farm-client.exe") || !strings.EqualFold(windowsPathBase(c.ConfigPath), SuiteClientConfigName) {
		return ErrSuiteServiceActivation
	}
	return nil
}

func suiteWindowsAbsolutePath(value string) bool {
	if len(value) < 4 || len(value) > 1024 || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) || value[1] != ':' || value[2] != '\\' {
		return false
	}
	for _, segment := range strings.Split(value[3:], `\`) {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || suiteWindowsReservedSegment.MatchString(segment) {
			return false
		}
		for _, character := range segment {
			if character < 0x20 || strings.ContainsRune(`<>:"/|?*`, character) {
				return false
			}
		}
	}
	return true
}

func windowsPathBase(value string) string {
	if index := strings.LastIndexByte(value, '\\'); index >= 0 {
		return value[index+1:]
	}
	return value
}

func buildSuiteWindowsTaskXML(contract suiteWindowsTaskContract) ([]byte, error) {
	if err := contract.validate(); err != nil {
		return nil, err
	}
	escape := func(value string) string {
		var output bytes.Buffer
		_ = xml.EscapeText(&output, []byte(value))
		return output.String()
	}
	enabled := "false"
	if contract.Enabled {
		enabled = "true"
	}
	arguments := `-config "` + contract.ConfigPath + `"`
	value := `<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
		`<RegistrationInfo><Description>Ant Browser Suite per-user Agent</Description></RegistrationInfo>` +
		`<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + escape(contract.UserSID) + `</UserId></LogonTrigger></Triggers>` +
		`<Principals><Principal id="Author"><UserId>` + escape(contract.UserSID) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>` +
		`<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>` + enabled + `</Enabled></Settings>` +
		`<Actions Context="Author"><Exec><Command>` + escape(contract.Command) + `</Command><Arguments>` + escape(arguments) + `</Arguments></Exec></Actions>` +
		`</Task>`
	return []byte(value), nil
}

type suiteXMLAttribute struct{ Space, Local, Value string }
type suiteXMLNode struct {
	Space, Local string
	Attributes   []suiteXMLAttribute
	Text         string
	Children     []*suiteXMLNode
}

func parseClosedSuiteWindowsTaskXML(raw []byte) (*suiteXMLNode, error) {
	if len(raw) == 0 || len(raw) > maxSuiteWindowsTaskXMLBytes || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrSuiteServiceActivation
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var root *suiteXMLNode
	stack := []*suiteXMLNode{}
	sawDeclaration := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrSuiteServiceActivation
		}
		switch current := token.(type) {
		case xml.StartElement:
			node := &suiteXMLNode{Space: current.Name.Space, Local: current.Name.Local}
			for _, attr := range current.Attr {
				if attr.Name.Space == "xmlns" {
					return nil, ErrSuiteServiceActivation
				}
				if attr.Name.Space == "" && attr.Name.Local == "xmlns" {
					continue
				}
				node.Attributes = append(node.Attributes, suiteXMLAttribute{attr.Name.Space, attr.Name.Local, attr.Value})
			}
			sort.Slice(node.Attributes, func(i, j int) bool { return fmt.Sprint(node.Attributes[i]) < fmt.Sprint(node.Attributes[j]) })
			if len(stack) == 0 {
				if root != nil {
					return nil, ErrSuiteServiceActivation
				}
				root = node
			} else {
				stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].Local != current.Name.Local || stack[len(stack)-1].Space != current.Name.Space {
				return nil, ErrSuiteServiceActivation
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(current)) != "" {
					return nil, ErrSuiteServiceActivation
				}
				continue
			}
			text := string(current)
			if strings.TrimSpace(text) != "" {
				stack[len(stack)-1].Text += text
			}
		case xml.ProcInst:
			if current.Target != "xml" || sawDeclaration || root != nil || !suiteWindowsXMLDeclaration.Match(current.Inst) {
				return nil, ErrSuiteServiceActivation
			}
			sawDeclaration = true
		case xml.Comment, xml.Directive:
			return nil, ErrSuiteServiceActivation
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, ErrSuiteServiceActivation
	}
	return root, nil
}

func matchSuiteWindowsTaskXML(raw []byte, contract suiteWindowsTaskContract) error {
	expectedRaw, err := buildSuiteWindowsTaskXML(contract)
	if err != nil {
		return err
	}
	actual, err := parseClosedSuiteWindowsTaskXML(raw)
	if err != nil {
		return err
	}
	expected, err := parseClosedSuiteWindowsTaskXML(expectedRaw)
	if err != nil || normalizeSuiteSchedulerDefaults(actual, contract) != nil || !reflect.DeepEqual(actual, expected) {
		return ErrSuiteServiceActivation
	}
	return nil
}

func normalizeSuiteSchedulerDefaults(root *suiteXMLNode, contract suiteWindowsTaskContract) error {
	if root == nil || root.Local != "Task" {
		return ErrSuiteServiceActivation
	}
	registration := directSuiteXMLChild(root, "RegistrationInfo")
	settings := directSuiteXMLChild(root, "Settings")
	if registration == nil || settings == nil {
		return ErrSuiteServiceActivation
	}
	if err := removeOptionalSuiteXMLLeaf(registration, "Author", contract.UserSID); err != nil {
		return err
	}
	if err := removeOptionalSuiteXMLLeaf(registration, "URI", contract.TaskName); err != nil {
		return err
	}
	defaults := map[string]string{
		"AllowHardTerminate":        "true",
		"AllowStartOnDemand":        "true",
		"Hidden":                    "false",
		"Priority":                  "7",
		"RunOnlyIfIdle":             "false",
		"RunOnlyIfNetworkAvailable": "false",
		"StartWhenAvailable":        "false",
		"WakeToRun":                 "false",
	}
	for name, value := range defaults {
		if err := removeOptionalSuiteXMLLeaf(settings, name, value); err != nil {
			return err
		}
	}
	for index, child := range settings.Children {
		if child.Local != "IdleSettings" {
			continue
		}
		if len(child.Attributes) != 0 || child.Text != "" || len(child.Children) != 2 ||
			child.Children[0].Local != "StopOnIdleEnd" || child.Children[0].Text != "true" || len(child.Children[0].Children) != 0 ||
			child.Children[1].Local != "RestartOnIdle" || child.Children[1].Text != "false" || len(child.Children[1].Children) != 0 {
			return ErrSuiteServiceActivation
		}
		settings.Children = append(settings.Children[:index], settings.Children[index+1:]...)
		break
	}
	return nil
}

func directSuiteXMLChild(parent *suiteXMLNode, local string) *suiteXMLNode {
	var result *suiteXMLNode
	for _, child := range parent.Children {
		if child.Local == local {
			if result != nil {
				return nil
			}
			result = child
		}
	}
	return result
}

func removeOptionalSuiteXMLLeaf(parent *suiteXMLNode, local, value string) error {
	match := -1
	for index, child := range parent.Children {
		if child.Local != local {
			continue
		}
		if match >= 0 || child.Text != value || len(child.Attributes) != 0 || len(child.Children) != 0 {
			return ErrSuiteServiceActivation
		}
		match = index
	}
	if match >= 0 {
		parent.Children = append(parent.Children[:match], parent.Children[match+1:]...)
	}
	return nil
}

func suiteWindowsTaskQueryIsAbsent(exitCode uint32, commandErr error) bool {
	return commandErr != nil && exitCode == suiteWindowsTaskQueryNotFound
}

func suiteWindowsTaskUTF16LE(raw []byte) []byte {
	units := utf16.Encode([]rune(string(raw)))
	result := []byte{0xff, 0xfe}
	for _, unit := range units {
		result = append(result, byte(unit), byte(unit>>8))
	}
	return result
}

func decodeSuiteWindowsTaskCommandXML(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxSuiteWindowsTaskCommandOutputBytes {
		return nil, ErrSuiteServiceActivation
	}
	if len(raw) >= 2 && ((raw[0] == 0xff && raw[1] == 0xfe) || (raw[0] == 0xfe && raw[1] == 0xff)) {
		var order binary.ByteOrder = binary.LittleEndian
		if raw[0] == 0xfe {
			order = binary.BigEndian
		}
		raw = raw[2:]
		if len(raw)%2 != 0 {
			return nil, ErrSuiteServiceActivation
		}
		units := make([]uint16, len(raw)/2)
		for index := range units {
			units[index] = order.Uint16(raw[index*2 : index*2+2])
		}
		raw = []byte(string(utf16.Decode(units)))
	}
	value := suiteWindowsUTF16Declaration.ReplaceAllString(string(raw), `encoding="UTF-8"`)
	if len(value) > maxSuiteWindowsTaskXMLBytes {
		return nil, ErrSuiteServiceActivation
	}
	return []byte(value), nil
}

type suiteBoundedCommandBuffer struct {
	value    bytes.Buffer
	exceeded bool
}

func (b *suiteBoundedCommandBuffer) Write(value []byte) (int, error) {
	if b.exceeded || b.value.Len()+len(value) > maxSuiteWindowsTaskCommandOutputBytes {
		b.exceeded = true
		return 0, ErrSuiteServiceActivation
	}
	return b.value.Write(value)
}

func (b *suiteBoundedCommandBuffer) Bytes() []byte { return append([]byte(nil), b.value.Bytes()...) }
