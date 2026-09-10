package backend

import (
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	browserStderrTailMaxLines = 40
	browserStderrTailMaxBytes = 4 * 1024
)

type browserProcessExitResult struct {
	Err        error
	StderrTail string
}

type browserProcessMonitor struct {
	cmd        *exec.Cmd
	stderrTail *tailTextBuffer
	stderr     *browserProcessStderrWriter
	waitDone   chan struct{}

	mu        sync.Mutex
	result    browserProcessExitResult
	debugPort int
}

func newBrowserProcessMonitor(cmd *exec.Cmd) (*browserProcessMonitor, error) {
	if cmd == nil {
		return nil, fmt.Errorf("browser command is nil")
	}
	if cmd.Stderr != nil {
		return nil, fmt.Errorf("browser command stderr is already configured")
	}
	monitor := &browserProcessMonitor{
		cmd:        cmd,
		stderrTail: newTailTextBuffer(browserStderrTailMaxLines, browserStderrTailMaxBytes),
		waitDone:   make(chan struct{}),
	}
	monitor.stderr = &browserProcessStderrWriter{monitor: monitor}
	cmd.Stderr = monitor.stderr
	return monitor, nil
}

func newDetachedBrowserProcessMonitor() *browserProcessMonitor {
	waitDone := make(chan struct{})
	close(waitDone)
	return &browserProcessMonitor{waitDone: waitDone}
}

func (m *browserProcessMonitor) Start() {
	go m.waitForExit()
}

func (m *browserProcessMonitor) Done() <-chan struct{} {
	return m.waitDone
}

func (m *browserProcessMonitor) HasExited() bool {
	select {
	case <-m.waitDone:
		return true
	default:
		return false
	}
}

func (m *browserProcessMonitor) Result() browserProcessExitResult {
	<-m.waitDone

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.result
}

func (m *browserProcessMonitor) Wait() error {
	return m.Result().Err
}

func (m *browserProcessMonitor) DebugPort() (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.debugPort <= 0 {
		return 0, false
	}
	return m.debugPort, true
}

func (m *browserProcessMonitor) SetDebugPort(port int) {
	if port <= 0 {
		return
	}

	m.mu.Lock()
	if m.debugPort <= 0 {
		m.debugPort = port
	}
	m.mu.Unlock()
}

func (m *browserProcessMonitor) waitForExit() {
	err := m.cmd.Wait()
	m.stderr.Flush()

	m.mu.Lock()
	m.result = browserProcessExitResult{
		Err:        err,
		StderrTail: m.stderrTail.String(),
	}
	m.mu.Unlock()
	close(m.waitDone)
}

// browserProcessStderrWriter lets os/exec own the pipe and its copy goroutine.
// Cmd.Wait therefore cannot publish an exit result until every stderr byte has
// reached this writer, including output from a process that exits immediately.
type browserProcessStderrWriter struct {
	monitor *browserProcessMonitor
	mu      sync.Mutex
	pending string
}

func (w *browserProcessStderrWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	w.pending += string(value)
	lines := make([]string, 0, strings.Count(w.pending, "\n"))
	for {
		index := strings.IndexByte(w.pending, '\n')
		if index < 0 {
			break
		}
		lines = append(lines, w.pending[:index])
		w.pending = w.pending[index+1:]
	}
	if len(w.pending) > 1024*1024 {
		w.pending = w.pending[len(w.pending)-1024*1024:]
	}
	w.mu.Unlock()
	for _, line := range lines {
		w.publish(line)
	}
	return len(value), nil
}

func (w *browserProcessStderrWriter) Flush() {
	w.mu.Lock()
	line := w.pending
	w.pending = ""
	w.mu.Unlock()
	if line != "" {
		w.publish(line)
	}
}

func (w *browserProcessStderrWriter) publish(line string) {
	if w == nil || w.monitor == nil {
		return
	}
	w.monitor.stderrTail.Append(line)
	if port, ok := parseBrowserDebugPortFromStderrLine(line); ok {
		w.monitor.SetDebugPort(port)
	}
}

type tailTextBuffer struct {
	maxLines int
	maxBytes int

	mu         sync.Mutex
	lines      []string
	totalBytes int
}

func newTailTextBuffer(maxLines int, maxBytes int) *tailTextBuffer {
	if maxLines <= 0 {
		maxLines = 1
	}
	if maxBytes <= 0 {
		maxBytes = 1024
	}

	return &tailTextBuffer{
		maxLines: maxLines,
		maxBytes: maxBytes,
	}
}

func (b *tailTextBuffer) Append(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	if len(trimmed) > b.maxBytes {
		trimmed = trimmed[len(trimmed)-b.maxBytes:]
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.lines = append(b.lines, trimmed)
	b.totalBytes += len(trimmed) + 1
	for len(b.lines) > b.maxLines || b.totalBytes > b.maxBytes {
		if len(b.lines) == 0 {
			b.totalBytes = 0
			break
		}
		b.totalBytes -= len(b.lines[0]) + 1
		b.lines = b.lines[1:]
	}
}

func (b *tailTextBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.lines, "\n")
}

func parseBrowserDebugPortFromStderrLine(line string) (int, bool) {
	const marker = "DevTools listening on "

	idx := strings.Index(line, marker)
	if idx < 0 {
		return 0, false
	}

	rawURL := strings.TrimSpace(line[idx+len(marker):])
	if rawURL == "" {
		return 0, false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0, false
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 {
		return 0, false
	}
	return port, true
}
