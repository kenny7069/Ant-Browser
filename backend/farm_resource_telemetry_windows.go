//go:build windows

package backend

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

type processMemoryCounters struct {
	Size                       uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// platformProcessTreeRSS returns the current working set of the root process
// and every descendant captured in one Toolhelp snapshot. The root must still
// exist and be queryable; descendants that exit after the snapshot are ignored.
func platformProcessTreeRSS(pid int) (int64, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	parents := make(map[uint32][]uint32)
	present := make(map[uint32]struct{})
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}
	for {
		present[entry.ProcessID] = struct{}{}
		parents[entry.ParentProcessID] = append(parents[entry.ParentProcessID], entry.ProcessID)
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return 0, err
		}
	}
	root := uint32(pid)
	if _, ok := present[root]; !ok {
		return 0, fmt.Errorf("process not found")
	}

	stack := []uint32{root}
	seen := make(map[uint32]struct{})
	var totalBytes uint64
	for len(stack) > 0 {
		last := len(stack) - 1
		processID := stack[last]
		stack = stack[:last]
		if _, ok := seen[processID]; ok {
			continue
		}
		seen[processID] = struct{}{}
		// Traverse the captured topology even if this intermediate process
		// exits before its working set is queried. Otherwise live grandchildren
		// disappear from the total merely because their parent raced with us.
		stack = append(stack, parents[processID]...)
		workingSet, queryErr := windowsProcessWorkingSet(processID)
		if queryErr != nil {
			if processID == root {
				return 0, queryErr
			}
			continue
		}
		totalBytes += uint64(workingSet)
	}
	return int64(totalBytes / (1024 * 1024)), nil
}

func windowsProcessWorkingSet(pid uint32) (uintptr, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	counters := processMemoryCounters{Size: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	result, _, callErr := getProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if result == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, callErr
		}
		return 0, fmt.Errorf("process memory query failed")
	}
	return counters.WorkingSetSize, nil
}
