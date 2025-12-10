package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.MustLoadDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32.MustFindProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.MustFindProc("Process32FirstW")
	procProcess32Next            = kernel32.MustFindProc("Process32NextW")
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
)

type PROCESSENTRY32 struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

// gives all processes if provided an empty string
// or the PID if provided a processName
func processEnumeration(strProcessName string) uint32 {
	// Take a snapshot of all processes
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot < 0 {
		fmt.Println("Error: unable to create snapshot")
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry PROCESSENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	if len(strProcessName) == 0 {
		// get first proc
		ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			fmt.Println("Error: unable to get first process")
			return 0
		}

		for {

			exe := syscall.UTF16ToString(entry.SzExeFile[:])
			fmt.Printf("PID: %d\tName: %s\n", entry.Th32ProcessID, exe)

			ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
			if ret == 0 {
				break
			}
		}
		return 0
	} else {
		//get first proc
		ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			fmt.Println("Error: unable to get first process")
			return 0
		}
		for {

			exe := syscall.UTF16ToString(entry.SzExeFile[:])

			if exe == strProcessName {
				return entry.Th32ProcessID
				//exit
			}

			//fmt.Printf("PID: %d\tName: %s\n", entry.Th32ProcessID, exe)
			// keep looking
			ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
			if ret == 0 {
				break
			}
		}
		return 0
	}
}
