package execution

import (
	"fmt"
	"go_to_h3ll/core"
	"strings"
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

// gives all processes if provided an empty string
// or the PID if provided a processName
func ProcessEnumeration(strProcessName string) uint32 {
	// Take a snapshot of all processes
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot < 0 {
		fmt.Println("Error: unable to create snapshot")
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry core.PROCESSENTRY32
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

			//case insensitive comparison
			if strings.EqualFold(exe, strProcessName) {
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

// works for services and system processes only, because of kernel limitation, SYSTEM_PROCESS_INFORMATION.ImageName is populated from the kernel’s internal structures. For many user processes, especially modern desktop apps, this field is blank.
func ProcessEnumerationNt(strProcessName string, hNtdll uintptr) uintptr {

	ntQuerySystemInformationAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtQuerySystemInformation")
	if err != nil {
		panic(err)
	}
	var length uint32 = 0x10000
	buffer := make([]byte, length)

	status := core.NtQuerySystemInformation(
		ntQuerySystemInformationAddr,
		core.SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		length,
		&length,
	)

	// Resize buffer if too small
	for int64(status) == core.STATUS_INFO_LENGTH_MISMATCH {
		buffer = make([]byte, length)
		status = core.NtQuerySystemInformation(ntQuerySystemInformationAddr,
			core.SystemProcessInformation,
			unsafe.Pointer(&buffer[0]),
			length,
			&length,
		)
	}

	if status != core.STATUS_SUCCESS {
		fmt.Printf("NtQuerySystemInformation failed: 0x%X\n", status)
	}

	var offset int = 0
	//if served empty string , enumerate all processes and return 0
	if strProcessName == "" {
		for {
			proc := (*core.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
			name := ""
			if proc.ImageName.Buffer != nil {
				name = core.UnicodeStringToGoString(proc.ImageName)
			}

			fmt.Printf("PID: %d | Name: %s | Threads: %d\n",
				proc.UniqueProcessId, name, proc.NumberOfThreads)

			if proc.NextEntryOffset == 0 {
				break
			}
			offset += int(proc.NextEntryOffset)
		}
		return 0
		//else return pid
	} else {
		for {
			spi := (*core.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
			pid := spi.UniqueProcessId
			var name string
			if spi.ImageName.Buffer != nil {
				name = core.UnicodeStringToGoString(spi.ImageName)
			}
			if name == strProcessName {
				return pid
			}
			if spi.NextEntryOffset == 0 {
				break
			}
			offset += int(spi.NextEntryOffset)
		}
	}
	//else not found
	return 0
}

// this doesn't work yet, the goal is to enumerate gui apps using the kernel modules stealthily
func ProcessEnumerationNtEnhanced(strProcessName string, hNtdll uintptr) uintptr {

	ntQuerySystemInformationAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtQuerySystemInformation")
	if err != nil {
		panic(err)
	}

	ntQueryInformationProcessAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtQueryInformationProcess")
	if err != nil {
		panic(err)
	}

	ntOpenProcessAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtOpenProcess")
	if err != nil {
		panic(err)
	}

	ntReadVirtualMemoryAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtReadVirtualMemory")
	if err != nil {
		panic(err)
	}

	var length uint32 = 0x10000
	buffer := make([]byte, length)

	status := core.NtQuerySystemInformation(
		ntQuerySystemInformationAddr,
		core.SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		length,
		&length,
	)

	// Resize buffer if too small
	for status != core.STATUS_SUCCESS {
		fmt.Printf("FAILED, TRYING TO RECOVER......\n")

		buffer = make([]byte, length)
		status = core.NtQuerySystemInformation(ntQuerySystemInformationAddr,
			core.SystemProcessInformation,
			unsafe.Pointer(&buffer[0]),
			length,
			&length,
		)
	}

	if status != core.STATUS_SUCCESS {
		fmt.Printf("NtQuerySystemInformation failed: 0x%X\n", status)

	}

	var offset int = 0
	var hProcess uintptr = 0
	objAttr := core.InitObjectAttributes(nil, 0x40, 0)
	clientId := core.CLIENT_ID{UniqueProcess: 0, UniqueThread: 0}
	var pbi core.PROCESS_BASIC_INFORMATION
	var retLen uint32
	var peb core.PEB
	var read uintptr

	for {
		proc := (*core.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))

		//Open Process
		clientId.UniqueProcess = proc.UniqueProcessId
		if clientId.UniqueProcess == 0 {
			offset += int(proc.NextEntryOffset)
			continue
		}
		fmt.Println("PID : ", proc.UniqueProcessId)
		status := core.NtOpenProcess(
			ntOpenProcessAddr,
			&hProcess,
			core.PROCESS_QUERY_INFORMATION|core.PROCESS_VM_READ,
			uintptr(unsafe.Pointer(&objAttr)), // OBJECT_ATTRIBUTES (default)
			uintptr(unsafe.Pointer(&clientId)),
		)
		if uint32(status) == uint32(0xC0000022) {
			fmt.Printf("NtOpenProcess access denied: 0x%X\n", status)
			offset += int(proc.NextEntryOffset)
			continue
		}
		if status != core.STATUS_SUCCESS {
			fmt.Printf("NtOpenProcess failed: 0x%X\n", status)
			break
		}

		//Query basic info

		status = core.NtQueryInformationProcess(
			ntQueryInformationProcessAddr,
			hProcess,
			core.ProcessBasicInformation,
			unsafe.Pointer(&pbi),
			uint32(unsafe.Sizeof(pbi)),
			&retLen,
		)
		if status != core.STATUS_SUCCESS {
			fmt.Printf("NtQueryInformationProcess failed: 0x%X\n", status)
			break
		}

		//read PEB
		status = core.NtReadVirtualMemory(
			ntReadVirtualMemoryAddr,
			hProcess,
			pbi.PebBaseAddress, // from NtQueryInformationProcess
			unsafe.Pointer(&peb),
			unsafe.Sizeof(peb),
			&read,
		)
		if status != core.STATUS_SUCCESS {
			fmt.Printf("NtReadVirtualMemory failed: 0x%X\n", status)
			break
		}

		//read RTL_USER_PROCESS_PARAMETERS to extract ImagePathName
		var params core.RTL_USER_PROCESS_PARAMETERS
		status = core.NtReadVirtualMemory(
			ntReadVirtualMemoryAddr,
			hProcess,
			peb.ProcessParameters,
			unsafe.Pointer(&params),
			unsafe.Sizeof(params),
			&read)
		if status != core.STATUS_SUCCESS {
			fmt.Printf("NtReadVirtualMemory 2nd call failed: 0x%X\n", status)
		}

		//read buffer and convert it to go string so it gives you a full exec path
		buf := make([]uint16, params.ImagePathName.Length/2)
		status = core.NtReadVirtualMemory(
			ntReadVirtualMemoryAddr,
			hProcess,
			uintptr(unsafe.Pointer(params.ImagePathName.Buffer)),
			unsafe.Pointer(&buf[0]),
			uintptr(params.ImagePathName.Length),
			&read,
		)

		if status != core.STATUS_SUCCESS {
			fmt.Printf("NtReadVirtualMemory 3rd call failed: 0x%X\n", status)
			break
		}
		fmt.Println(core.UnicodeStringToGoString(params.ImagePathName))

		//extract process name from there maybe ?

		if proc.NextEntryOffset == 0 {
			break
		}
		offset += int(proc.NextEntryOffset)
	}
	return 0

}
