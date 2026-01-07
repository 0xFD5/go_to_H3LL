package core

import (
	"fmt"
	"syscall"
	"unsafe"
)

//
// Type definitions (function "pointer" signatures)
//

// NtOpenProcess
type NtOpenProcessFunc func(
	processHandle *uintptr,
	desiredAccess uint32,
	objectAttributes uintptr, // POBJECT_ATTRIBUTES
	clientId uintptr, // PCLIENT_ID
) int32 // NTSTATUS

// NtAllocateVirtualMemory
type NtAllocateVirtualMemoryFunc func(
	hProcess uintptr,
	baseAddress *uintptr,
	zeroBits uint32,
	regionSize *uintptr,
	allocationType uint32,
	protect uint32,
) int32 // NTSTATUS

// NtProtectVirtualMemory
type NtProtectVirtualMemoryFunc func(
	hProcess uintptr,
	baseAddress *uintptr,
	regionSize *uintptr,
	newProtect uint32,
	oldProtect *uint32,
) int32 // NTSTATUS

// NtWriteVirtualMemory
type NtWriteVirtualMemoryFunc func(
	hProcess uintptr,
	baseAddress uintptr,
	buffer uintptr,
	bufferSize uintptr,
	numberOfBytesWritten *uintptr,
) int32 // NTSTATUS

// NtCreateThreadEx
type NtCreateThreadExFunc func(
	threadHandle *uintptr,
	desiredAccess uint32,
	objectAttributes uintptr,
	hProcess uintptr,
	startAddress uintptr,
	parameter uintptr,
	createFlags uint32,
	zeroBits uintptr,
	stackSize uintptr,
	maximumStackSize uintptr,
	attributeList uintptr,
) int32 // NTSTATUS

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

// Demonstration: resolve addresses and print them (safe)
func NtOpenProcess(addr uintptr, processHandle *uintptr, desiredAccess uint32, objectAttributes uintptr, clientId uintptr) int32 {
	r, _, _ := syscall.SyscallN(
		addr,
		uintptr(unsafe.Pointer(processHandle)),
		uintptr(desiredAccess),
		objectAttributes,
		clientId,
	)
	return int32(r) // NTSTATUS
}

func NtAllocateVirtualMemory(addr uintptr, hProcess uintptr, baseAddress *uintptr, zeroBits uint32, regionSize *uintptr, allocationType uint32, protect uint32) int32 {
	r, _, _ := syscall.SyscallN(
		addr,
		hProcess,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(zeroBits),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType),
		uintptr(protect),
	)
	return int32(r) // NTSTATUS
}

func NtProtectVirtualMemory(addr uintptr, hProcess uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) int32 {
	r, _, _ := syscall.SyscallN(
		addr,
		hProcess,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)
	return int32(r) // NTSTATUS
}

func NtWriteVirtualMemory(addr uintptr, hProcess uintptr, baseAddress uintptr, buffer uintptr, bufferSize uintptr, numberOfBytesWritten *uintptr) int32 {
	r, _, _ := syscall.SyscallN(
		addr,
		hProcess,
		baseAddress,
		buffer,
		bufferSize,
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
	)
	return int32(r) // NTSTATUS
}

func NtCreateThreadEx(addr uintptr, threadHandle *uintptr, desiredAccess uint32, objectAttributes uintptr, hProcess uintptr, startAddress uintptr, parameter uintptr, createFlags uint32, zeroBits uintptr, stackSize uintptr, maximumStackSize uintptr, attributeList uintptr) int32 {
	r, _, _ := syscall.SyscallN(
		addr,
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess),
		objectAttributes,
		hProcess,
		startAddress,
		parameter,
		uintptr(createFlags),
		zeroBits,
		stackSize,
		maximumStackSize,
		attributeList,
	)
	return int32(r) // NTSTATUS
}

func NtWaitForSingleObject(
	addr uintptr,
	handle uintptr,
	alertable bool,
	timeout *int64, // LARGE_INTEGER, can be nil
) int32 {
	var alert uintptr
	if alertable {
		alert = 1
	} else {
		alert = 0
	}

	r, _, _ := syscall.SyscallN(
		addr,
		handle,
		alert,
		uintptr(unsafe.Pointer(timeout)),
	)
	return int32(r) // NTSTATUS
}

func CheckLoadNtFunctions(hNtdll uintptr) {

	// Assuming we have a handle to Ntdll(could be manually resolved, unhooked, whatever..)
	// Resolve NTAPI addresses
	ntOpenProcessAddr, err := GetProcAddressFromPEB(hNtdll, "NtOpenProcess")
	if err != nil {
		panic(err)
	}
	ntAllocateVirtualMemoryAddr, err := GetProcAddressFromPEB(hNtdll, "NtAllocateVirtualMemory")
	if err != nil {
		panic(err)
	}
	ntProtectVirtualMemoryAddr, err := GetProcAddressFromPEB(hNtdll, "NtProtectVirtualMemory")
	if err != nil {
		panic(err)
	}
	ntWriteVirtualMemoryAddr, err := GetProcAddressFromPEB(hNtdll, "NtWriteVirtualMemory")
	if err != nil {
		panic(err)
	}
	ntCreateThreadExAddr, err := GetProcAddressFromPEB(hNtdll, "NtCreateThreadEx")
	if err != nil {
		panic(err)
	}
	ntWaitForSingleObject, err := GetProcAddressFromPEB(hNtdll, "NtWaitForSingleObject")
	if err != nil {
		panic(err)
	}

	// Print resolved addresses (no execution in this demo)
	fmt.Printf("\n*-----------------------fetched NTAPI functions-----------------------*\n")
	fmt.Printf("ntdll:                 0x%X\n", hNtdll)
	fmt.Printf("NtOpenProcess:         0x%X\n", ntOpenProcessAddr)
	fmt.Printf("NtAllocateVirtualMemory:0x%X\n", ntAllocateVirtualMemoryAddr)
	fmt.Printf("NtProtectVirtualMemory: 0x%X\n", ntProtectVirtualMemoryAddr)
	fmt.Printf("NtWriteVirtualMemory:   0x%X\n", ntWriteVirtualMemoryAddr)
	fmt.Printf("NtCreateThreadEx:       0x%X\n", ntCreateThreadExAddr)
	fmt.Printf("NtWaitForSingleObject:       0x%X\n", ntWaitForSingleObject)
	fmt.Printf("*----------------/////////DO WHAT YOU WANT////////////-----------------*\n")

	// Example placeholder (safe, not performing remote operations):
	// var hProc uintptr
	// status := NtOpenProcess(ntOpenProcessAddr, &hProc, PROCESS_QUERY_INFORMATION, 0, uintptr(unsafe.Pointer(&clientId)))
	// fmt.Printf("NtOpenProcess status: 0x%X, handle: 0x%X\n", status, hProc)
}
