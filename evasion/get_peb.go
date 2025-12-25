package evasion

import (
	"syscall"
	"unsafe"
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

// Simplified LDR_DATA_TABLE_ENTRY to get the BaseAddress and Name
type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    unsafe.Pointer
	EntryPoint                 unsafe.Pointer
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint8
	SsHandle                        unsafe.Pointer
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

// Minimal PEB structure
type PEB struct {
	InheritedAddressSpace    uint8
	ReadImageFileExecOptions uint8
	BeingDebugged            uint8
	BitField                 uint8
	Mutant                   unsafe.Pointer
	ImageBaseAddress         unsafe.Pointer
	Ldr                      *PEB_LDR_DATA
}

func GetPEB() uintptr // Declared without body

func getNtdllBaseFromPEB() uintptr {
	pebAddr := GetPEB()
	peb := (*PEB)(unsafe.Pointer(pebAddr))

	head := &peb.Ldr.InLoadOrderModuleList
	curr := head.Flink

	for curr != head {
		// Calculate the start of the LDR_DATA_TABLE_ENTRY structure
		// InLoadOrderLinks is at offset 0, so curr is the pointer to the entry.
		entry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(curr))

		// Convert the UTF16 buffer to a Go string
		dllName := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(entry.BaseDllName.Buffer))[:])

		if dllName == "ntdll.dll" {
			return uintptr(entry.DllBase)
		}

		curr = curr.Flink
	}
	return 0
}
