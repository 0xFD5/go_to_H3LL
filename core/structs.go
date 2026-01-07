package core

import "unsafe"

const IMAGE_DIRECTORY_ENTRY_EXPORT = 0

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

// IMAGE_DOS_HEADER (from winnt.h)
type ImageDosHeader struct {
	EMagic    uint16     // Magic number
	ECblp     uint16     // Bytes on last page of file
	ECp       uint16     // Pages in file
	ECrlc     uint16     // Relocations
	ECparhdr  uint16     // Size of header in paragraphs
	EMinalloc uint16     // Minimum extra paragraphs needed
	EMaxalloc uint16     // Maximum extra paragraphs needed
	ESS       uint16     // Initial (relative) SS value
	ESP       uint16     // Initial SP value
	Ecsum     uint16     // Checksum
	EIP       uint16     // Initial IP value
	ECs       uint16     // Initial (relative) CS value
	Elfarlc   uint16     // File address of relocation table
	Eovno     uint16     // Overlay number
	Eres      [4]uint16  // Reserved words
	EOemid    uint16     // OEM identifier (for e_oeminfo)
	EOeminfo  uint16     // OEM information; e_oemid specific
	Eres2     [10]uint16 // Reserved words
	ELfanew   int32      // File address of new exe header
}

// IMAGE_NT_HEADERS64 (from winnt.h)
type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type ImageNtHeaders64 struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader64
}

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

// IMAGE_EXPORT_DIRECTORY mirrors the Windows PE export directory structure.
// Field sizes and ordering must match WinNT.h definitions.
type ImageExportDirectory struct {
	Characteristics       uint32 // Reserved, usually zero
	TimeDateStamp         uint32 // Build timestamp
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32 // RVA of DLL name string
	Base                  uint32 // Starting ordinal number
	NumberOfFunctions     uint32 // Total number of function pointers
	NumberOfNames         uint32 // Number of named exports
	AddressOfFunctions    uint32 // RVA array of function RVAs
	AddressOfNames        uint32 // RVA array of name RVAs
	AddressOfNameOrdinals uint32 // RVA array of ordinals
}

// CLIENT_ID structure
type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// OBJECT_ATTRIBUTES structure (minimal version)
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}
