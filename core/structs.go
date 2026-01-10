//https://ntdoc.m417z.com/
//https://www.vergiliusproject.com/
//https://doxygen.reactos.org/

package core

import "unsafe"

const IMAGE_DIRECTORY_ENTRY_EXPORT = 0

//SYSTEM_INFORMATION_CLASS
const SystemProcessInformation = 5

// NTSTATUS helpers
const STATUS_INFO_LENGTH_MISMATCH int64 = -(0x3FFFFFF5)
const STATUS_SUCCESS = 0x00000000
const PROCESS_QUERY_INFORMATION = 0x0400
const PROCESS_VM_READ = 0x0010
const (
	ProcessBasicInformation       = 0
	ProcessWow64Information       = 26
	ProcessImageFileName          = 27
	ProcessCommandLineInformation = 60
)

// NTSTATUS is a 32-bit value
type NTSTATUS uint32

// PROCESS_BASIC_INFORMATION (x64, no reserved fields)
type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   NTSTATUS // process exit status
	PebBaseAddress               uintptr  // pointer to PEB
	AffinityMask                 uintptr  // KAFFINITY (mask of CPUs)
	BasePriority                 int32    // KPRIORITY
	UniqueProcessId              uintptr  // HANDLE (actually PID)
	InheritedFromUniqueProcessId uintptr  // HANDLE (parent PID)
}

/*----------------------------------------------------------------------------*/

type CURDIR struct {
	DosPath UNICODE_STRING
	Handle  uintptr
}

type RTL_DRIVE_LETTER_CURDIR struct {
	Flags     uint16
	Length    uint16
	TimeStamp int32
	DosPath   UNICODE_STRING
}

// RTL_USER_PROCESS_PARAMETERS (x64)
type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength                    uint32
	Length                           uint32
	Flags                            uint32
	DebugFlags                       uint32
	ConsoleHandle                    uintptr
	ConsoleFlags                     uint32
	StandardInput                    uintptr
	StandardOutput                   uintptr
	StandardError                    uintptr
	CurrentDirectory                 CURDIR
	DllPath                          UNICODE_STRING
	ImagePathName                    UNICODE_STRING
	CommandLine                      UNICODE_STRING
	Environment                      uintptr
	StartingX                        uint32
	StartingY                        uint32
	CountX                           uint32
	CountY                           uint32
	CountCharsX                      uint32
	CountCharsY                      uint32
	FillAttribute                    uint32
	WindowFlags                      uint32
	ShowWindowFlags                  uint32
	WindowTitle                      UNICODE_STRING
	DesktopInfo                      UNICODE_STRING
	ShellInfo                        UNICODE_STRING
	RuntimeData                      UNICODE_STRING
	CurrentDirectories               [32]RTL_DRIVE_LETTER_CURDIR // RTL_MAX_DRIVE_LETTERS = 32
	EnvironmentSize                  uintptr
	EnvironmentVersion               uintptr
	PackageDependencyData            uintptr
	ProcessGroupId                   uint32
	LoaderThreads                    uint32
	RedirectionDllName               UNICODE_STRING
	HeapPartitionName                UNICODE_STRING
	DefaultThreadpoolCpuSetMasks     *uint64
	DefaultThreadpoolCpuSetMaskCount uint32
	DefaultThreadpoolThreadMaximum   uint32
	HeapMemoryTypeMask               uint32
}

/*---------------------------------------------------------------------------*/

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

// BOOLEAN in Windows is a byte
type BOOLEAN byte

// PEB (partial, enough for ProcessParameters walking), ADD MORE IF YOU SEE FIT
type PEB struct {
	InheritedAddressSpace    BOOLEAN
	ReadImageFileExecOptions BOOLEAN
	BeingDebugged            BOOLEAN
	BitField                 BOOLEAN
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      *PEB_LDR_DATA
	ProcessParameters        uintptr // -> RTL_USER_PROCESS_PARAMETERS
	SubSystemData            uintptr
	ProcessHeap              uintptr
	FastPebLock              uintptr
	AtlThunkSListPtr         uintptr
	IFEOKey                  uintptr
	CrossProcessFlags        uint32
	KernelCallbackTable      uintptr
	SystemReserved           uint32
	AtlThunkSListPtr32       uint32
	ApiSetMap                uintptr
	TlsExpansionCounter      uint32
	TlsBitmap                uintptr
	TlsBitmapBits            [2]uint32
	ReadOnlySharedMemoryBase uintptr
	SharedData               uintptr
	ReadOnlyStaticServerData *uintptr
	AnsiCodePageData         uintptr
	OemCodePageData          uintptr
	UnicodeCaseTableData     uintptr
	NumberOfProcessors       uint32
	NtGlobalFlag             uint32
	// ... (omit rest unless you need them)
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

type LARGE_INTEGER struct {
	QuadPart int64
}

// SYSTEM_PROCESS_INFORMATION
type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        uint64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   LARGE_INTEGER
	UserTime                     LARGE_INTEGER
	KernelTime                   LARGE_INTEGER
	ImageName                    UNICODE_STRING
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
	HandleCount                  uint32
	SessionId                    uint32
	UniqueProcessKey             uintptr
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           LARGE_INTEGER
	WriteOperationCount          LARGE_INTEGER
	OtherOperationCount          LARGE_INTEGER
	ReadTransferCount            LARGE_INTEGER
	WriteTransferCount           LARGE_INTEGER
	OtherTransferCount           LARGE_INTEGER
	// Threads array follows in memory
}

// SYSTEM_THREAD_INFORMATION
type SYSTEM_THREAD_INFORMATION struct {
	KernelTime      LARGE_INTEGER
	UserTime        LARGE_INTEGER
	CreateTime      LARGE_INTEGER
	WaitTime        uint32
	StartAddress    uintptr
	ClientId        CLIENT_ID
	Priority        int32
	BasePriority    int32
	ContextSwitches uint32
	ThreadState     uint32
	WaitReason      uint32
}
