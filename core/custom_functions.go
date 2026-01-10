package core

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

var errGetModuleHandleFromPEB = errors.New("errGetModuleHandleFromPEB error")

// parametrized with the module name
func GetModuleHandleFromPEB(module string) (uintptr, error) {
	pebAddr := GetPEB()
	peb := (*PEB)(unsafe.Pointer(pebAddr))

	head := &peb.Ldr.InLoadOrderModuleList
	curr := head.Flink

	for curr != head {
		entry := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(curr))

		// UNICODE_STRING: Length is in bytes; divide by 2 for UTF-16 code units
		n := int(entry.BaseDllName.Length) / 2
		if entry.BaseDllName.Buffer != nil && n > 0 {
			// Create a bounded slice exactly to Length/2
			buf := (*[1 << 20]uint16)(unsafe.Pointer(entry.BaseDllName.Buffer))[:n:n]
			name := syscall.UTF16ToString(buf)

			if strings.EqualFold(name, module) {
				return uintptr(entry.DllBase), nil // HMODULE-equivalent
			}
		}

		curr = curr.Flink
	}
	return 0, errGetModuleHandleFromPEB
}

/*--------------------------------CUSTOM GET PROC ADDRESS-----------------------------*/
var errorGetProcAddressFromPEB = errors.New("GetProcAddressFromPEB error")

func GetProcAddressFromPEB(hModule uintptr, funcName string) (uintptr, error) {
	dosHeader := (*ImageDosHeader)(unsafe.Pointer(hModule))
	ntHeaders := (*ImageNtHeaders64)(unsafe.Pointer(hModule + uintptr(dosHeader.ELfanew)))

	exportDirRVA := ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	exportDir := (*ImageExportDirectory)(unsafe.Pointer(hModule + uintptr(exportDirRVA)))

	names := (*[1 << 20]uint32)(unsafe.Pointer(hModule + uintptr(exportDir.AddressOfNames)))[:exportDir.NumberOfNames]
	ordinals := (*[1 << 20]uint16)(unsafe.Pointer(hModule + uintptr(exportDir.AddressOfNameOrdinals)))[:exportDir.NumberOfNames]
	funcs := (*[1 << 20]uint32)(unsafe.Pointer(hModule + uintptr(exportDir.AddressOfFunctions)))[:exportDir.NumberOfFunctions]

	for i, nameRVA := range names {
		name := ptrToString(hModule + uintptr(nameRVA))
		if strings.EqualFold(name, funcName) {
			ordinal := ordinals[i]
			funcRVA := funcs[ordinal]
			return hModule + uintptr(funcRVA), nil
		}
	}
	return 0, errorGetProcAddressFromPEB
}

// ptrToString reads a null-terminated ASCII string from memory at addr.
// Assumes addr points into the current process memory (like a loaded DLL).
func ptrToString(addr uintptr) string {
	if addr == 0 {
		return ""
	}
	// Treat addr as pointer to a byte slice
	p := (*byte)(unsafe.Pointer(addr))
	bytes := make([]byte, 0, 64) // start with small capacity

	for {
		b := *p
		if b == 0 {
			break
		}
		bytes = append(bytes, b)
		addr++
		p = (*byte)(unsafe.Pointer(addr))
	}
	return string(bytes)
}

func UnicodeStringToGoString(u UNICODE_STRING) string {
	if u.Buffer == nil || u.Length == 0 {
		return ""
	}
	return syscall.UTF16ToString(
		(*[1 << 16]uint16)(unsafe.Pointer(u.Buffer))[:u.Length/2],
	)
}

func InitObjectAttributes(objName *UNICODE_STRING, attributes uint32, rootDir uintptr) OBJECT_ATTRIBUTES {
	return OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
		RootDirectory: rootDir,
		ObjectName:    uintptr(unsafe.Pointer(objName)),
		Attributes:    attributes,
		// SecurityDescriptor and SecurityQualityOfService left nil
	}
}
