//go:build noavx || purego || !amd64

package cpu

import (
	"fmt"
	"golang.org/x/sys/cpu"
)

const SupportAVX512 = false

func Print() {
	fmt.Println("LALALA")
	fmt.Println(cpu.X86.HasAVX512)
	fmt.Println(cpu.X86.HasAVX512DQ)
	fmt.Println(cpu.X86.HasAVX512VBMI2)
}
