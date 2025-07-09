//go:build !noavx && !purego

package cpu

import (
	"fmt"
	"golang.org/x/sys/cpu"
)

var (
	SupportAVX512 = SupportADX && cpu.X86.HasAVX512 && cpu.X86.HasAVX512DQ && cpu.X86.HasAVX512VBMI2
)

func Print() {
	fmt.Println("AMD")
	fmt.Println(cpu.X86.HasAVX512)
	fmt.Println(cpu.X86.HasAVX512DQ)
	fmt.Println(cpu.X86.HasAVX512VBMI2)
}
