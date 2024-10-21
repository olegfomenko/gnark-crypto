package mimc

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	mrand "math/rand"
	"testing"
)

func TestHashASMMIMC(t *testing.T) {
	initConstants()
	fmt.Println("Running test")

	for i := 0; i < 100; i++ {
		msg := make([]byte, 128)
		_, err := mrand.Read(msg)
		if err != nil {
			panic(err)
		}

		h1 := NewMiMC()
		h2 := NewMiMC()

		res1 := h1.Sum(msg)

		res2 := h2.(*digest).Sum2(msg)

		assert.Equal(t, bytes.Compare(res1, res2), 0)
	}

}

func BenchmarkMIMCNative(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		msg := make([]byte, 128)
		_, err := mrand.Read(msg)
		if err != nil {
			panic(err)
		}

		h := NewMiMC()

		b.StartTimer()
		_ = h.Sum(msg)
	}
}

func BenchmarkMIMCAsm(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		msg := make([]byte, 128)
		_, err := mrand.Read(msg)
		if err != nil {
			panic(err)
		}

		h := NewMiMC()

		b.StartTimer()
		_ = h.(*digest).Sum2(msg)
	}
}
