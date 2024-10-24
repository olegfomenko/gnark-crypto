package mimc

import (
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mrand "math/rand"
	"testing"
)

func BenchmarkEncryptASM(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()
		b.StartTimer()
		fr.MIMCEncrypt(h, m)
	}
}

func BenchmarkEncryptSemiASM(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()
		b.StartTimer()
		MIMCEncryptSemi(h, m)
	}
}

func MIMCEncryptSemi(h, m *fr.Element) {
	for i := 0; i < mimcNbRounds; i++ {
		fr.MIMCStep(h, m, &fr.MIMCConstants[i])
	}

	m.Add(m, h)
}

func BenchmarkEncryptNative(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()

		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()

		d := digest{}
		d.h = *h
		msg := *m

		b.StartTimer()
		d.encrypt(msg)
	}
}

func TestHashMIMC(t *testing.T) {
	fmt.Println("Running test")

	for i := 0; i < 1000; i++ {
		msg := make([]byte, 128)
		_, err := mrand.Read(msg)
		if err != nil {
			panic(err)
		}

		h := NewMiMC()
		_, err = h.Write(msg)
		if err != nil {
			panic(err)
		}

		res := h.Sum(nil)
		fmt.Println(hex.EncodeToString(res))
	}

}
