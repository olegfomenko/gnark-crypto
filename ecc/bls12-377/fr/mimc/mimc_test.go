package mimc

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
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

//func BenchmarkMIMCNative(b *testing.B) {
//	for i := 0; i < b.N; i++ {
//		b.StopTimer()
//		msg := make([]byte, 128)
//		_, err := mrand.Read(msg)
//		if err != nil {
//			panic(err)
//		}
//
//		h := NewMiMC()
//
//		b.StartTimer()
//		_ = h.Sum(msg)
//		_ = h.Sum(nil)
//	}
//}
//
//func BenchmarkMIMCAsm(b *testing.B) {
//	for i := 0; i < b.N; i++ {
//		b.StopTimer()
//		msg := make([]byte, 128)
//		_, err := mrand.Read(msg)
//		if err != nil {
//			panic(err)
//		}
//
//		h := NewMiMC()
//
//		b.StartTimer()
//		_ = h.(*digest).Sum2(msg)
//		_ = h.(*digest).Sum2(nil)
//	}
//}

func BenchmarkEncryptNative(b *testing.B) {
	initConstants()

	for i := 0; i < 1000; i++ {
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()
		encryptTest1(h, m)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		doStuff()
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()

		b.StartTimer()
		encryptTest1(h, m)
	}
}

func BenchmarkEncryptNative2(b *testing.B) {
	initConstants()

	for i := 0; i < 1000; i++ {
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()

		msg := *m
		hash := *h
		encryptTest2(hash, msg)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		doStuff()
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()

		msg := *m
		hash := *h
		b.StartTimer()
		encryptTest2(hash, msg)
	}
}

func BenchmarkEncryptASM(b *testing.B) {
	for i := 0; i < 1000; i++ {
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()
		fr.MIMCEncrypt(h, m)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		doStuff()
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()
		b.StartTimer()
		fr.MIMCEncrypt(h, m)
	}
}

func encryptTest1(h, m *fr.Element) *fr.Element {
	var tmp fr.Element
	for i := 0; i < mimcNbRounds; i++ {
		// m = (m+k+c)^**17
		tmp.Add(m, h).Add(&tmp, &mimcConstants[i])
		m.Square(&tmp).
			Square(m).
			Square(m).
			Square(m).
			Mul(m, &tmp)
	}
	m.Add(m, h)
	return m
}

func encryptTest2(m, h fr.Element) fr.Element {
	var tmp fr.Element
	for i := 0; i < mimcNbRounds; i++ {
		// m = (m+k+c)^**17
		tmp.Add(&m, &h).Add(&tmp, &mimcConstants[i])
		m.Square(&tmp).
			Square(&m).
			Square(&m).
			Square(&m).
			Mul(&m, &tmp)
	}
	m.Add(&m, &h)
	return m
}

func doStuff() {
	for i := 0; i < 50; i++ {
		tmp := make([]byte, 4096)
		mrand.Read(tmp)
		sha3.Sum256(tmp)
	}
}
