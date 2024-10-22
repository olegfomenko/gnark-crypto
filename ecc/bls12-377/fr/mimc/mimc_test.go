package mimc

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"testing"
)

func BenchmarkEncryptASM(b *testing.B) {
	m, _ := new(fr.Element).SetRandom()
	h, _ := new(fr.Element).SetRandom()
	fr.MIMCEncrypt(h, m)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m, _ := new(fr.Element).SetRandom()
		h, _ := new(fr.Element).SetRandom()
		b.StartTimer()
		fr.MIMCEncrypt(h, m)
	}
}

func BenchmarkEncryptSemiASM(b *testing.B) {
	b.ResetTimer()

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
	b.ResetTimer()

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
