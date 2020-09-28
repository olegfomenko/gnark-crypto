// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gurvy DO NOT EDIT

package bn256

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gurvy/bn256/fr"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
)

// ------------------------------------------------------------
// examples

func ExampleMillerLoop() {

	// samples a random scalar r
	var r big.Int
	var rFr fr.Element
	rFr.SetRandom()
	rFr.ToBigIntRegular(&r)

	// computes r*g1Gen, r*g2Gen
	var rg1 G1Affine
	var rg2 G2Affine
	rg1.ScalarMultiplication(&g1GenAff, &r)
	rg2.ScalarMultiplication(&g2GenAff, &r)

	// Computes e(g1GenAff, ag2) and e(ag1, g2GenAff)
	e1 := FinalExponentiation(MillerLoop(g1GenAff, rg2))
	e2 := FinalExponentiation(MillerLoop(rg1, g2GenAff))

	// checks that bilinearity property holds
	check := e1.Equal(&e2)

	fmt.Printf("%t\n", check)
	// Output: true

}

// ------------------------------------------------------------
// tests

func TestPairing(t *testing.T) {

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100

	properties := gopter.NewProperties(parameters)

	genA := GenE12()
	genR1 := GenFr()
	genR2 := GenFr()

	properties.Property("[BN256] Having the receiver as operand (final expo) should output the same result", prop.ForAll(
		func(a *e12) bool {
			var b e12
			b.Set(a)
			b.FinalExponentiation(a)
			a.FinalExponentiation(a)
			return a.Equal(&b)
		},
		genA,
	))

	properties.Property("[BN256] Exponentiating FinalExpo(a) to r should output 1", prop.ForAll(
		func(a *e12) bool {
			var one e12
			var e big.Int
			e.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
			one.SetOne()
			a.FinalExponentiation(a).Exp(a, e)
			return a.Equal(&one)
		},
		genA,
	))

	properties.Property("[BN256] bilinearity", prop.ForAll(
		func(a, b fr.Element) bool {

			var res, resa, resb, resab, zero GT

			var ag1 G1Affine
			var bg2 G2Affine

			var abigint, bbigint, ab big.Int

			a.ToBigIntRegular(&abigint)
			b.ToBigIntRegular(&bbigint)
			ab.Mul(&abigint, &bbigint)

			ag1.ScalarMultiplication(&g1GenAff, &abigint)
			bg2.ScalarMultiplication(&g2GenAff, &bbigint)

			res = FinalExponentiation(MillerLoop(g1GenAff, g2GenAff))
			resa = FinalExponentiation(MillerLoop(ag1, g2GenAff))
			resb = FinalExponentiation(MillerLoop(g1GenAff, bg2))

			resab.Exp(&res, ab)
			resa.Exp(&resa, bbigint)
			resb.Exp(&resb, abigint)

			return resab.Equal(&resa) && resab.Equal(&resb) && !res.Equal(&zero)

		},
		genR1,
		genR2,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ------------------------------------------------------------
// benches

func BenchmarkPairing(b *testing.B) {

	var g1GenAff G1Affine
	var g2GenAff G2Affine

	g1GenAff.FromJacobian(&g1Gen)
	g2GenAff.FromJacobian(&g2Gen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FinalExponentiation(MillerLoop(g1GenAff, g2GenAff))
	}
}

func BenchmarkFinalExponentiation(b *testing.B) {

	var a e12
	a.SetRandom()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FinalExponentiation(&a)
	}

}
