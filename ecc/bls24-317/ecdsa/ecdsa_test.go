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

// Code generated by consensys/gnark-crypto DO NOT EDIT

package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
)

func TestECDSA(t *testing.T) {

	t.Parallel()
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("[BLS24-317] test the signing and verification", prop.ForAll(
		func() bool {

			var pp params
			_, _, g, _ := bls24317.Generators()
			pp.Base.Set(&g)
			pp.Order = fr.Modulus()

			privKey, _ := pp.GenerateKey(rand.Reader)

			hash := []byte("testing ECDSA")
			signature, _ := pp.Sign(hash, *privKey, rand.Reader)

			return pp.Verify(hash, signature, privKey.PublicKey.Q)
		},
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
