package fflonk

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// ReadFrom decodes OpeningProof data from reader.
func (proof *OpeningProof) ReadFrom(r io.Reader) (int64, error) {

	dec := bn254.NewDecoder(r)

	toDecode := []interface{}{
		&proof.SOpeningProof.W,
		&proof.SOpeningProof.WPrime,
		proof.SOpeningProof.ClaimedValues,
		proof.ClaimedValues,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}

// WriteTo writes binary encoding of OpeningProof.
func (proof *OpeningProof) WriteTo(w io.Writer) (int64, error) {

	enc := bn254.NewEncoder(w)

	toEncode := []interface{}{
		&proof.SOpeningProof.W,
		&proof.SOpeningProof.WPrime,
		proof.SOpeningProof.ClaimedValues,
		proof.ClaimedValues,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil
}
