package iavlproofs

import (
	"bytes"
	"testing"
)

func TestConvertExistence(t *testing.T) {
	proof, err := generateIavlResult(200, middle)
	if err != nil {
		t.Fatal(err)
	}

	converted, err := convertExistenceProof(proof.Proof, proof.Key, proof.Value)
	if err != nil {
		t.Fatal(err)
	}

	calc, err := converted.Calculate()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(calc, proof.RootHash) {
		t.Errorf("Calculated: %X\nExpected:   %X", calc, proof.RootHash)
	}
}
