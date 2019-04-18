package iavlproofs

import (
	"bytes"
	"testing"
)

func TestConvertProof(t *testing.T) {
	proof, err := GenerateRangeProof(200)
	if err != nil {
		t.Fatal(err)
	}

	converted, err := ConvertExistenceProof(proof.Proof, proof.Key, proof.Value)
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
