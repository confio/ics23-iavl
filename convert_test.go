package iavlproofs

import (
	"bytes"
	"testing"

	proofs "github.com/confio/proofs/go"
)

func TestConvertExistence(t *testing.T) {
	proof, err := generateIavlResult(200)
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

func TestConvertNonExistence(t *testing.T) {
	proof, err := generateIavlNoResult(200, middle)
	if err != nil {
		t.Fatal(err)
	}

	left, err := convertExistenceProof(proof.Left.Proof, proof.Left.Key, proof.Left.Value)
	if err != nil {
		t.Fatal(err)
	}

	right, err := convertExistenceProof(proof.Right.Proof, proof.Right.Key, proof.Right.Value)
	if err != nil {
		t.Fatal(err)
	}

	nonexist := &proofs.NonExistenceProof{
		Key:   proof.Key,
		Left:  left,
		Right: right,
	}

	err = nonexist.Verify(proofs.IavlSpec, proof.Left.RootHash, proof.Key)
	if err != nil {
		t.Fatal(err)
	}
}
