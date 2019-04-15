package iavlproofs

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/libs/db"
)

func TestConvertProof(t *testing.T) {
	proof, err := generateRangeProof(1)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(proof.proof.String())
	fmt.Printf("Root: %X\n", proof.rootHash)

	converted, err := ConvertExistenceProof(proof.proof, proof.key, proof.value)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("\n\n%#v\n", converted)
	calc, err := converted.Calculate()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(calc, proof.rootHash) {
		t.Errorf("Calculated: %X\nExpected:   %X", calc, proof.rootHash)
	}
}

type provenValue struct {
	key      []byte
	value    []byte
	proof    *iavl.RangeProof
	rootHash []byte
}

// generateRangeProof makes a tree of size and returns a range proof for one random element
//
// returns a range proof and the root hash of the tree
func generateRangeProof(size int) (*provenValue, error) {
	tree := iavl.NewMutableTree(db.NewMemDB(), 0)

	// insert lots of info and store the bytes
	/*
		allkeys := make([][]byte, size)
		for i := 0; i < size; i++ {
			key := cmn.RandStr(20)
			value := "value_for_" + key
			tree.Set([]byte(key), []byte(value))
			allkeys[i] = []byte(key)
		}

		key := allkeys[0]
	*/
	key := []byte{0xca, 0xfe}
	val := []byte{0xde, 0xad, 0xbe, 0xef}
	tree.Set(key, val)

	value, proof, err := tree.GetWithProof(key)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("GetWithProof returned nil value")
	}
	if !bytes.Equal(value, val) {
		return nil, fmt.Errorf("Wrote %X got value %X", val, value)
	}
	if len(proof.Leaves) != 1 {
		return nil, fmt.Errorf("GetWithProof returned %d leaves", len(proof.Leaves))
	}
	root := tree.WorkingHash()

	res := &provenValue{
		key:      key,
		value:    value,
		proof:    proof,
		rootHash: root,
	}
	return res, nil
}
