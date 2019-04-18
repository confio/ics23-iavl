package iavlproofs

import (
	"fmt"

	"github.com/tendermint/iavl"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/db"
)

type IavlResult struct {
	Key      []byte
	Value    []byte
	Proof    *iavl.RangeProof
	RootHash []byte
}

// GenerateRangeProof makes a tree of size and returns a range proof for one random element
//
// returns a range proof and the root hash of the tree
func GenerateRangeProof(size int) (*IavlResult, error) {
	tree := iavl.NewMutableTree(db.NewMemDB(), 0)

	// insert lots of info and store the bytes
	allkeys := make([][]byte, size)
	for i := 0; i < size; i++ {
		key := cmn.RandStr(20)
		value := "value_for_" + key
		tree.Set([]byte(key), []byte(value))
		allkeys[i] = []byte(key)
	}

	key := allkeys[0]
	// key := []byte{0xca, 0xfe}
	// val := []byte{0xde, 0xad, 0xbe, 0xef}
	// tree.Set(key, val)

	value, proof, err := tree.GetWithProof(key)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("GetWithProof returned nil value")
	}
	if len(proof.Leaves) != 1 {
		return nil, fmt.Errorf("GetWithProof returned %d leaves", len(proof.Leaves))
	}
	root := tree.WorkingHash()

	res := &IavlResult{
		Key:      key,
		Value:    value,
		Proof:    proof,
		RootHash: root,
	}
	return res, nil
}
