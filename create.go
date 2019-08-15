package iavlproofs

import (
	"fmt"

	proofs "github.com/confio/proofs/go"
	"github.com/tendermint/iavl"
)

/*
CreateMembershipProof will produce a CommitmentProof that the given key (and queries value) exists in the iavl tree.
If the key doesn't exist in the tree, this will return an error.
*/
func CreateMembershipProof(tree *iavl.MutableTree, key []byte) (*proofs.CommitmentProof, error) {
	exist, err := createExistenceProof(tree, key)
	if err != nil {
		return nil, err
	}
	proof := &proofs.CommitmentProof{
		Proof: &proofs.CommitmentProof_Exist{
			Exist: exist,
		},
	}
	return proof, nil
}

/*
CreateNonMembershipProof will produce a CommitmentProof that the given key doesn't exist in the iavl tree.
If the key exists in the tree, this will return an error.
*/
func CreateNonMembershipProof(tree *iavl.MutableTree, key []byte) (*proofs.CommitmentProof, error) {
	// idx is one node right of what we want....
	idx, val := tree.Get(key)
	if val != nil {
		return nil, fmt.Errorf("Cannot create NonExistanceProof when Key in State")
	}

	var err error
	nonexist := &proofs.NonExistenceProof{
		Key: key,
	}

	if idx >= 1 {
		leftkey, _ := tree.GetByIndex(idx - 1)
		nonexist.Left, err = createExistenceProof(tree, leftkey)
		if err != nil {
			return nil, err
		}
	}

	// this will be nil if nothing right of the queried key
	rightkey, _ := tree.GetByIndex(idx)
	if rightkey != nil {
		nonexist.Right, err = createExistenceProof(tree, rightkey)
		if err != nil {
			return nil, err
		}
	}

	proof := &proofs.CommitmentProof{
		Proof: &proofs.CommitmentProof_Nonexist{
			Nonexist: nonexist,
		},
	}
	return proof, nil
}

func createExistenceProof(tree *iavl.MutableTree, key []byte) (*proofs.ExistenceProof, error) {
	value, proof, err := tree.GetWithProof(key)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("Cannot create ExistanceProof when Key not in State")
	}
	return convertExistenceProof(proof, key, value)
}