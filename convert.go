package iavlproofs

import (
	"fmt"

	proofs "github.com/confio/proofs/go"
	"github.com/tendermint/iavl"
)

// ConvertExistenceProof will convert the given proof into a valid
// existence proof, if that's what it is.
//
// This is the simplest case of the range proof and we will focus on
// demoing compatibility here
func ConvertExistenceProof(p *iavl.RangeProof, key, value []byte) (*proofs.ExistenceProof, error) {
	if len(p.Leaves) != 1 {
		return nil, fmt.Errorf("Existence proof requires RangeProof to have exactly one leaf")
	}

	leaf := convertLeafOp(p.Leaves[0].Version)
	leafHash := p.Leaves[0].Hash()
	fmt.Printf("leaf hash: %X\n", leafHash)

	inner := convertInnerOps(p.LeftPath)
	// prepend leaf
	steps := append([]*proofs.ProofOp{leaf}, inner...)

	proof := &proofs.ExistenceProof{
		Key:   key,
		Value: value,
		Steps: steps,
	}
	return proof, nil
}

func convertLeafOp(version int64) *proofs.ProofOp {
	// this is adapted from iavl/proof.go:proofLeafNode.Hash()
	prefix := aminoVarInt(0)
	prefix = append(prefix, aminoVarInt(1)...)
	prefix = append(prefix, aminoVarInt(version)...)

	leaf := &proofs.LeafOp{
		Hash:         proofs.HashOp_SHA256,
		PrehashValue: proofs.HashOp_SHA256,
		Length:       proofs.LengthOp_VAR_PROTO,
		Prefix:       prefix,
	}
	fmt.Printf("Leaf: %#v\n", leaf)
	return proofs.WrapLeaf(leaf)
}

// we cannot get the proofInnerNode type, so we need to do the whole path in one function
func convertInnerOps(path iavl.PathToLeaf) []*proofs.ProofOp {
	steps := make([]*proofs.ProofOp, 0, len(path))

	// we need to go in reverse order, iavl starts from root to leaf,
	// we want to go up from the leaf to the root
	for i := len(path) - 1; i >= 0; i-- {
		// this is adapted from iavl/proof.go:proofInnerNode.Hash()
		prefix := aminoVarInt(int64(path[i].Height))
		prefix = append(prefix, aminoVarInt(path[i].Size)...)
		prefix = append(prefix, aminoVarInt(path[i].Version)...)

		var suffix []byte
		if len(path[i].Left) > 0 {
			prefix = append(prefix, path[i].Left...)
		} else {
			suffix = path[i].Right
		}

		op := &proofs.InnerOp{
			Hash:   proofs.HashOp_SHA256,
			Prefix: prefix,
			Suffix: suffix,
		}
		wrapped := proofs.WrapInner(op)
		steps = append(steps, wrapped)
	}

	return steps
}

func aminoVarInt(orig int64) []byte {
	// amino-specific byte swizzling
	i := uint64(orig) << 1
	if orig < 0 {
		i = ^i
	}

	// avoid multiple allocs for normal case
	res := make([]byte, 0, 8)

	// standard protobuf encoding
	for i >= 1<<7 {
		res = append(res, uint8(i&0x7f|0x80))
		i >>= 7
	}
	res = append(res, uint8(i))
	return res
}
