package iavlproofs

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/tendermint/iavl"
	cmn "github.com/tendermint/tendermint/libs/common"
	db "github.com/tendermint/tm-db"
)

// IavlResult is the result of one match
type IavlResult struct {
	Key      []byte
	Value    []byte
	Proof    *iavl.RangeProof
	RootHash []byte
}

// IavlResult is the result for a non-existence proof
type IavlNoResult struct {
	Key   []byte
	Left  *IavlResult
	Right *IavlResult
}

// generateIavlResult makes a tree of size and returns a range proof for one random element
//
// returns a range proof and the root hash of the tree
func generateIavlResult(size int) (*IavlResult, error) {
	tree, allkeys := buildTree(size)
	key := allkeys[7]
	return iavlResult(tree, key)
}

func iavlResult(tree *iavl.MutableTree, key []byte) (*IavlResult, error) {
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

type where int

const (
	left where = iota
	right
	middle
)

// generateIavlNoResult makes a tree of size and returns a range proof
// showing one element is not in the tree
func generateIavlNoResult(size int, loc where) (*IavlNoResult, error) {
	tree, allkeys := buildTree(size)
	var leftkey, rightkey, key []byte

	if loc == left {
		leftkey = nil
		rightkey = allkeys[0]
		key = []byte{0, 0, 0, 1}
	} else if loc == right {
		leftkey = allkeys[len(allkeys)-1]
		rightkey = nil
		key = []byte{255, 255, 255, 255}

	} else {
		leftkey = allkeys[13]
		rightkey = allkeys[14]
		key = append([]byte{}, leftkey...)
		key[18] = 255
		key[19] = 255
	}

	var left, right *IavlResult
	var err error
	if len(leftkey) > 0 {
		left, err = iavlResult(tree, leftkey)
		if err != nil {
			return nil, err
		}
	}
	if len(rightkey) > 0 {
		right, err = iavlResult(tree, rightkey)
		if err != nil {
			return nil, err
		}
	}

	res := &IavlNoResult{
		Key:   key,
		Left:  left,
		Right: right,
	}
	return res, nil
}

// creates random key/values and stores in tree
// returns a list of all keys in sorted order
func buildTree(size int) (tree *iavl.MutableTree, keys [][]byte) {
	tree = iavl.NewMutableTree(db.NewMemDB(), 0)

	// insert lots of info and store the bytes
	keys = make([][]byte, size)
	for i := 0; i < size; i++ {
		key := cmn.RandStr(20)
		value := "value_for_" + key
		tree.Set([]byte(key), []byte(value))
		keys[i] = []byte(key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i], keys[j]) < 0
	})

	return tree, keys
}
