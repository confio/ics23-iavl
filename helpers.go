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

// generateIavlResult makes a tree of size and returns a range proof for one random element
//
// returns a range proof and the root hash of the tree
func generateIavlResult(size int, loc where) (*IavlResult, error) {
	tree, allkeys := buildTree(size)
	key := getKey(allkeys, loc)

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

// this returns a key, on left/right/middle
func getKey(allkeys [][]byte, loc where) []byte {
	if loc == left {
		return allkeys[0]
	}
	if loc == right {
		return allkeys[len(allkeys)-1]
	}
	// select a random index between 1 and allkeys-2
	idx := cmn.RandInt()%(len(allkeys)-2) + 1
	return allkeys[idx]
}

// this returns a missing key - left of all, right of all, or in the middle
func getNonKey(allkeys [][]byte, loc where) []byte {
	if loc == left {
		return []byte{0, 0, 0, 1}
	}
	if loc == right {
		return []byte{0xff, 0xff, 0xff, 0xff}
	}
	// otherwise, next to an existing key (copy before mod)
	key := append([]byte{}, getKey(allkeys, loc)...)
	key[len(key)-2] = 255
	key[len(key)-1] = 255
	return key
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
