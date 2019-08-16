package iavlproofs

import (
	"testing"

	"github.com/confio/proofs-iavl/helpers"
	proofs "github.com/confio/proofs/go"
)

func TestCreateMembership(t *testing.T) {
	cases := map[string]struct{
		size int
		loc helpers.Where
	}{
		"small left": { size: 100, loc: helpers.Left},
		"small middle": { size: 100, loc: helpers.Middle},
		"small right": { size: 100, loc: helpers.Right},
		"big left": { size: 5431, loc: helpers.Left},
		"big middle": { size: 5431, loc: helpers.Middle},
		"big right": { size: 5431, loc: helpers.Right},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tree, allkeys := helpers.BuildTree(tc.size)
			key := helpers.GetKey(allkeys, tc.loc)
			_, val := tree.Get(key)
			proof, err := CreateMembershipProof(tree, key)
			if err != nil {
				t.Fatalf("Creating Proof: %+v", err)
			}

			root := tree.WorkingHash()
			valid := proofs.VerifyMembership(proofs.IavlSpec, root, proof, key, val)
			if !valid {
				t.Fatalf("Membership Proof Invalid")
			}
		})
	}
}

// func TestCreateNonMembership(t *testing.T) {
// 	cases := map[string]struct{
// 		size int
// 		loc helpers.Where
// 	}{
// 		"small left": { size: 100, loc: helpers.Left},
// 		"small middle": { size: 100, loc: helpers.Middle},
// 		"small right": { size: 100, loc: helpers.Right},
// 		"big left": { size: 5431, loc: helpers.Left},
// 		"big middle": { size: 5431, loc: helpers.Middle},
// 		"big right": { size: 5431, loc: helpers.Right},
// 	}

// 	for name, tc := range cases {
// 		t.Run(name, func(t *testing.T) {
// 			tree, allkeys := helpers.BuildTree(tc.size)
// 			key := helpers.GetNonKey(allkeys, tc.loc)

// 			proof, err := CreateMembershipProof(tree, key)
// 			if err != nil {
// 				t.Fatalf("Creating Proof: %+v", err)
// 			}

// 			root := tree.WorkingHash()
// 			valid := proofs.VerifyNonMembership(proofs.IavlSpec, root, proof, key)
// 			if !valid {
// 				t.Fatalf("Non Membership Proof Invalid")
// 			}
// 		})
// 	}
// }