package rln

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func random32() [32]byte {
	var randomBytes [32]byte
	_, _ = rand.Read(randomBytes[:])
	return randomBytes
}

func TestMerkleProofSerDe(t *testing.T) {

	for _, testSize := range []int{0, 1, 8, 16, 20} {
		mProof := MerkleProof{
			PathElements: []MerkleNode{},
			PathIndexes:  []uint8{},
		}

		for i := 0; i < testSize; i++ {
			mProof.PathElements = append(mProof.PathElements, random32())
			mProof.PathIndexes = append(mProof.PathIndexes, uint8(i%2))
		}

		// Check the size is the expected
		ser := mProof.serialize()
		require.Equal(t, 8+testSize*32+testSize+8, len(ser))

		// Deserialize and check its matches the original
		desProof := MerkleProof{}
		err := desProof.deserialize(ser)
		require.NoError(t, err)
		require.Equal(t, mProof, desProof)
	}
}

func TestRLNWitnessInputSerDe(t *testing.T) {
	depth := 20

	mProof := MerkleProof{
		PathElements: []MerkleNode{},
		PathIndexes:  []uint8{},
	}

	for i := 0; i < depth; i++ {
		mProof.PathElements = append(mProof.PathElements, random32())
		mProof.PathIndexes = append(mProof.PathIndexes, uint8(i%2))
	}

	witness := RLNWitnessInput{
		IDSecretHash:      random32(),
		UserMessageLimit:  8,
		MessageId:         7,
		MerkleProof:       mProof,
		X:                 [32]byte{0x00},
		ExternalNullifier: [32]byte{0x00},
	}

	ser := witness.serialize()
	require.Equal(t, 32+32+32+8+depth*32+depth+8+32+32, len(ser))
}
