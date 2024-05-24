package rln

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// serialize converts a RateLimitProof and the data to a byte seq
// format taken from: https://github.com/vacp2p/zerokit/blob/v0.5.0/rln/src/public.rs#L747
// [identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
func serialize(
	idKey IDSecretHash,
	memIndex MembershipIndex,
	userMessageLimit uint32,
	messageId uint32,
	externalNullifier [32]byte,
	msg []byte) []byte {

	memIndexBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(memIndexBytes, uint64(memIndex))

	lenPrefMsg := appendLength(msg)

	var userMessageLimitByte [32]byte
	var messageIdByte [32]byte
	binary.LittleEndian.PutUint32(userMessageLimitByte[0:], userMessageLimit)
	binary.LittleEndian.PutUint32(messageIdByte[0:], messageId)

	output := append(idKey[:], memIndexBytes...)
	output = append(output, userMessageLimitByte[:]...)
	output = append(output, messageIdByte[:]...)
	output = append(output, externalNullifier[:]...)
	output = append(output, lenPrefMsg...)

	return output
}

// serialize converts a RateLimitProof and data to a byte seq
// this conversion is used in the proof verification proc
// the order of serialization is based on https://github.com/kilic/rln/blob/7ac74183f8b69b399e3bc96c1ae8ab61c026dc43/src/public.rs#L205
// [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
func (r RateLimitProof) serializeWithData(data []byte) []byte {
	lenPrefMsg := appendLength(data)
	proofBytes := r.serialize()
	proofBytes = append(proofBytes, lenPrefMsg...)
	return proofBytes
}

// serialize converts a RateLimitProof to a byte seq
// [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
func (r RateLimitProof) serialize() []byte {
	proofBytes := append(r.Proof[:], r.MerkleRoot[:]...)
	proofBytes = append(proofBytes, r.ExternalNullifier[:]...)
	proofBytes = append(proofBytes, r.ShareX[:]...)
	proofBytes = append(proofBytes, r.ShareY[:]...)
	proofBytes = append(proofBytes, r.Nullifier[:]...)
	return proofBytes
}

func (r *RLNWitnessInput) serialize() []byte {
	output := make([]byte, 0)

	output = append(output, r.IDSecretHash[:]...)
	output = append(output, r.MerkleProof.serialize()...)
	output = append(output, r.X[:]...)
	output = append(output, r.Epoch[:]...)
	output = append(output, r.RlnIdentifier[:]...)

	return output
}

func (r *RLNWitnessInput) deserialize(b []byte) error {

	return errors.New("not implemented")
}

func (r *MerkleProof) serialize() []byte {
	output := make([]byte, 0)

	output = append(output, appendLength32(Flatten(r.PathElements))...)
	output = append(output, appendLength(r.PathIndexes)...)

	return output
}

func (r *MerkleProof) deserialize(b []byte) error {

	// Check if we can read the first byte
	if len(b) < 8 {
		return errors.New(fmt.Sprintf("wrong input size: %d", len(b)))
	}

	var numElements big.Int
	var numIndexes big.Int

	offset := 0

	// Get amounf of elements in the proof
	numElements.SetBytes(revert(b[offset : offset+8]))
	offset += 8

	// With numElements we can determine the expected length of the proof.
	expectedLen := 8 + int(32*numElements.Uint64()) + 8 + int(numElements.Uint64())
	if len(b) != expectedLen {
		return errors.New(fmt.Sprintf("wrong input size expected: %d, current: %d",
			expectedLen,
			len(b)))
	}

	r.PathElements = make([]MerkleNode, numElements.Uint64())

	for i := uint64(0); i < numElements.Uint64(); i++ {
		copy(r.PathElements[i][:], b[offset:offset+32])
		offset += 32
	}

	// Get amount of indexes in the path
	numIndexes.SetBytes(revert(b[offset : offset+8]))
	offset += 8

	// Both numElements and numIndexes shall be equal and match the tree depth.
	if numIndexes.Uint64() != numElements.Uint64() {
		return errors.New(fmt.Sprintf("amount of values in path and indexes do not match: %s vs %s",
			numElements.String(), numIndexes.String()))
	}

	r.PathIndexes = make([]uint8, numIndexes.Uint64())

	for i := uint64(0); i < numIndexes.Uint64(); i++ {
		r.PathIndexes[i] = b[offset]
		offset += 1
	}

	if offset != len(b) {
		return errors.New(
			fmt.Sprintf("error parsing proof read: %d, length; %d", offset, len(b)))
	}

	return nil
}
