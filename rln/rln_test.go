package rln

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/suite"
)

func TestRLNSuite(t *testing.T) {
	suite.Run(t, new(RLNSuite))
}

type RLNSuite struct {
	suite.Suite
}

func (s *RLNSuite) TestNew() {
	rln, err := NewRLN()
	s.NoError(err)

	root1, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root1, 32)

	rln2, err := NewWithConfig(DefaultTreeDepth, nil)
	s.NoError(err)

	root2, err := rln2.GetMerkleRoot()
	s.NoError(err)
	s.Len(root2, 32)
	s.Equal(root1, root2)
}

func (s *RLNSuite) TestMembershipKeyGen() {
	rln, err := NewRLN()
	s.NoError(err)

	key, err := rln.MembershipKeyGen()
	s.NoError(err)
	s.Len(key.IDSecretHash, 32)
	s.Len(key.IDCommitment, 32)
	s.Len(key.IDTrapdoor, 32)
	s.Len(key.IDNullifier, 32)
	s.NotEmpty(key.IDSecretHash)
	s.NotEmpty(key.IDCommitment)
	s.NotEmpty(key.IDTrapdoor)
	s.NotEmpty(key.IDNullifier)
	s.False(bytes.Equal(key.IDCommitment[:], make([]byte, 32)))
	s.False(bytes.Equal(key.IDSecretHash[:], make([]byte, 32)))
	s.False(bytes.Equal(key.IDTrapdoor[:], make([]byte, 32)))
	s.False(bytes.Equal(key.IDNullifier[:], make([]byte, 32)))
}

func (s *RLNSuite) TestGetMerkleRoot() {
	rln, err := NewRLN()
	s.NoError(err)

	root1, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root1, 32)

	root2, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root2, 32)

	s.Equal(root1, root2)
}

func (s *RLNSuite) TestInsertMember() {
	rln, err := NewRLN()
	s.NoError(err)

	keypair, err := rln.MembershipKeyGen()
	s.NoError(err)

	err = rln.InsertMember(keypair.IDCommitment, keypair.UserMessageLimit)
	s.NoError(err)
}

func (s *RLNSuite) TestInsertMembers() {
	rln, err := NewRLN()
	s.NoError(err)

	var commitments []IDCommitment
	for i := 0; i < 10; i++ {
		keypair, err := rln.MembershipKeyGen()
		s.NoError(err)
		commitments = append(commitments, keypair.IDCommitment)
	}

	err = rln.InsertMembers(0, commitments)
	s.NoError(err)

	numLeaves := rln.LeavesSet()
	s.Equal(uint(10), numLeaves)
}

func (s *RLNSuite) TestRemoveMember() {
	rln, err := NewRLN()
	s.NoError(err)

	keypair, err := rln.MembershipKeyGen()
	s.NoError(err)

	err = rln.InsertMember(keypair.IDCommitment, keypair.UserMessageLimit)
	s.NoError(err)

	err = rln.DeleteMember(MembershipIndex(0))
	s.NoError(err)
}

func (s *RLNSuite) TestMerkleTreeConsistenceBetweenDeletionAndInsertion() {
	rln, err := NewRLN()
	s.NoError(err)

	root1, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root1, 32)

	keypair, err := rln.MembershipKeyGen()
	s.NoError(err)

	err = rln.InsertMember(keypair.IDCommitment, keypair.UserMessageLimit)
	s.NoError(err)

	// read the Merkle Tree root after insertion
	root2, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root2, 32)

	// delete the first member
	deleted_member_index := MembershipIndex(0)
	err = rln.DeleteMember(deleted_member_index)
	s.NoError(err)

	// read the Merkle Tree root after the deletion
	root3, err := rln.GetMerkleRoot()
	s.NoError(err)
	s.Len(root3, 32)

	// the root must change after the insertion
	s.NotEqual(root1, root2)

	// The initial root of the tree (empty tree) must be identical to
	// the root of the tree after one insertion followed by a deletion
	s.Equal(root1, root3)
}

func (s *RLNSuite) TestHash() {
	rln, err := NewRLN()
	s.NoError(err)

	// prepare the input
	msg := []byte("Hello")
	hash, err := rln.Sha256(msg)
	s.NoError(err)

	expectedHash, _ := hex.DecodeString("4c6ea217404bd5f10e243bac29dc4f1ec36bf4a41caba7b4c8075c54abb3321e")
	s.Equal(expectedHash, hash[:])
}

func (s *RLNSuite) TestPoseidon() {
	rln, err := NewRLN()
	s.NoError(err)

	// prepare the input
	msg1, _ := hex.DecodeString("126f4c026cd731979365f79bd345a46d673c5a3f6f588bdc718e6356d02b6fdc")
	msg2, _ := hex.DecodeString("1f0e5db2b69d599166ab16219a97b82b662085c93220382b39f9f911d3b943b1")
	hash, err := rln.Poseidon(msg1, msg2)
	s.NoError(err)

	expectedHash, _ := hex.DecodeString("83e4a6b2dea68aad26f04f32f37ac1e018188a0056b158b2aa026d34266d1f30")
	s.Equal(expectedHash, hash[:])
}

func (s *RLNSuite) TestCreateListMembershipKeysAndCreateMerkleTreeFromList() {
	groupSize := 100
	list, root, err := CreateMembershipList(groupSize)
	s.NoError(err)
	s.Len(list, groupSize)
	s.Len(root, HASH_HEX_SIZE) // check the size of the calculated tree root
}

func (s *RLNSuite) TestCheckCorrectness() {
	groupKeys := STATIC_GROUP_KEYS

	// create a set of MembershipKeyPair objects from groupKeys
	groupKeyPairs, err := ToIdentityCredentials(groupKeys)
	s.NoError(err)

	// extract the id commitments
	var groupIDCommitments []IDCommitment
	for _, c := range groupKeyPairs {
		groupIDCommitments = append(groupIDCommitments, c.IDCommitment)
	}

	// calculate the Merkle tree root out of the extracted id commitments
	root, err := CalcMerkleRoot(groupIDCommitments)
	s.NoError(err)

	expectedRoot, _ := hex.DecodeString(STATIC_GROUP_MERKLE_ROOT)

	s.Len(groupKeyPairs, STATIC_GROUP_SIZE)
	s.Equal(expectedRoot, root[:])
}

func (s *RLNSuite) TestGetLeaf() {
	rln, err := NewRLN()
	s.NoError(err)

	amountLeafs := int(31)

	for i := 0; i < amountLeafs; i++ {
		// allowed messages per epoch of the membership
		// using different values between 1 and 7
		userMessageLimit := uint32(amountLeafs%7 + 1)

		// generate membership
		memKeys, err := rln.MembershipKeyGen(userMessageLimit)
		s.NoError(err)

		// insert membership
		err = rln.InsertMember(memKeys.IDCommitment, memKeys.UserMessageLimit)
		s.NoError(err)

		// retrieve the leaf
		retrievedLeaf, err := rln.GetLeaf(uint(i))
		s.NoError(err)

		// calculate the leaf we would expect
		userMessageLimitBytes := SerializeUint32(userMessageLimit)
		hashedLeaf, err := rln.Poseidon(memKeys.IDCommitment[:], userMessageLimitBytes[:])
		s.NoError(err)

		// assert it matches
		s.Equal(hashedLeaf, retrievedLeaf)
	}
}

func (s *RLNSuite) TestValidProof() {
	rln, err := NewRLN()
	s.NoError(err)

	// allowed messages per epoch of the membership
	userMessageLimit := uint32(10)

	//peer's index in the Merkle Tree
	index := uint(5)

	memKeys, err := rln.MembershipKeyGen(userMessageLimit)
	s.NoError(err)

	// Create a Merkle tree with random members
	for i := uint(0); i < 10; i++ {
		if i == index {
			err = rln.InsertMember(memKeys.IDCommitment, memKeys.UserMessageLimit)
			s.NoError(err)
		} else {
			// create a new key pair
			memberKeys, err := rln.MembershipKeyGen(userMessageLimit)
			s.NoError(err)

			err = rln.InsertMember(memberKeys.IDCommitment, memberKeys.UserMessageLimit)
			s.NoError(err)
		}
	}

	// prepare the message
	msg := []byte("Hello")

	// prepare the epoch
	var epoch Epoch = SerializeUint32(1000)

	// generate multiple valid proofs for the same epoch
	for i := uint32(0); i < userMessageLimit; i++ {
		// message sequence within the epoch
		messageId := uint32(i)

		// generate proof
		proofRes, err := rln.GenerateProof(msg, *memKeys, MembershipIndex(index), epoch, messageId)
		s.NoError(err)

		// verify the proof
		verified, err := rln.Verify(msg, *proofRes)
		s.NoError(err)
		s.True(verified)

		// verify with roots
		root, err := rln.GetMerkleRoot()
		s.NoError(err)

		verified, err = rln.Verify(msg, *proofRes, root)
		s.NoError(err)
		s.True(verified)
	}
}

func (s *RLNSuite) TestProofBeyondLimit() {
	rln, err := NewRLN()
	s.NoError(err)

	// allowed messages per epoch of the membership
	userMessageLimit := uint32(10)

	//peer's index in the Merkle Tree
	index := uint(5)

	memKeys, err := rln.MembershipKeyGen(userMessageLimit)
	s.NoError(err)

	// Create a Merkle tree with random members
	for i := uint(0); i < 10; i++ {
		if i == index {
			err = rln.InsertMember(memKeys.IDCommitment, memKeys.UserMessageLimit)
			s.NoError(err)
		} else {
			// create a new key pair
			memberKeys, err := rln.MembershipKeyGen(userMessageLimit)
			s.NoError(err)

			err = rln.InsertMember(memberKeys.IDCommitment, memberKeys.UserMessageLimit)
			s.NoError(err)
		}
	}

	// prepare the message
	msg := []byte("Hello")

	// prepare the epoch
	var epoch Epoch = SerializeUint32(876543456)

	// TODO;:
	for i := uint32(userMessageLimit + 1); i < (userMessageLimit + 10); i++ {
		// message sequence within the epoch
		messageId := uint32(i)

		// generate proof TODO:Errors!
		_, err := rln.GenerateProof(msg, *memKeys, MembershipIndex(index), epoch, messageId)
		s.Error(err)
	}
}

func (s *RLNSuite) TestInvalidProof() {
	rln, err := NewRLN()
	s.NoError(err)

	memKeys, err := rln.MembershipKeyGen()
	s.NoError(err)

	//peer's index in the Merkle Tree
	index := 5

	// Create a Merkle tree with random members
	for i := 0; i < 10; i++ {
		if i == index {
			// insert the current peer's pk
			err := rln.InsertMember(memKeys.IDCommitment, memKeys.UserMessageLimit)
			s.NoError(err)
		} else {
			// create a new key pair
			memberKeys, err := rln.MembershipKeyGen()
			s.NoError(err)

			err = rln.InsertMember(memberKeys.IDCommitment, memberKeys.UserMessageLimit)
			s.NoError(err)
		}
	}

	root, err := rln.GetMerkleRoot()
	s.NoError(err)

	// prepare the message
	msg := []byte("Hello")

	// prepare the epoch
	var epoch Epoch

	badIndex := 4

	// message sequence within the epoch
	messageId := uint32(1)

	// generate proof
	proofRes, err := rln.GenerateProof(msg, *memKeys, MembershipIndex(badIndex), epoch, messageId)
	s.NoError(err)

	// verify the proof (should not be verified)
	verified, err := rln.Verify(msg, *proofRes, root)
	s.NoError(err)
	s.False(verified)
}

func (s *RLNSuite) TestGetMerkleProof() {
	for _, treeDepth := range []TreeDepth{TreeDepth15, TreeDepth19, TreeDepth20} {
		treeDepthInt := int(treeDepth)

		rln, err := NewWithConfig(treeDepth, nil)
		s.NoError(err)

		leaf0 := [32]byte{0x00}
		leaf1 := [32]byte{0x01}
		leaf5 := [32]byte{0x05}

		rln.InsertMemberAt(0, leaf0)
		rln.InsertMemberAt(1, leaf1)
		rln.InsertMemberAt(5, leaf5)

		b1, err := rln.GetMerkleProof(0)
		s.NoError(err)
		s.Equal(treeDepthInt, len(b1.PathElements))
		s.Equal(treeDepthInt, len(b1.PathIndexes))
		// First path is right leaf [0, 1]
		s.EqualValues(leaf1, b1.PathElements[0])

		b2, err := rln.GetMerkleProof(4)
		s.NoError(err)
		s.Equal(treeDepthInt, len(b2.PathElements))
		s.Equal(treeDepthInt, len(b2.PathIndexes))
		// First path is right leaf [4, 5]
		s.EqualValues(leaf5, b2.PathElements[0])

		b3, err := rln.GetMerkleProof(10)
		s.NoError(err)
		s.Equal(treeDepthInt, len(b3.PathElements))
		s.Equal(treeDepthInt, len(b3.PathIndexes))
		// First path is right leaf. But its empty
		s.EqualValues([32]byte{0x00}, b3.PathElements[0])
	}
}

func (s *RLNSuite) TestGenerateRLNProofWithWitness_VerifiesOK() {
	s.T().Skip("Skipped until proof generation with witness is implemented for RLNv2")
	treeSize := 20

	rln, err := NewRLN()
	s.NoError(err)

	treeElements := make([]IdentityCredential, 0)

	// Create a Merkle tree with random members
	for i := 0; i < treeSize; i++ {
		memberKeys, err := rln.MembershipKeyGen()
		s.NoError(err)

		err = rln.InsertMember(memberKeys.IDCommitment, memberKeys.UserMessageLimit)
		s.NoError(err)
		treeElements = append(treeElements, *memberKeys)
	}

	// We generate proofs with a custom witness aquired outside zerokit for diferent indexes
	for _, memberIndex := range []uint{0, 10, 13, 15} {
		root, err := rln.GetMerkleRoot()
		s.NoError(err)

		// We provide out custom witness
		merkleProof, err := rln.GetMerkleProof(memberIndex)
		s.NoError(err)

		message := []byte("some rln protected message")
		epoch := ToEpoch(1000)

		rlnWitness := CreateWitness(
			treeElements[memberIndex].IDSecretHash,
			message,
			epoch,
			merkleProof)

		// Generate a proof with our custom witness (Merkle Path of the memberIndex)
		proofRes1, err := rln.GenerateRLNProofWithWitness(rlnWitness)
		s.NoError(err)
		verified1, err := rln.Verify(message, *proofRes1, root)
		s.NoError(err)
		s.True(verified1)

		// message sequence within the epoch
		messageId := uint32(1)

		// Generate a proof without our custom witness, to ensure they match
		proofRes2, err := rln.GenerateProof(message, treeElements[memberIndex], MembershipIndex(memberIndex), epoch, messageId)
		s.NoError(err)

		// Ensure we have the same root
		s.Equal(root, proofRes1.MerkleRoot)

		// Proof generate with custom witness match the proof generate with the witness
		// from zerokit. Proof itself is not asserted, can be different.
		s.Equal(proofRes1.MerkleRoot, proofRes2.MerkleRoot)
		//s.Equal(proofRes1.Epoch, proofRes2.Epoch)
		s.Equal(proofRes1.ShareX, proofRes2.ShareX)
		s.Equal(proofRes1.ShareY, proofRes2.ShareY)
		s.Equal(proofRes1.Nullifier, proofRes2.Nullifier)
		//s.Equal(proofRes1.RLNIdentifier, proofRes2.RLNIdentifier)
	}
}

func (s *RLNSuite) TestGenerateRLNProofWithWitness_VerifiesNOK() {
	s.T().Skip("Skipped until proof generation with witness is implemented for RLNv2")

	treeSize := 20

	rln, err := NewRLN()
	s.NoError(err)

	treeElements := make([]IdentityCredential, 0)

	// Create a Merkle tree with random members
	for i := 0; i < treeSize; i++ {
		memberKeys, err := rln.MembershipKeyGen()
		s.NoError(err)

		err = rln.InsertMember(memberKeys.IDCommitment, memberKeys.UserMessageLimit)
		s.NoError(err)
		treeElements = append(treeElements, *memberKeys)
	}

	// We generate proofs with a custom witness aquired outside zerokit for diferent indexes
	for _, memberIndex := range []uint{0, 10, 13, 15} {
		root, err := rln.GetMerkleRoot()
		s.NoError(err)

		// We provide out custom witness
		merkleProof, err := rln.GetMerkleProof(memberIndex)
		s.NoError(err)

		message := []byte("some rln protected message")
		epoch := ToEpoch(1000)

		rlnWitness1 := CreateWitness(
			treeElements[memberIndex].IDSecretHash,
			message,
			epoch,
			merkleProof)

		// Generate a proof with our custom witness (Merkle Path of the memberIndex)
		proofRes1, err := rln.GenerateRLNProofWithWitness(rlnWitness1)
		s.NoError(err)

		// 1) Message changed, does not verify
		verified1, err := rln.Verify([]byte("different message"), *proofRes1, root)
		s.NoError(err)
		s.False(verified1)

		// 2) Different epoch, does not verify
		//proofRes1.Epoch = ToEpoch(999)
		verified2, err := rln.Verify(message, *proofRes1, root)
		s.NoError(err)
		s.False(verified2)

		// 3) Merkle proof in provided witness is wrong, does not verify
		merkleProof.PathElements[0] = [32]byte{0x11}
		rlnWitness2 := CreateWitness(
			treeElements[memberIndex].IDSecretHash,
			message,
			epoch,
			merkleProof)

		proofRes3, err := rln.GenerateRLNProofWithWitness(rlnWitness2)
		s.NoError(err)

		verified3, err := rln.Verify(message, *proofRes3, root)
		s.NoError(err)
		s.False(verified3)

		// 4) Membership does not match the index (and not part of tree), does not verify
		merkleProof4, err := rln.GetMerkleProof(memberIndex)
		s.NoError(err)

		// Membership that does not match the index
		memberKeys, err := rln.MembershipKeyGen()
		s.NoError(err)

		// Proof proves memberIndex inclusion, but provided membership is different
		rlnWitness4 := CreateWitness(
			memberKeys.IDSecretHash,
			[]byte("some rln protected message"),
			ToEpoch(999),
			merkleProof4)

		proofRes4, err := rln.GenerateRLNProofWithWitness(rlnWitness4)
		s.NoError(err)

		verified4, err := rln.Verify(message, *proofRes4, root)
		s.NoError(err)
		s.False(verified4)
	}
}

func (s *RLNSuite) TestEpochConsistency() {
	// check edge cases
	var epoch uint64 = math.MaxUint64
	epochBytes := ToEpoch(epoch)
	decodedEpoch := epochBytes.Uint64()

	s.Equal(epoch, decodedEpoch)
}

func (s *RLNSuite) TestEpochComparison() {
	// check edge cases
	var time1 uint64 = math.MaxUint64
	var time2 uint64 = math.MaxUint64 - 1

	epoch1 := ToEpoch(time1)
	epoch2 := ToEpoch(time2)

	s.Equal(int64(1), Diff(epoch1, epoch2))
	s.Equal(int64(-1), Diff(epoch2, epoch1))
}
