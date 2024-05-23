package rln

import "C"
import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/waku-org/go-zerokit-rln/rln/link"
)

// Same as: https://github.com/vacp2p/zerokit/blob/v0.3.5/rln/src/public.rs#L35
// Prevents a RLN ZK proof generated for one application to be re-used in another one.
var RLN_IDENTIFIER = [32]byte{166, 140, 43, 8, 8, 22, 206, 113, 151, 128, 118, 40, 119, 197, 218, 174, 11, 117, 84, 228, 96, 211, 212, 140, 145, 104, 146, 99, 24, 192, 217, 4}

var DEFAULT_USER_MESSAGE_LIMIT = uint32(10)

// RLN represents the context used for rln.
type RLN struct {
	w *link.RLNWrapper
}

func getResourcesFolder(depth TreeDepth) string {
	return fmt.Sprintf("tree_height_%d", depth)
}

// NewRLN generates an instance of RLN. An instance supports both zkSNARKs logics
// and Merkle tree data structure and operations. It uses a depth of 20 by default
func NewRLN() (*RLN, error) {
	return NewWithConfig(DefaultTreeDepth, nil)
}

// NewRLNWithParams generates an instance of RLN. An instance supports both zkSNARKs logics
// and Merkle tree data structure and operations. The parameter `depth“ indicates the depth of Merkle tree
func NewRLNWithParams(depth int, wasm []byte, zkey []byte, verifKey []byte, treeConfig *TreeConfig) (*RLN, error) {
	r := &RLN{}
	var err error

	treeConfigBytes := []byte{}
	if treeConfig != nil {
		treeConfigBytes, err = json.Marshal(treeConfig)
		if err != nil {
			return nil, err
		}
	}

	r.w, err = link.NewWithParams(depth, wasm, zkey, verifKey, treeConfigBytes)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// NewWithConfig generates an instance of RLN. An instance supports both zkSNARKs logics
// and Merkle tree data structure and operations. The parameter `depth` indicates the depth of Merkle tree
func NewWithConfig(depth TreeDepth, treeConfig *TreeConfig) (*RLN, error) {
	r := &RLN{}
	var err error

	configBytes, err := json.Marshal(config{
		ResourcesFolder: getResourcesFolder(depth),
		TreeConfig:      treeConfig,
	})
	if err != nil {
		return nil, err
	}

	r.w, err = link.New(int(depth), configBytes)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *RLN) SetTree(treeHeight uint) error {
	success := r.w.SetTree(treeHeight)
	if !success {
		return errors.New("could not set tree height")
	}
	return nil
}

// Initialize merkle tree with a list of IDCommitments
func (r *RLN) InitTreeWithMembers(idComms []IDCommitment) error {
	idCommBytes := serializeCommitments(idComms)
	initSuccess := r.w.InitTreeWithLeaves(idCommBytes)
	if !initSuccess {
		return errors.New("could not init tree")
	}
	return nil
}

func toIdentityCredential(generatedKeys []byte, userMessageLimit uint32) (*IdentityCredential, error) {
	// add user message limit
	key := &IdentityCredential{
		IDTrapdoor:       [32]byte{},
		IDNullifier:      [32]byte{},
		IDSecretHash:     [32]byte{},
		IDCommitment:     [32]byte{},
		UserMessageLimit: userMessageLimit,
	}

	if len(generatedKeys) != 32*4 {
		return nil, errors.New("generated keys are of invalid length")
	}

	copy(key.IDTrapdoor[:], generatedKeys[:32])
	copy(key.IDNullifier[:], generatedKeys[32:64])
	copy(key.IDSecretHash[:], generatedKeys[64:96])
	copy(key.IDCommitment[:], generatedKeys[96:128])

	return key, nil
}

// MembershipKeyGen generates a IdentityCredential that can be used for the
// registration into the rln membership contract. Returns an error if the key generation fails
// Accepts an optional parameter that sets the user message limit which defaults
// to DEFAULT_USER_MESSAGE_LIMIT
func (r *RLN) MembershipKeyGen(params ...uint32) (*IdentityCredential, error) {
	var userMessageLimit uint32
	if len(params) == 1 {
		userMessageLimit = params[0]
	} else if len(params) == 0 {
		userMessageLimit = DEFAULT_USER_MESSAGE_LIMIT
	} else {
		return nil, errors.New("just one user message limit is allowed")
	}

	generatedKeys := r.w.ExtendedKeyGen()
	if generatedKeys == nil {
		return nil, errors.New("error in key generation")
	}
	return toIdentityCredential(generatedKeys, userMessageLimit)
}

// SeededMembershipKeyGen generates a deterministic IdentityCredential using a seed
// that can be used for the registration into the rln membership contract.
// Returns an error if the key generation fails
// Accepts an optional parameter that sets the user message limit which defaults
// to DEFAULT_USER_MESSAGE_LIMIT
func (r *RLN) SeededMembershipKeyGen(seed []byte, params ...uint32) (*IdentityCredential, error) {
	var userMessageLimit uint32
	if len(params) == 1 {
		userMessageLimit = params[0]
	} else if len(params) == 0 {
		userMessageLimit = DEFAULT_USER_MESSAGE_LIMIT
	} else {
		return nil, errors.New("just one user message limit is allowed")
	}

	generatedKeys := r.w.ExtendedSeededKeyGen(seed)
	if generatedKeys == nil {
		return nil, errors.New("error in key generation")
	}
	return toIdentityCredential(generatedKeys, userMessageLimit)
}

// appendLength returns length prefixed version of the input with the following format
// [len<8>|input<var>], the len is a 8 byte value serialized in little endian
func appendLength(input []byte) []byte {
	inputLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(inputLen, uint64(len(input)))
	return append(inputLen, input...)
}

// Similar to appendLength but for 32 byte values. The length that is prepended is
// the length of elements that are 32 bytes long each
func appendLength32(input []byte) []byte {
	inputLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(inputLen, uint64(len(input)/32))
	return append(inputLen, input...)
}

func (r *RLN) Sha256(data []byte) (MerkleNode, error) {
	lenPrefData := appendLength(data)

	b, err := r.w.Hash(lenPrefData)
	if err != nil {
		return MerkleNode{}, err
	}

	var result MerkleNode
	copy(result[:], b)

	return result, nil
}

func (r *RLN) Poseidon(input ...[]byte) (MerkleNode, error) {
	data := serializeSlice(input)

	inputLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(inputLen, uint64(len(input)))

	lenPrefData := append(inputLen, data...)

	b, err := r.w.PoseidonHash(lenPrefData)
	if err != nil {
		return MerkleNode{}, err
	}

	var result MerkleNode
	copy(result[:], b)

	return result, nil
}

// GenerateProof generates a proof for the RLN given a KeyPair and the index in a merkle tree.
// The output will containt the proof data and should be parsed as |proof<128>|root<32>|epoch<32>|share_x<32>|share_y<32>|nullifier<32>|
// integers wrapped in <> indicate value sizes in bytes
func (r *RLN) GenerateProof(
	data []byte,
	key IdentityCredential,
	index MembershipIndex,
	epoch Epoch,
	messageId uint32) (*RateLimitProof, error) {

	externalNullifierInput, err := r.Poseidon(epoch[:], RLN_IDENTIFIER[:])
	if err != nil {
		return nil, fmt.Errorf("could not construct the external nullifier: %w", err)
	}

	input := serialize(key.IDSecretHash, index, key.UserMessageLimit, messageId, externalNullifierInput, data)
	proofBytes, err := r.w.GenerateRLNProof(input)
	if err != nil {
		return nil, err
	}

	if len(proofBytes) != 288 {
		return nil, fmt.Errorf("invalid proof generated. size: %d expected: 288",
			len(proofBytes))
	}

	// parse proof taken from: https://github.com/vacp2p/zerokit/blob/v0.5.0/rln/src/public.rs#L750
	// [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
	proofOffset := 128
	rootOffset := proofOffset + 32
	externalNullifierOffset := rootOffset + 32
	shareXOffset := externalNullifierOffset + 32
	shareYOffset := shareXOffset + 32
	nullifierOffset := shareYOffset + 32

	var zkproof ZKSNARK
	var proofRoot, shareX, shareY MerkleNode
	var externalNullifier Nullifier
	var nullifier Nullifier

	copy(zkproof[:], proofBytes[0:proofOffset])
	copy(proofRoot[:], proofBytes[proofOffset:rootOffset])
	copy(externalNullifier[:], proofBytes[rootOffset:externalNullifierOffset])
	copy(shareX[:], proofBytes[externalNullifierOffset:shareXOffset])
	copy(shareY[:], proofBytes[shareXOffset:shareYOffset])
	copy(nullifier[:], proofBytes[shareYOffset:nullifierOffset])

	return &RateLimitProof{
		Proof:             zkproof,
		MerkleRoot:        proofRoot,
		ExternalNullifier: externalNullifier,
		ShareX:            shareX,
		ShareY:            shareY,
		Nullifier:         nullifier,
	}, nil
}

// Returns a RLN proof with a custom witness, so no tree is required in the RLN instance
// to calculate such proof. The witness can be created with GetMerkleProof data
// input [ id_secret_hash<32> | num_elements<8> | path_elements<var1> | num_indexes<8> | path_indexes<var2> | x<32> | epoch<32> | rln_identifier<32> ]
// output [ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]
func (r *RLN) GenerateRLNProofWithWitness(witness RLNWitnessInput) (*RateLimitProof, error) {
	// TODO: Will be implemented once custom witness is supported in RLN v2
	return nil, errors.New("not implemented")

	proofBytes, err := r.w.GenerateRLNProofWithWitness(witness.serialize())
	if err != nil {
		return nil, err
	}

	if len(proofBytes) != 320 {
		return nil, errors.New("invalid proof generated")
	}

	// parse the proof as [ proof<128> | root<32> | epoch<32> | share_x<32> | share_y<32> | nullifier<32> | rln_identifier<32> ]
	proofOffset := 128
	rootOffset := proofOffset + 32
	epochOffset := rootOffset + 32
	shareXOffset := epochOffset + 32
	shareYOffset := shareXOffset + 32
	nullifierOffset := shareYOffset + 32
	rlnIdentifierOffset := nullifierOffset + 32

	var zkproof ZKSNARK
	var proofRoot, shareX, shareY MerkleNode
	var epochR Epoch
	var nullifier Nullifier
	var rlnIdentifier RLNIdentifier

	copy(zkproof[:], proofBytes[0:proofOffset])
	copy(proofRoot[:], proofBytes[proofOffset:rootOffset])
	copy(epochR[:], proofBytes[rootOffset:epochOffset])
	copy(shareX[:], proofBytes[epochOffset:shareXOffset])
	copy(shareY[:], proofBytes[shareXOffset:shareYOffset])
	copy(nullifier[:], proofBytes[shareYOffset:nullifierOffset])
	copy(rlnIdentifier[:], proofBytes[nullifierOffset:rlnIdentifierOffset])

	return &RateLimitProof{
		Proof:      zkproof,
		MerkleRoot: proofRoot,
		ShareX:     shareX,
		ShareY:     shareY,
		Nullifier:  nullifier,
	}, nil

}

func serialize32(roots [][32]byte) []byte {
	var result []byte
	for _, r := range roots {
		result = append(result, r[:]...)
	}
	return result
}

func serializeSlice(roots [][]byte) []byte {
	var result []byte
	for _, r := range roots {
		result = append(result, r[:]...)
	}
	return result
}

func serializeCommitments(commitments []IDCommitment) []byte {
	// serializes a seq of IDCommitments to a byte seq
	// the serialization is based on https://github.com/status-im/nwaku/blob/37bd29fbc37ce5cf636734e7dd410b1ed27b88c8/waku/v2/protocol/waku_rln_relay/rln.nim#L142
	// the order of serialization is |id_commitment_len<8>|id_commitment<var>|
	var result []byte

	inputLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(inputLen, uint64(len(commitments)))
	result = append(result, inputLen...)

	for _, idComm := range commitments {
		result = append(result, idComm[:]...)
	}

	return result
}

func serializeIndices(indices []MembershipIndex) []byte {
	var result []byte

	inputLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(inputLen, uint64(len(indices)))
	result = append(result, inputLen...)

	for _, index := range indices {
		result = binary.LittleEndian.AppendUint64(result, uint64(index))
	}

	return result
}

// proof [ proof<128>| root<32>| epoch<32>| share_x<32>| share_y<32>| nullifier<32> | signal_len<8> | signal<var> ]
// validRoots should contain a sequence of roots in the acceptable windows.
// As default, it is set to an empty sequence of roots. This implies that the validity check for the proof's root is skipped
func (r *RLN) Verify(data []byte, proof RateLimitProof, roots ...[32]byte) (bool, error) {
	proofBytes := proof.serializeWithData(data)
	rootBytes := serialize32(roots)

	res, err := r.w.VerifyWithRoots(proofBytes, rootBytes)
	if err != nil {
		return false, err
	}

	return res, nil
}

// RecoverIDSecret returns an IDSecret having obtained before two proofs
func (r *RLN) RecoverIDSecret(proof1 RateLimitProof, proof2 RateLimitProof) (IDSecretHash, error) {
	proof1Bytes := proof1.serialize()
	proof2Bytes := proof2.serialize()
	secret, err := r.w.RecoverIDSecret(proof1Bytes, proof2Bytes)
	if err != nil {
		return IDSecretHash{}, err
	}
	var result IDSecretHash
	copy(result[:], secret)
	return result, nil
}

// InsertMember adds the member to the tree. The leaf is made of
// the id commitment and the user message limit
func (r *RLN) InsertMember(idComm IDCommitment, userMessageLimit uint32) error {
	userMessageLimitBytes := SerializeUint32(userMessageLimit)

	hashedLeaf, err := r.Poseidon(idComm[:], userMessageLimitBytes[:])
	if err != nil {
		return err
	}

	insertionSuccess := r.w.SetNextLeaf(hashedLeaf[:])
	if !insertionSuccess {
		return errors.New("could not insert member")
	}
	return nil
}

// Insert multiple members i.e., identity commitments starting from index
// This proc is atomic, i.e., if any of the insertions fails, all the previous insertions are rolled back
func (r *RLN) InsertMembers(index MembershipIndex, idComms []IDCommitment) error {
	idCommBytes := serializeCommitments(idComms)
	indicesBytes := serializeIndices(nil)
	insertionSuccess := r.w.AtomicOperation(index, idCommBytes, indicesBytes)
	if !insertionSuccess {
		return errors.New("could not insert members")
	}
	return nil
}

// Insert a member in the tree at specified index
func (r *RLN) InsertMemberAt(index MembershipIndex, idComm IDCommitment) error {
	insertionSuccess := r.w.SetLeaf(index, idComm[:])
	if !insertionSuccess {
		return errors.New("could not insert member")
	}
	return nil
}

// DeleteMember removes an IDCommitment key from the tree. The index
// parameter is the position of the id commitment key to be deleted from the tree.
// The deleted id commitment key is replaced with a zero leaf
func (r *RLN) DeleteMember(index MembershipIndex) error {
	deletionSuccess := r.w.DeleteLeaf(index)
	if !deletionSuccess {
		return errors.New("could not delete member")
	}
	return nil
}

// Delete multiple members
func (r *RLN) DeleteMembers(indices []MembershipIndex) error {
	idCommBytes := serializeCommitments(nil)
	indicesBytes := serializeIndices(indices)
	insertionSuccess := r.w.AtomicOperation(0, idCommBytes, indicesBytes)
	if !insertionSuccess {
		return errors.New("could not insert members")
	}
	return nil
}

// GetMerkleRoot reads the Merkle Tree root after insertion
func (r *RLN) GetMerkleRoot() (MerkleNode, error) {
	b, err := r.w.GetRoot()
	if err != nil {
		return MerkleNode{}, err
	}

	if len(b) != 32 {
		return MerkleNode{}, errors.New("wrong output size")
	}

	var result MerkleNode
	copy(result[:], b)

	return result, nil
}

// GetLeaf reads the value stored at some index in the Merkle Tree
func (r *RLN) GetLeaf(index MembershipIndex) (IDCommitment, error) {
	b, err := r.w.GetLeaf(index)
	if err != nil {
		return IDCommitment{}, err
	}

	if len(b) != 32 {
		return IDCommitment{}, errors.New("wrong output size")
	}

	var result IDCommitment
	copy(result[:], b)

	return result, nil
}

// GetMerkleProof returns the Merkle proof for the element at the specified index
// The output should be parsed as: num_elements<8>|path_elements<var1>|num_indexes<8>|path_indexes<var2>
// where num_elements indicate var1 array size and num_indexes indicate var2 array size.
// Both num_elements and num_indexes shall be equal and match the tree depth.
// A tree with depth 20 has 676 bytes = 8 + 32 * 20 + 8 + 20 * 1
// Proof elements are stored as little endian
func (r *RLN) GetMerkleProof(index MembershipIndex) (MerkleProof, error) {
	proofBytes, err := r.w.GetMerkleProof(index)
	if err != nil {
		return MerkleProof{}, err
	}

	var result MerkleProof
	err = result.deserialize(proofBytes)
	if err != nil {
		return MerkleProof{}, err
	}

	return result, nil
}

// AddAll adds members to the Merkle tree
func (r *RLN) AddAll(list []IdentityCredential) error {
	for _, member := range list {
		if err := r.InsertMember(member.IDCommitment, member.UserMessageLimit); err != nil {
			return err
		}
	}
	return nil
}

// CalcMerkleRoot returns the root of the Merkle tree that is computed from the supplied list
func CalcMerkleRoot(list []IDCommitment) (MerkleNode, error) {
	rln, err := NewRLN()
	if err != nil {
		return MerkleNode{}, err
	}

	if err := rln.InsertMembers(0, list); err != nil {
		return MerkleNode{}, err
	}

	return rln.GetMerkleRoot()
}

// CreateMembershipList produces a list of membership key pairs and also returns the root of a Merkle tree constructed
// out of the identity commitment keys of the generated list. The output of this function is used to initialize a static
// group keys (to test waku-rln-relay in the off-chain mode)
func CreateMembershipList(n int) ([]IdentityCredential, MerkleNode, error) {
	// initialize a Merkle tree
	rln, err := NewRLN()
	if err != nil {
		return nil, MerkleNode{}, err
	}

	var output []IdentityCredential
	for i := 0; i < n; i++ {
		// generate a keypair
		keypair, err := rln.MembershipKeyGen()
		if err != nil {
			return nil, MerkleNode{}, err
		}

		output = append(output, *keypair)

		// insert the key to the Merkle tree
		if err := rln.InsertMember(keypair.IDCommitment, keypair.UserMessageLimit); err != nil {
			return nil, MerkleNode{}, err
		}
	}

	root, err := rln.GetMerkleRoot()
	if err != nil {
		return nil, MerkleNode{}, err
	}

	return output, root, nil
}

// SetMetadata stores serialized data
func (r *RLN) SetMetadata(metadata []byte) error {
	success := r.w.SetMetadata(metadata)
	if !success {
		return errors.New("could not set metadata")
	}
	return nil
}

// GetMetadata returns the stored serialized metadata
func (r *RLN) GetMetadata() ([]byte, error) {
	return r.w.GetMetadata()
}

// AtomicOperation can be used to insert and remove elements into the merkle tree
func (r *RLN) AtomicOperation(index MembershipIndex, idCommsToInsert []IDCommitment, indicesToRemove []MembershipIndex) error {
	idCommBytes := serializeCommitments(idCommsToInsert)
	indicesBytes := serializeIndices(indicesToRemove)
	execSuccess := r.w.AtomicOperation(index, idCommBytes, indicesBytes)
	if !execSuccess {
		return errors.New("could not execute atomic_operation")
	}
	return nil
}

// Flush
func (r *RLN) Flush() error {
	success := r.w.Flush()
	if !success {
		return errors.New("cannot flush db")
	}
	return nil
}

// LeavesSet indicates how many elements have been inserted in the merkle tree
func (r *RLN) LeavesSet() uint {
	return r.w.LeavesSet()
}
