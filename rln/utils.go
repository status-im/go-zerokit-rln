package rln

import (
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

func ToIdentityCredentials(groupKeys [][]string) ([]IdentityCredential, error) {
	// groupKeys is  sequence of membership key tuples in the form of (identity key, identity commitment) all in the hexadecimal format
	// the toIdentityCredentials proc populates a sequence of IdentityCredentials using the supplied groupKeys
	// Returns an error if the conversion fails

	var groupIdCredentials []IdentityCredential

	for _, gk := range groupKeys {
		idTrapdoor, err := ToBytes32LE(gk[0])
		if err != nil {
			return nil, err
		}

		idNullifier, err := ToBytes32LE(gk[1])
		if err != nil {
			return nil, err
		}

		idSecretHash, err := ToBytes32LE(gk[2])
		if err != nil {
			return nil, err
		}

		idCommitment, err := ToBytes32LE(gk[3])
		if err != nil {
			return nil, err
		}

		groupIdCredentials = append(groupIdCredentials, IdentityCredential{
			IDTrapdoor:   idTrapdoor,
			IDNullifier:  idNullifier,
			IDSecretHash: idSecretHash,
			IDCommitment: idCommitment,
		})
	}

	return groupIdCredentials, nil
}

func Bytes32(b []byte) [32]byte {
	var result [32]byte
	copy(result[32-len(b):], b)
	return result
}

func Bytes128(b []byte) [128]byte {
	var result [128]byte
	copy(result[128-len(b):], b)
	return result
}

func Flatten(b [][32]byte) []byte {
	result := make([]byte, len(b)*32)
	for i, v := range b {
		copy(result[i*32:(i+1)*32], v[:])
	}
	return result
}

func ToBytes32LE(hexStr string) ([32]byte, error) {

	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return [32]byte{}, err
	}

	bLen := len(b)
	for i := 0; i < bLen/2; i++ {
		b[i], b[bLen-i-1] = b[bLen-i-1], b[i]
	}

	return Bytes32(b), nil
}

func revert(b []byte) []byte {
	bLen := len(b)
	for i := 0; i < bLen/2; i++ {
		b[i], b[bLen-i-1] = b[bLen-i-1], b[i]
	}
	return b
}

// BigIntToBytes32 takes a *big.Int (which uses big endian) and converts it into a little endian 32 byte array
// Notice that is the *big.Int value contains an integer <= 2^248 - 1 (a 7 bytes value with all bits on), it will right-pad the result with 0s until
// the result has 32 bytes, i.e.:
// for a some bigInt whose `Bytes()` are {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}, using this function will return
// {0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
func BigIntToBytes32(value *big.Int) [32]byte {
	b := revert(value.Bytes())
	tmp := make([]byte, 32)
	copy(tmp[0:len(b)], b)
	return Bytes32(tmp)
}

// Bytes32ToBigInt takes a little endian 32 byte array and returns a *big.Int (which uses big endian)
func Bytes32ToBigInt(value [32]byte) *big.Int {
	b := revert(value[:])
	result := new(big.Int)
	result.SetBytes(b)
	return result
}

// Keccak functions take from here. To avoid unnecessary dependency to go-ethereum.
// https://github.com/ethereum/go-ethereum/blob/v1.13.11/crypto/crypto.go#L62-L84

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// Avoids multiple allocations if used frequently
var keccak256Pool = sync.Pool{New: func() interface{} {
	return NewKeccakState()
}}

// NewKeccakState creates a new KeccakState
func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak256().(KeccakState)
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	h, ok := keccak256Pool.Get().(KeccakState)
	if !ok {
		h = NewKeccakState()
	}
	defer keccak256Pool.Put(h)
	h.Reset()
	for _, b := range data {
		h.Write(b)
	}

	h.Read(b)
	return b
}

// Hashes a byte array to a field element in BN254, as used by zerokit.
// Equivalent to: https://github.com/vacp2p/zerokit/blob/v0.3.4/rln/src/hashers.rs
func HashToBN255(data []byte) [32]byte {
	// Hash is fixed to 32 bytes
	hashed := Keccak256(data[:])

	// Convert to field element
	var frBN254 fr.Element
	frBN254.Unmarshal(revert(hashed))
	frBN254Bytes := frBN254.Bytes()

	// Return fixed size
	fixexLen := [32]byte{}
	copy(fixexLen[:], revert(frBN254Bytes[:]))
	return fixexLen
}

func SerializeUint32(input uint32) [32]byte {
	var byte32Type [32]byte
	binary.LittleEndian.PutUint32(byte32Type[0:], input)

	return byte32Type
}
