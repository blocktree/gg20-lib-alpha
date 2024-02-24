package commitments

import (
	"math/big"

	"github.com/blocktree/gg20-lib-alpha/utils"
)

const (
	HashLength = 256
)

type (
	HashCommitment   = *big.Int
	HashDeCommitment = []*big.Int

	HashCommitDecommit struct {
		C HashCommitment
		D HashDeCommitment
	}
)

func NewHashCommitmentWithRandomness(r *big.Int, secrets ...*big.Int) *HashCommitDecommit {
	parts := make([]*big.Int, len(secrets)+1)
	parts[0] = r
	for i := 1; i < len(parts); i++ {
		parts[i] = secrets[i-1]
	}
	hash := utils.SHA512_256i(parts...)

	cmt := &HashCommitDecommit{}
	cmt.C = hash
	cmt.D = parts
	return cmt
}

func NewHashCommitment(secrets ...*big.Int) *HashCommitDecommit {
	r := utils.MustGetRandomInt(HashLength) // r
	return NewHashCommitmentWithRandomness(r, secrets...)
}

func NewHashDeCommitmentFromBytes(marshalled [][]byte) HashDeCommitment {
	return utils.ByteSlicesToBigInts(marshalled)
}

func (cmt *HashCommitDecommit) Verify() bool {
	C, D := cmt.C, cmt.D
	if C == nil || D == nil {
		return false
	}
	hash := utils.SHA512_256i(D...)
	return hash.Cmp(C) == 0
}

func (cmt *HashCommitDecommit) DeCommit() (bool, HashDeCommitment) {
	if cmt.Verify() {
		// [1:] skips random element r in D
		return true, cmt.D[1:]
	} else {
		return false, nil
	}
}
