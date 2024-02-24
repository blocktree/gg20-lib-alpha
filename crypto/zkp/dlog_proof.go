package zkp

import (
	"errors"
	"math/big"

	"github.com/blocktree/gg20-lib-alpha/crypto"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

type (
	// Schnorr ZK of the discrete logarithm of pho_i such that A = g^pho (GG18)
	DLogProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
	}
)

// NewDLogProof constructs a new Schnorr ZK of the discrete logarithm of pho_i such that A = g^pho (GG18)
func NewDLogProof(x *big.Int, X *crypto.ECPoint) (*DLogProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("NewDLogProof received nil or invalid value(s)")
	}
	ecParams := gg20.EC().Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(gg20.EC(), ecParams.Gx, ecParams.Gy) // already on the curve.

	a := utils.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(gg20.EC(), a)

	var c *big.Int
	{
		cHash := utils.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
		c = utils.RejectionSample(q, cHash)
	}
	t := new(big.Int).Mul(c, x)
	t = utils.ModInt(q).Add(a, t)

	return &DLogProof{Alpha: alpha, T: t}, nil
}

// NewDLogProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *DLogProof) Verify(X *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() {
		return false
	}
	ecParams := gg20.EC().Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(gg20.EC(), ecParams.Gx, ecParams.Gy)

	var c *big.Int
	{
		cHash := utils.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
		c = utils.RejectionSample(q, cHash)
	}
	tG := crypto.ScalarBaseMult(gg20.EC(), pf.T)
	Xc := X.ScalarMult(c)
	aXc, err := pf.Alpha.Add(Xc)
	if err != nil {
		return false
	}
	if aXc.X().Cmp(tG.X()) != 0 || aXc.Y().Cmp(tG.Y()) != 0 {
		return false
	}
	return true
}

func (pf *DLogProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil && pf.Alpha.ValidateBasic()
}
