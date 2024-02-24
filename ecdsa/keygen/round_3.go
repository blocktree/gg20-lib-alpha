package keygen

import (
	"errors"
	"math/big"

	"github.com/hashicorp/go-multierror"
	errors2 "github.com/pkg/errors"

	"github.com/blocktree/gg20-lib-alpha/crypto"
	"github.com/blocktree/gg20-lib-alpha/crypto/commitments"
	"github.com/blocktree/gg20-lib-alpha/crypto/vss"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

func (round *round3) Start() *gg20.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	PIdx := round.PartyID().Index

	// 2-3.
	Vc := make(vss.Vs, round.Threshold()+1)
	for c := range Vc {
		Vc[c] = round.temp.vs[c] // ours
	}

	// 4-11.
	type vssOut struct {
		unWrappedErr error
		pjVs         vss.Vs
	}
	chs := make([]chan vssOut, len(Ps))
	for i := range chs {
		if i == PIdx {
			continue
		}
		chs[i] = make(chan vssOut)
	}
	for j := range Ps {
		if j == PIdx {
			continue
		}
		// 6-8.
		go func(j int, ch chan<- vssOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j]
			r2msg2 := round.temp.keyGenRound2Message2s[j].Content().(*KeyGenRound2Message2)
			KGDj := r2msg2.UnmarshalDeCommitment()
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjVs, err := crypto.UnFlattenECPoints(gg20.EC(), flatPolyGs)
			if err != nil {
				ch <- vssOut{err, nil}
				return
			}
			r2msg1 := round.temp.keyGenRound2Message1s[j].Content().(*KeyGenRound2Message1)
			PjShare := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     r2msg1.UnmarshalShare(),
			}
			if ok = PjShare.Verify(round.Threshold(), PjVs); !ok {
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			// (9) handled above
			ch <- vssOut{nil, PjVs}
		}(j, chs[j])
	}

	// 1,9. calculate xi (deferred for performance)
	modQ := utils.ModInt(gg20.EC().Params().N)
	xi := new(big.Int).Set(round.temp.shares[PIdx].Share)
	for j := range Ps {
		if j == PIdx {
			continue
		}
		r2msg1 := round.temp.keyGenRound2Message1s[j].Content().(*KeyGenRound2Message1)
		share := r2msg1.UnmarshalShare()
		xi = xi.Add(xi, share)
	}
	round.save.Xi = modQ.Add(xi, zero)

	// consume unbuffered channels (end the goroutines)
	vssResults := make([]vssOut, len(Ps))
	{
		culprits := make([]*gg20.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			vssResults[j] = <-chs[j]
			// collect culprits to error out with
			if err := vssResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			}
		}
		var multiErr error
		if len(culprits) > 0 {
			for _, vssResult := range vssResults {
				if vssResult.unWrappedErr == nil {
					continue
				}
				multiErr = multierror.Append(multiErr, vssResult.unWrappedErr)
			}
			return round.WrapError(multiErr, culprits...)
		}
	}
	{
		var err error
		culprits := make([]*gg20.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			// 10-11.
			PjVs := vssResults[j].pjVs
			for c := 0; c <= round.Threshold(); c++ {
				Vc[c], err = Vc[c].Add(PjVs[c])
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), culprits...)
		}
	}

	// 12-16. compute Xj for each Pj
	{
		var err error
		culprits := make([]*gg20.PartyID, 0, len(Ps)) // who caused the error(s)
		bigXj := round.save.BigXj
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.KeyInt()
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
			bigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
		round.save.BigXj = bigXj
	}

	// 17. compute and SAVE the ECDSA public key `y`
	ecdsaPubKey, err := crypto.NewECPoint(gg20.EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	utils.Logger.Debugf("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi
	ki := round.PartyID().KeyInt()
	proof := round.save.PaillierSK.Proof(ki, ecdsaPubKey)
	r3msg := NewKeyGenRound3Message(round.PartyID(), proof)
	round.temp.keyGenRound3Messages[PIdx] = r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) CanAccept(msg gg20.ParsedMessage) bool {
	if _, ok := msg.Content().(*KeyGenRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *gg20.Error) {
	for j, msg := range round.temp.keyGenRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() gg20.Round {
	round.started = false
	return &round4{round}
}
