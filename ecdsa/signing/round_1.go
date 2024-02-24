package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/blocktree/gg20-lib-alpha/crypto"
	"github.com/blocktree/gg20-lib-alpha/crypto/commitments"
	"github.com/blocktree/gg20-lib-alpha/crypto/mta"
	"github.com/blocktree/gg20-lib-alpha/ecdsa/keygen"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the signing part of the GG18 ECDSA GG20 spec (Gennaro, Goldfeder; 2018)
func newRound1(params *gg20.Parameters, key *keygen.LocalPartySaveData, data *SignatureData, temp *localTempData, out chan<- gg20.Message, end chan<- *SignatureData) gg20.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *gg20.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	if round.temp.m != nil &&
		round.temp.m.Cmp(gg20.EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index
	round.ok[i] = true

	gammaI := utils.GetRandomPositiveInt(gg20.EC().Params().N)
	kI := utils.GetRandomPositiveInt(gg20.EC().Params().N)
	round.temp.gammaI = gammaI
	round.temp.r5AbortData.GammaI = gammaI.Bytes()

	gammaIG := crypto.ScalarBaseMult(gg20.EC(), gammaI)
	round.temp.gammaIG = gammaIG

	cmt := commitments.NewHashCommitment(gammaIG.X(), gammaIG.Y())
	round.temp.deCommit = cmt.D

	// MtA round 1
	paiPK := round.key.PaillierPKs[i]
	cA, rA, err := paiPK.EncryptAndReturnRandomness(kI)
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// set "k"-related temporary variables, also used for identified aborts later in the protocol
	{
		kIBz := kI.Bytes()
		round.temp.KI = kIBz // now part of the OneRoundData struct
		round.temp.r5AbortData.KI = kIBz
		round.temp.r7AbortData.KI = kIBz
		round.temp.cAKI = cA // used for the ZK proof in round 5
		round.temp.rAKI = rA
		round.temp.r7AbortData.KRandI = rA.Bytes()
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		pi, err := mta.AliceInit(paiPK, kI, cA, rA, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, pi)
		round.temp.signRound1Message1s[i] = r1msg1
		round.temp.c1Is[j] = cA
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1Message2(round.PartyID(), cmt.C)
	round.temp.signRound1Message2s[i] = r1msg2
	round.out <- r1msg2
	return nil
}

func (round *round1) Update() (bool, *gg20.Error) {
	for j, msg1 := range round.temp.signRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg gg20.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() gg20.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index
	xi, ks, bigXs := round.key.Xi, round.key.Ks, round.key.BigXj
	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	if wI, bigWs, err := PrepareForSigning(i, len(ks), xi, ks, bigXs); err != nil {
		return err
	} else {
		round.temp.wI = wI
		round.temp.bigWs = bigWs
	}
	return nil
}
