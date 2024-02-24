package keygen

import (
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/blocktree/gg20-lib-alpha/gg20"
)

const (
	paillierBitsLen = 2048
)

func (round *round2) Start() *gg20.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	// 6. verify dln proofs, store r1 message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.keyGenRound1Messages)*2)
	dlnProof1FailCulprits := make([]*gg20.PartyID, len(round.temp.keyGenRound1Messages))
	dlnProof2FailCulprits := make([]*gg20.PartyID, len(round.temp.keyGenRound1Messages))
	wg := new(sync.WaitGroup)
	for j, msg := range round.temp.keyGenRound1Messages {
		r1msg := msg.Content().(*KeyGenRound1Message)
		H1j, H2j, NTildej, paillierPubKeyj :=
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalPaillierPK()

		if paillierPubKeyj.N.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("got paillier modulus with insufficient bits for this party"), msg.GetFrom())
		}

		if NTildej.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("got NTildej with insufficient bits for this party"), msg.GetFrom())
		}

		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		// the H1, H2 dupe check is disabled during some benchmarking scenarios to allow reuse of pre-params
		if !round.Params().UNSAFE_KGIgnoreH1H2Dupes() {
			h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
			if _, found := h1H2Map[h1JHex]; found {
				return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
			}
			if _, found := h1H2Map[h2JHex]; found {
				return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
			}
			h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}
		}
		wg.Add(2)
		go func(j int, msg gg20.ParsedMessage, r1msg *KeyGenRound1Message, H1j, H2j, NTildej *big.Int) {
			if dlnProof1, err := r1msg.UnmarshalDLNProof1(); err != nil || !dlnProof1.Verify(H1j, H2j, NTildej) {
				dlnProof1FailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, H1j, H2j, NTildej)
		go func(j int, msg gg20.ParsedMessage, r1msg *KeyGenRound1Message, H1j, H2j, NTildej *big.Int) {
			if dlnProof2, err := r1msg.UnmarshalDLNProof2(); err != nil || !dlnProof2.Verify(H2j, H1j, NTildej) {
				dlnProof2FailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, H1j, H2j, NTildej)
	}
	wg.Wait()
	for _, culprit := range append(dlnProof1FailCulprits, dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof verification failed"), culprit)
		}
	}
	// save NTilde_j, h1_j, h2_j, ...
	for j, msg := range round.temp.keyGenRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*KeyGenRound1Message)
		paillierPK, H1j, H2j, NTildej, KGC :=
			r1msg.UnmarshalPaillierPK(),
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalCommitment()
		round.save.PaillierPKs[j] = paillierPK // used in round 4
		round.save.NTildej[j] = NTildej
		round.save.H1j[j], round.save.H2j[j] = H1j, H2j
		round.temp.KGCs[j] = KGC
	}

	// 5. p2p send share ij to Pj
	shares := round.temp.shares
	for j, Pj := range round.Parties().IDs() {
		r2msg1 := NewKeyGenRound2Message1(Pj, round.PartyID(), shares[j])
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.keyGenRound2Message1s[j] = r2msg1
			continue
		}
		round.temp.keyGenRound2Message1s[i] = r2msg1
		round.out <- r2msg1
	}

	// 7. BROADCAST de-commitments of Shamir poly*G
	r2msg2 := NewKeyGenRound2Message2(round.PartyID(), round.temp.deCommitPolyG)
	round.temp.keyGenRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg gg20.ParsedMessage) bool {
	if _, ok := msg.Content().(*KeyGenRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KeyGenRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *gg20.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.keyGenRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.keyGenRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() gg20.Round {
	round.started = false
	return &round3{round}
}