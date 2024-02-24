package keygen

import (
	"errors"

	"github.com/blocktree/gg20-lib-alpha/crypto/paillier"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

func (round *round4) Start() *gg20.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	PIDs := Ps.Keys()
	ecdsaPub := round.save.ECDSAPub

	// 1-3. (concurrent)
	// r3 messages are assumed to be available and != nil in this function
	r3msgs := round.temp.keyGenRound3Messages
	chs := make([]chan bool, len(r3msgs))
	for i := range chs {
		chs[i] = make(chan bool)
	}
	for j, msg := range round.temp.keyGenRound3Messages {
		if j == i {
			continue
		}
		r3msg := msg.Content().(*KeyGenRound3Message)
		go func(prf paillier.Proof, j int, ch chan<- bool) {
			ppk := round.save.PaillierPKs[j]
			ok, err := prf.Verify(ppk.N, PIDs[j], ecdsaPub)
			if err != nil {
				utils.Logger.Error(round.WrapError(err, Ps[j]).Error())
				ch <- false
				return
			}
			ch <- ok
		}(r3msg.UnmarshalProofInts(), j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)
	for j, ch := range chs {
		if j == i {
			round.ok[j] = true
			continue
		}
		round.ok[j] = <-ch
	}
	culprits := make([]*gg20.PartyID, 0, len(Ps)) // who caused the error(s)
	for j, ok := range round.ok {
		if !ok {
			culprits = append(culprits, Ps[j])
			utils.Logger.Warnf("paillier verify failed for party %s", Ps[j])
			continue
		}
		utils.Logger.Debugf("paillier verify passed for party %s", Ps[j])

	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}

	round.end <- *round.save

	return nil
}

func (round *round4) CanAccept(msg gg20.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *gg20.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() gg20.Round {
	return nil // finished!
}
