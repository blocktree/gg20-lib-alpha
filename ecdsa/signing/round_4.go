package signing

import (
	"errors"

	"github.com/blocktree/gg20-lib-alpha/gg20"
)

func (round *round4) Start() *gg20.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	r4msg := NewSignRound4Message(Pi, round.temp.deCommit)
	round.temp.signRound4Messages[i] = r4msg
	round.out <- r4msg
	return nil
}

func (round *round4) Update() (bool, *gg20.Error) {
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round4) CanAccept(msg gg20.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) NextRound() gg20.Round {
	round.started = false
	return &round5{round}
}
