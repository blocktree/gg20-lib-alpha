package signing

import (
	"github.com/blocktree/gg20-lib-alpha/ecdsa/keygen"
	"github.com/blocktree/gg20-lib-alpha/gg20"
)

const (
	TaskName = "signing"
)

type (
	base struct {
		*gg20.Parameters
		key     *keygen.LocalPartySaveData
		data    *SignatureData
		temp    *localTempData
		out     chan<- gg20.Message
		end     chan<- *SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5

		// Trigger for when a consistency check fails during Phase 5 of the protocol, resulting in a Type 5 identifiable abort (GG20)
		abortingT5 bool
	}
	// The final round for the one-round signing mode (see the README)
	round7 struct {
		*round6

		// Trigger for when a consistency check fails during Phase 6 of the protocol, resulting in a Type 7 identifiable abort (GG20)
		abortingT7 bool
	}
	finalization struct {
		*round7
	}
)

var (
	_ gg20.Round = (*round1)(nil)
	_ gg20.Round = (*round2)(nil)
	_ gg20.Round = (*round3)(nil)
	_ gg20.Round = (*round4)(nil)
	_ gg20.Round = (*round5)(nil)
	_ gg20.Round = (*round6)(nil)
	_ gg20.Round = (*round7)(nil)
	_ gg20.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *gg20.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*gg20.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*gg20.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*gg20.PartyID) *gg20.Error {
	return gg20.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}
