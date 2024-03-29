package gg20

import (
	"errors"
	"fmt"
	"sync"

	"github.com/blocktree/gg20-lib-alpha/utils"
)

type Party interface {
	Start() *Error
	UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err *Error)
	Update(msg ParsedMessage) (ok bool, err *Error)
	Running() bool
	WaitingFor() []*PartyID
	ValidateMessage(msg ParsedMessage) (bool, *Error)
	StoreMessage(msg ParsedMessage) (bool, *Error)
	FirstRound() Round
	WrapError(err error, culprits ...*PartyID) *Error
	PartyID() *PartyID
	String() string

	setRound(Round) *Error
	round() Round
	advance()
	lock()
	unlock()
}

type BaseParty struct {
	mtx        sync.Mutex
	rnd        Round
	FirstRound Round
}

func (p *BaseParty) Running() bool {
	return p.rnd != nil
}

func (p *BaseParty) WaitingFor() []*PartyID {
	p.lock()
	defer p.unlock()
	if p.rnd == nil {
		return []*PartyID{}
	}
	return p.rnd.WaitingFor()
}

func (p *BaseParty) WrapError(err error, culprits ...*PartyID) *Error {
	if p.rnd == nil {
		return NewError(err, "", -1, nil, culprits...)
	}
	return p.rnd.WrapError(err, culprits...)
}

func (p *BaseParty) ValidateMessage(msg ParsedMessage) (bool, *Error) {
	if msg == nil || msg.Content() == nil {
		return false, p.WrapError(fmt.Errorf("received nil msg: %s", msg))
	}
	if msg.GetFrom() == nil || !msg.GetFrom().ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("received msg with an invalid sender: %s", msg))
	}
	if !msg.ValidateBasic() {
		return false, p.WrapError(fmt.Errorf("message failed ValidateBasic: %s", msg), msg.GetFrom())
	}
	return true, nil
}

func (p *BaseParty) String() string {
	return fmt.Sprintf("round: %d", p.round().RoundNumber())
}

func (p *BaseParty) setRound(round Round) *Error {
	if p.rnd != nil {
		return p.WrapError(errors.New("a round is already set on this party"))
	}
	p.rnd = round
	return nil
}

func (p *BaseParty) round() Round {
	return p.rnd
}

func (p *BaseParty) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseParty) lock() {
	p.mtx.Lock()
}

func (p *BaseParty) unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p Party, task string, prepare ...func(Round) *Error) *Error {
	p.lock()
	defer p.unlock()
	if p.PartyID() == nil || !p.PartyID().ValidateBasic() {
		return p.WrapError(fmt.Errorf("could not start. this party has an invalid PartyID: %+v", p.PartyID()))
	}
	if p.round() != nil {
		return p.WrapError(errors.New("could not start. this party is in an unexpected state. use the constructor and Start()"))
	}
	round := p.FirstRound()
	if err := p.setRound(round); err != nil {
		return err
	}
	if 1 < len(prepare) {
		return p.WrapError(errors.New("too many prepare functions given to Start(); 1 allowed"))
	}
	if len(prepare) == 1 {
		if err := prepare[0](round); err != nil {
			return err
		}
	}
	utils.Logger.Infof("party %s: %s round %d starting", p.round().Params().PartyID(), task, 1)
	defer func() {
		utils.Logger.Debugf("party %s: %s round %d finished", p.round().Params().PartyID(), task, 1)
	}()
	return p.round().Start()
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p Party, msg ParsedMessage, task string) (ok bool, err *Error) {
	// fast-fail on an invalid message; do not lock the mutex yet
	if _, err := p.ValidateMessage(msg); err != nil {
		return false, err
	}
	// lock the mutex. need this mtx unlock hook; L108 is recursive so cannot use defer
	r := func(ok bool, err *Error) (bool, *Error) {
		p.unlock()
		return ok, err
	}
	p.lock() // data is written to P state below
	utils.Logger.Debugf("party %s received message: %s", p.PartyID(), msg.String())
	if p.round() != nil {
		utils.Logger.Debugf("party %s round %d update: %s", p.PartyID(), p.round().RoundNumber(), msg.String())
	}
	if ok, err := p.StoreMessage(msg); err != nil || !ok {
		return r(false, err)
	}
	if p.round() != nil {
		utils.Logger.Debugf("party %s: %s round %d update", p.round().Params().PartyID(), task, p.round().RoundNumber())
		if _, err := p.round().Update(); err != nil {
			return r(false, err)
		}
		if p.round().CanProceed() {
			if p.advance(); p.round() != nil {
				if err := p.round().Start(); err != nil {
					return r(false, err)
				}
				rndNum := p.round().RoundNumber()
				utils.Logger.Infof("party %s: %s round %d started", p.round().Params().PartyID(), task, rndNum)
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				utils.Logger.Infof("party %s: %s finished!", p.PartyID(), task)
			}
			p.unlock()                      // recursive so can't defer after return
			return BaseUpdate(p, msg, task) // re-run round update or finish)
		}
		return r(true, nil)
	}
	return r(true, nil)
}
