package keygen

import (
	"errors"
	"fmt"
	"math/big"

	cmt "github.com/blocktree/gg20-lib-alpha/crypto/commitments"
	"github.com/blocktree/gg20-lib-alpha/crypto/vss"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

// Implements Party
// Implements Stringer
var _ gg20.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*gg20.BaseParty
		params *gg20.Parameters

		temp localTempData
		data LocalPartySaveData

		// outbound messaging
		out chan<- gg20.Message
		end chan<- LocalPartySaveData
	}

	localMessageStore struct {
		keyGenRound1Messages,
		keyGenRound2Message1s,
		keyGenRound2Message2s,
		keyGenRound3Messages []gg20.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after keygen)
		ui            *big.Int // used for tests
		KGCs          []cmt.HashCommitment
		vs            vss.Vs
		shares        vss.Shares
		deCommitPolyG cmt.HashDeCommitment
	}
)

func NewLocalParty(
	params *gg20.Parameters,
	out chan<- gg20.Message,
	end chan<- LocalPartySaveData,
	optionalPreParams ...LocalPreParams,
) gg20.Party {
	partyCount := params.PartyCount()
	data := NewLocalPartySaveData(partyCount)
	// when `optionalPreParams` is provided we'll use the pre-computed primes instead of generating them from scratch
	if 0 < len(optionalPreParams) {
		if 1 < len(optionalPreParams) {
			panic(errors.New("keygen.NewLocalParty expected 0 or 1 item in `optionalPreParams`"))
		}
		if !optionalPreParams[0].ValidateWithProof() {
			panic(errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of gg20-lib"))
		}
		data.LocalPreParams = optionalPreParams[0]
	}
	p := &LocalParty{
		BaseParty: new(gg20.BaseParty),
		params:    params,
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.keyGenRound1Messages = make([]gg20.ParsedMessage, partyCount)
	p.temp.keyGenRound2Message1s = make([]gg20.ParsedMessage, partyCount)
	p.temp.keyGenRound2Message2s = make([]gg20.ParsedMessage, partyCount)
	p.temp.keyGenRound3Messages = make([]gg20.ParsedMessage, partyCount)
	// temp data init
	p.temp.KGCs = make([]cmt.HashCommitment, partyCount)
	return p
}

func (p *LocalParty) FirstRound() gg20.Round {
	return newRound1(p.params, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *gg20.Error {
	return gg20.BaseStart(p, TaskName)
}

func (p *LocalParty) Update(msg gg20.ParsedMessage) (ok bool, err *gg20.Error) {
	return gg20.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *gg20.PartyID, isBroadcast bool) (bool, *gg20.Error) {
	msg, err := gg20.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg gg20.ParsedMessage) (bool, *gg20.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg gg20.ParsedMessage) (bool, *gg20.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *KeyGenRound1Message:
		p.temp.keyGenRound1Messages[fromPIdx] = msg
	case *KeyGenRound2Message1:
		p.temp.keyGenRound2Message1s[fromPIdx] = msg
	case *KeyGenRound2Message2:
		p.temp.keyGenRound2Message2s[fromPIdx] = msg
	case *KeyGenRound3Message:
		p.temp.keyGenRound3Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		utils.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

// recovers a party's original index in the set of parties during keygen
func (save LocalPartySaveData) OriginalIndex() (int, error) {
	index := -1
	ki := save.ShareID
	for j, kj := range save.Ks {
		if kj.Cmp(ki) != 0 {
			continue
		}
		index = j
		break
	}
	if index < 0 {
		return -1, errors.New("a party index could not be recovered from Ks")
	}
	return index, nil
}

func (p *LocalParty) PartyID() *gg20.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
