package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/blocktree/gg20-lib-alpha/crypto"
	cmt "github.com/blocktree/gg20-lib-alpha/crypto/commitments"
	"github.com/blocktree/gg20-lib-alpha/crypto/mta"
	"github.com/blocktree/gg20-lib-alpha/ecdsa/keygen"
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

		keys keygen.LocalPartySaveData
		temp localTempData
		data SignatureData

		// outbound messaging
		out chan<- gg20.Message
		end chan<- *SignatureData
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages,
		signRound4Messages,
		signRound5Messages,
		signRound6Messages,
		signRound7Messages []gg20.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		m,
		wI,
		cAKI,
		rAKI,
		deltaI,
		sigmaI,
		gammaI *big.Int
		c1Is     []*big.Int
		bigWs    []*crypto.ECPoint
		gammaIG  *crypto.ECPoint
		deCommit cmt.HashDeCommitment

		// round 2
		betas, // return value of Bob_mid
		c1JIs,
		c2JIs,
		vJIs []*big.Int // return value of Bob_mid_wc
		pI1JIs []*mta.ProofBob
		pI2JIs []*mta.ProofBobWC

		// round 3
		lI *big.Int

		// round 5
		bigGammaJs  []*crypto.ECPoint
		r5AbortData SignRound6Message_AbortData

		// round 6
		SignatureData_OneRoundData

		// round 7
		sI *big.Int
		rI,
		TI *crypto.ECPoint
		r7AbortData SignRound7Message_AbortData
	}
)

// Constructs a new ECDSA signing party. Note: msg may be left nil for one-round signing mode to only do the pre-processing steps.
func NewLocalParty(
	msg *big.Int,
	params *gg20.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- gg20.Message,
	end chan<- *SignatureData,
) gg20.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(gg20.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Message1s = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound5Messages = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound6Messages = make([]gg20.ParsedMessage, partyCount)
	p.temp.signRound7Messages = make([]gg20.ParsedMessage, partyCount)
	// temp data init
	p.temp.m = msg
	p.temp.c1Is = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1JIs = make([]*big.Int, partyCount)
	p.temp.c2JIs = make([]*big.Int, partyCount)
	p.temp.pI1JIs = make([]*mta.ProofBob, partyCount)
	p.temp.pI2JIs = make([]*mta.ProofBobWC, partyCount)
	p.temp.vJIs = make([]*big.Int, partyCount)
	p.temp.bigGammaJs = make([]*crypto.ECPoint, partyCount)
	p.temp.r5AbortData.AlphaIJ = make([][]byte, partyCount)
	p.temp.r5AbortData.BetaJI = make([][]byte, partyCount)
	return p
}

// Constructs a new ECDSA signing party for one-round signing. The final SignatureData struct will be a partial struct containing only the data for a final signing round (see the readme).
func NewLocalPartyWithOneRoundSign(
	params *gg20.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- gg20.Message,
	end chan<- *SignatureData,
) gg20.Party {
	return NewLocalParty(nil, params, key, out, end)
}

func (p *LocalParty) FirstRound() gg20.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *gg20.Error {
	return gg20.BaseStart(p, TaskName, func(round gg20.Round) *gg20.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
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
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
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
	case *SignRound1Message1:
		p.temp.signRound1Message1s[fromPIdx] = msg
	case *SignRound1Message2:
		p.temp.signRound1Message2s[fromPIdx] = msg
	case *SignRound2Message:
		p.temp.signRound2Messages[fromPIdx] = msg
	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg
	case *SignRound4Message:
		p.temp.signRound4Messages[fromPIdx] = msg
	case *SignRound5Message:
		p.temp.signRound5Messages[fromPIdx] = msg
	case *SignRound6Message:
		p.temp.signRound6Messages[fromPIdx] = msg
	case *SignRound7Message:
		p.temp.signRound7Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		utils.Logger.Warnf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *gg20.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
