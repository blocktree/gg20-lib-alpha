package signing

import (
	"errors"
	"math/big"

	"github.com/blocktree/gg20-lib-alpha/crypto"
	cmt "github.com/blocktree/gg20-lib-alpha/crypto/commitments"
	"github.com/blocktree/gg20-lib-alpha/crypto/mta"
	"github.com/blocktree/gg20-lib-alpha/crypto/zkp"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []gg20.MessageContent{
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
		(*SignRound4Message)(nil),
		(*SignRound5Message)(nil),
		(*SignRound6Message)(nil),
		(*SignRound7Message)(nil),
	}
)

// ----- //

func NewSignRound1Message1(
	to, from *gg20.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		To:          []*gg20.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := proof.Bytes()
	content := &SignRound1Message1{
		C:               c.Bytes(),
		RangeProofAlice: pfBz[:],
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyBytes(m.GetC()) &&
		utils.NonEmptyMultiBytes(m.GetRangeProofAlice(), mta.RangeProofAliceBytesParts)
}

func (m *SignRound1Message1) UnmarshalC() *big.Int {
	return new(big.Int).SetBytes(m.GetC())
}

func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*mta.RangeProofAlice, error) {
	return mta.RangeProofAliceFromBytes(m.GetRangeProofAlice())
}

// ----- //

func NewSignRound1Message2(
	from *gg20.PartyID,
	commitment cmt.HashCommitment,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound1Message2) ValidateBasic() bool {
	return m.Commitment != nil &&
		utils.NonEmptyBytes(m.GetCommitment())
}

func (m *SignRound1Message2) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewSignRound2Message(
	to, from *gg20.PartyID,
	c1JI *big.Int,
	pi1JI *mta.ProofBob,
	c2JI *big.Int,
	pi2JI *mta.ProofBobWC,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		To:          []*gg20.PartyID{to},
		IsBroadcast: false,
	}
	pfBob := pi1JI.Bytes()
	pfBobWC := pi2JI.Bytes()
	content := &SignRound2Message{
		C1:         c1JI.Bytes(),
		C2:         c2JI.Bytes(),
		ProofBob:   pfBob[:],
		ProofBobWc: pfBobWC[:],
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyBytes(m.GetC1()) &&
		utils.NonEmptyBytes(m.GetC2()) &&
		utils.NonEmptyMultiBytes(m.GetProofBob(), mta.ProofBobBytesParts) &&
		utils.NonEmptyMultiBytes(m.GetProofBobWc(), mta.ProofBobWCBytesParts)
}

func (m *SignRound2Message) UnmarshalProofBob() (*mta.ProofBob, error) {
	return mta.ProofBobFromBytes(m.GetProofBob())
}

func (m *SignRound2Message) UnmarshalProofBobWC() (*mta.ProofBobWC, error) {
	return mta.ProofBobWCFromBytes(m.GetProofBobWc())
}

// ----- //

func NewSignRound3Message(
	from *gg20.PartyID,
	deltaI *big.Int,
	TI *crypto.ECPoint,
	tProof *zkp.TProof,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		DeltaI: deltaI.Bytes(),
		TI: &utils.ECPoint{
			X: TI.X().Bytes(),
			Y: TI.Y().Bytes(),
		},
		TProofAlpha: &utils.ECPoint{
			X: tProof.Alpha.X().Bytes(),
			Y: tProof.Alpha.Y().Bytes(),
		},
		TProofT: tProof.T.Bytes(),
		TProofU: tProof.U.Bytes(),
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	if m == nil ||
		m.GetTI() == nil ||
		!m.GetTI().ValidateBasic() ||
		!utils.NonEmptyBytes(m.GetDeltaI()) ||
		!utils.NonEmptyBytes(m.GetTProofT()) ||
		!utils.NonEmptyBytes(m.GetTProofU()) {
		return false
	}
	TI, err := m.UnmarshalTI()
	if err != nil {
		return false
	}
	tProof, err := m.UnmarshalTProof()
	if err != nil {
		return false
	}
	// we have everything we need to validate the TProof here!
	basePoint2, err := crypto.ECBasePoint2(gg20.EC())
	if err != nil {
		return false
	}
	return TI.ValidateBasic() && tProof.Verify(TI, basePoint2)
}

func (m *SignRound3Message) UnmarshalTI() (*crypto.ECPoint, error) {
	if m.GetTI() == nil || !m.GetTI().ValidateBasic() {
		return nil, errors.New("UnmarshalTI() X or Y coord is nil or did not validate")
	}
	return crypto.NewECPointFromProtobuf(m.GetTI())
}

func (m *SignRound3Message) UnmarshalTProof() (*zkp.TProof, error) {
	alpha, err := crypto.NewECPointFromProtobuf(m.GetTProofAlpha())
	if err != nil {
		return nil, err
	}
	return &zkp.TProof{
		Alpha: alpha,
		T:     new(big.Int).SetBytes(m.GetTProofT()),
		U:     new(big.Int).SetBytes(m.GetTProofU()),
	}, nil
}

// ----- //

func NewSignRound4Message(
	from *gg20.PartyID,
	deCommitment cmt.HashDeCommitment,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := utils.BigIntsToBytes(deCommitment)
	content := &SignRound4Message{
		DeCommitment: dcBzs,
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyMultiBytes(m.DeCommitment, 3)
}

func (m *SignRound4Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewSignRound5Message(
	from *gg20.PartyID,
	Ri *crypto.ECPoint,
	pdlwSlackPf *zkp.PDLwSlackProof,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs, err := pdlwSlackPf.Marshal()
	if err != nil {
		return nil
	}
	content := &SignRound5Message{
		RI:             Ri.ToProtobufPoint(),
		ProofPdlWSlack: pfBzs,
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound5Message) ValidateBasic() bool {
	if m == nil ||
		m.GetRI() == nil ||
		!m.GetRI().ValidateBasic() ||
		!utils.NonEmptyMultiBytes(m.GetProofPdlWSlack(), zkp.PDLwSlackMarshalledParts) {
		return false
	}
	RI, err := m.UnmarshalRI()
	if err != nil {
		return false
	}
	return RI.ValidateBasic()
}

func (m *SignRound5Message) UnmarshalRI() (*crypto.ECPoint, error) {
	return crypto.NewECPointFromProtobuf(m.GetRI())
}

func (m *SignRound5Message) UnmarshalPDLwSlackProof() (*zkp.PDLwSlackProof, error) {
	return zkp.UnmarshalPDLwSlackProof(m.GetProofPdlWSlack())
}

// ----- //

func NewSignRound6MessageSuccess(
	from *gg20.PartyID,
	sI *crypto.ECPoint,
	proof *zkp.STProof,

) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound6Message{
		Content: &SignRound6Message_Success{
			Success: &SignRound6Message_SuccessData{
				SI:           sI.ToProtobufPoint(),
				StProofAlpha: proof.Alpha.ToProtobufPoint(),
				StProofBeta:  proof.Beta.ToProtobufPoint(),
				StProofT:     proof.T.Bytes(),
				StProofU:     proof.U.Bytes(),
			},
		},
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func NewSignRound6MessageAbort(
	from *gg20.PartyID,
	data *SignRound6Message_AbortData,

) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	// this hack makes the ValidateBasic pass because the [i] index position for this P is empty in these arrays
	data.GetAlphaIJ()[from.Index] = []byte{1}
	data.GetBetaJI()[from.Index] = []byte{1}
	content := &SignRound6Message{
		Content: &SignRound6Message_Abort{Abort: data},
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound6Message) ValidateBasic() bool {
	if m == nil || m.GetContent() == nil {
		return false
	}
	switch c := m.GetContent().(type) {
	case *SignRound6Message_Success:
		if c.Success == nil ||
			c.Success.GetSI() == nil ||
			!c.Success.GetSI().ValidateBasic() ||
			c.Success.GetStProofAlpha() == nil ||
			c.Success.GetStProofBeta() == nil ||
			!c.Success.GetStProofAlpha().ValidateBasic() ||
			!c.Success.GetStProofBeta().ValidateBasic() ||
			!utils.NonEmptyBytes(c.Success.GetStProofT()) ||
			!utils.NonEmptyBytes(c.Success.GetStProofU()) {
			return false
		}
		sI, err := c.Success.UnmarshalSI()
		if err != nil {
			return false
		}
		tProof, err := c.Success.UnmarshalSTProof()
		if err != nil {
			return false
		}
		return sI.ValidateBasic() && tProof.ValidateBasic()
	case *SignRound6Message_Abort:
		return c.Abort != nil &&
			utils.NonEmptyBytes(c.Abort.GetKI()) &&
			utils.NonEmptyBytes(c.Abort.GetGammaI()) &&
			utils.NonEmptyMultiBytes(c.Abort.GetAlphaIJ()) &&
			utils.NonEmptyMultiBytes(c.Abort.GetBetaJI(), len(c.Abort.GetAlphaIJ()))
	default:
		return false
	}
}

func (m *SignRound6Message_SuccessData) UnmarshalSI() (*crypto.ECPoint, error) {
	return crypto.NewECPointFromProtobuf(m.GetSI())
}

func (m *SignRound6Message_SuccessData) UnmarshalSTProof() (*zkp.STProof, error) {
	alpha, err := crypto.NewECPointFromProtobuf(m.GetStProofAlpha())
	if err != nil {
		return nil, err
	}
	beta, err := crypto.NewECPointFromProtobuf(m.GetStProofBeta())
	if err != nil {
		return nil, err
	}
	return &zkp.STProof{
		Alpha: alpha,
		Beta:  beta,
		T:     new(big.Int).SetBytes(m.GetStProofT()),
		U:     new(big.Int).SetBytes(m.GetStProofU()),
	}, nil
}

// ----- //

func NewSignRound7MessageSuccess(
	from *gg20.PartyID,
	sI *big.Int,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound7Message{
		Content: &SignRound7Message_SI{SI: sI.Bytes()},
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func NewSignRound7MessageAbort(
	from *gg20.PartyID,
	data *SignRound7Message_AbortData,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	// this hack makes the ValidateBasic pass because the [i] index position for this P is empty in these arrays
	data.GetMuIJ()[from.Index] = []byte{1}
	data.GetMuRandIJ()[from.Index] = []byte{1}
	content := &SignRound7Message{
		Content: &SignRound7Message_Abort{Abort: data},
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *SignRound7Message) ValidateBasic() bool {
	if m == nil || m.GetContent() == nil {
		return false
	}
	switch c := m.GetContent().(type) {
	case *SignRound7Message_SI:
		return utils.NonEmptyBytes(c.SI)
	case *SignRound7Message_Abort:
		return c.Abort != nil &&
			utils.NonEmptyBytes(c.Abort.GetKI()) &&
			utils.NonEmptyBytes(c.Abort.GetKRandI()) &&
			utils.NonEmptyMultiBytes(c.Abort.GetMuIJ()) &&
			utils.NonEmptyMultiBytes(c.Abort.GetMuRandIJ(), len(c.Abort.GetMuIJ())) &&
			c.Abort.GetEcddhProofA1() != nil &&
			c.Abort.GetEcddhProofA1().ValidateBasic() &&
			c.Abort.GetEcddhProofA2() != nil &&
			c.Abort.GetEcddhProofA2().ValidateBasic() &&
			utils.NonEmptyBytes(c.Abort.GetEcddhProofZ())
	default:
		return false
	}
}

func (m *SignRound7Message_AbortData) UnmarshalSigmaIProof() (*zkp.ECDDHProof, error) {
	a1, err := crypto.NewECPointFromProtobuf(m.GetEcddhProofA1())
	if err != nil {
		return nil, err
	}
	a2, err := crypto.NewECPointFromProtobuf(m.GetEcddhProofA2())
	if err != nil {
		return nil, err
	}
	return &zkp.ECDDHProof{
		A1: a1,
		A2: a2,
		Z:  new(big.Int).SetBytes(m.GetEcddhProofZ()),
	}, nil
}
