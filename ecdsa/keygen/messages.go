package keygen

import (
	"math/big"

	cmt "github.com/blocktree/gg20-lib-alpha/crypto/commitments"
	"github.com/blocktree/gg20-lib-alpha/crypto/dlnp"
	"github.com/blocktree/gg20-lib-alpha/crypto/paillier"
	"github.com/blocktree/gg20-lib-alpha/crypto/vss"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []gg20.MessageContent{
		(*KeyGenRound1Message)(nil),
		(*KeyGenRound2Message1)(nil),
		(*KeyGenRound2Message2)(nil),
		(*KeyGenRound3Message)(nil),
	}
)

// ----- //

func NewKeyGenRound1Message(
	from *gg20.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
	dlnProof1, dlnProof2 *dlnp.Proof,
) (gg20.ParsedMessage, error) {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dlnProof1Bz, err := dlnProof1.Marshal()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Marshal()
	if err != nil {
		return nil, err
	}
	content := &KeyGenRound1Message{
		Commitment: ct.Bytes(),
		PaillierN:  paillierPK.N.Bytes(),
		NTilde:     nTildeI.Bytes(),
		H1:         h1I.Bytes(),
		H2:         h2I.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg), nil
}

func (m *KeyGenRound1Message) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyBytes(m.GetCommitment()) &&
		utils.NonEmptyBytes(m.GetPaillierN()) &&
		utils.NonEmptyBytes(m.GetNTilde()) &&
		utils.NonEmptyBytes(m.GetH1()) &&
		utils.NonEmptyBytes(m.GetH2()) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		utils.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnp.Iterations*2)) &&
		utils.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnp.Iterations*2))
}

func (m *KeyGenRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

func (m *KeyGenRound1Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KeyGenRound1Message) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KeyGenRound1Message) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KeyGenRound1Message) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KeyGenRound1Message) UnmarshalDLNProof1() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_1())
}

func (m *KeyGenRound1Message) UnmarshalDLNProof2() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_2())
}

// ----- //

func NewKeyGenRound2Message1(
	to, from *gg20.PartyID,
	share *vss.Share,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		To:          []*gg20.PartyID{to},
		IsBroadcast: false,
	}
	content := &KeyGenRound2Message1{
		Share: share.Share.Bytes(),
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *KeyGenRound2Message1) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyBytes(m.GetShare())
}

func (m *KeyGenRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

// ----- //

func NewKeyGenRound2Message2(
	from *gg20.PartyID,
	deCommitment cmt.HashDeCommitment,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := utils.BigIntsToBytes(deCommitment)
	content := &KeyGenRound2Message2{
		DeCommitment: dcBzs,
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *KeyGenRound2Message2) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyMultiBytes(m.GetDeCommitment())
}

func (m *KeyGenRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewKeyGenRound3Message(
	from *gg20.PartyID,
	proof paillier.Proof,
) gg20.ParsedMessage {
	meta := gg20.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs := make([][]byte, len(proof))
	for i := range pfBzs {
		if proof[i] == nil {
			continue
		}
		pfBzs[i] = proof[i].Bytes()
	}
	content := &KeyGenRound3Message{
		PaillierProof: pfBzs,
	}
	msg := gg20.NewMessageWrapper(meta, content)
	return gg20.NewMessage(meta, content, msg)
}

func (m *KeyGenRound3Message) ValidateBasic() bool {
	return m != nil &&
		utils.NonEmptyMultiBytes(m.GetPaillierProof(), paillier.ProofIters)
}

func (m *KeyGenRound3Message) UnmarshalProofInts() paillier.Proof {
	var pf paillier.Proof
	proofBzs := m.GetPaillierProof()
	for i := range pf {
		pf[i] = new(big.Int).SetBytes(proofBzs[i])
	}
	return pf
}
