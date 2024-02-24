package signing

import (
	reflect "reflect"
	sync "sync"

	common "github.com/blocktree/gg20-lib-alpha/utils"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// Represents a P2P message sent to each party during Phase 1 of the GG20 ECDSA GG20 signing protocol.
type SignRound1Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C               []byte   `protobuf:"bytes,1,opt,name=c,proto3" json:"c,omitempty"`
	RangeProofAlice [][]byte `protobuf:"bytes,2,rep,name=range_proof_alice,json=rangeProofAlice,proto3" json:"range_proof_alice,omitempty"`
}

func (x *SignRound1Message1) Reset() {
	*x = SignRound1Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message1) ProtoMessage() {}

func (x *SignRound1Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message1.ProtoReflect.Descriptor instead.
func (*SignRound1Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message1) GetC() []byte {
	if x != nil {
		return x.C
	}
	return nil
}

func (x *SignRound1Message1) GetRangeProofAlice() [][]byte {
	if x != nil {
		return x.RangeProofAlice
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Phase 1 of the GG20 ECDSA GG20 signing protocol.
type SignRound1Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment []byte `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *SignRound1Message2) Reset() {
	*x = SignRound1Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message2) ProtoMessage() {}

func (x *SignRound1Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message2.ProtoReflect.Descriptor instead.
func (*SignRound1Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{1}
}

func (x *SignRound1Message2) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

// Represents a P2P message sent to each party during Phase 2 of the GG20 ECDSA GG20 signing protocol.
type SignRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C1         []byte   `protobuf:"bytes,1,opt,name=c1,proto3" json:"c1,omitempty"`
	C2         []byte   `protobuf:"bytes,2,opt,name=c2,proto3" json:"c2,omitempty"`
	ProofBob   [][]byte `protobuf:"bytes,3,rep,name=proof_bob,json=proofBob,proto3" json:"proof_bob,omitempty"`
	ProofBobWc [][]byte `protobuf:"bytes,4,rep,name=proof_bob_wc,json=proofBobWc,proto3" json:"proof_bob_wc,omitempty"`
}

func (x *SignRound2Message) Reset() {
	*x = SignRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message) ProtoMessage() {}

func (x *SignRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message.ProtoReflect.Descriptor instead.
func (*SignRound2Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound2Message) GetC1() []byte {
	if x != nil {
		return x.C1
	}
	return nil
}

func (x *SignRound2Message) GetC2() []byte {
	if x != nil {
		return x.C2
	}
	return nil
}

func (x *SignRound2Message) GetProofBob() [][]byte {
	if x != nil {
		return x.ProofBob
	}
	return nil
}

func (x *SignRound2Message) GetProofBobWc() [][]byte {
	if x != nil {
		return x.ProofBobWc
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Phase 3 of the GG20 ECDSA GG20 signing protocol.
type SignRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeltaI      []byte          `protobuf:"bytes,1,opt,name=delta_i,json=deltaI,proto3" json:"delta_i,omitempty"`
	TI          *common.ECPoint `protobuf:"bytes,2,opt,name=t_i,json=tI,proto3" json:"t_i,omitempty"`
	TProofAlpha *common.ECPoint `protobuf:"bytes,3,opt,name=t_proof_alpha,json=tProofAlpha,proto3" json:"t_proof_alpha,omitempty"`
	TProofT     []byte          `protobuf:"bytes,4,opt,name=t_proof_t,json=tProofT,proto3" json:"t_proof_t,omitempty"`
	TProofU     []byte          `protobuf:"bytes,5,opt,name=t_proof_u,json=tProofU,proto3" json:"t_proof_u,omitempty"`
}

func (x *SignRound3Message) Reset() {
	*x = SignRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message) ProtoMessage() {}

func (x *SignRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message.ProtoReflect.Descriptor instead.
func (*SignRound3Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{3}
}

func (x *SignRound3Message) GetDeltaI() []byte {
	if x != nil {
		return x.DeltaI
	}
	return nil
}

func (x *SignRound3Message) GetTI() *common.ECPoint {
	if x != nil {
		return x.TI
	}
	return nil
}

func (x *SignRound3Message) GetTProofAlpha() *common.ECPoint {
	if x != nil {
		return x.TProofAlpha
	}
	return nil
}

func (x *SignRound3Message) GetTProofT() []byte {
	if x != nil {
		return x.TProofT
	}
	return nil
}

func (x *SignRound3Message) GetTProofU() []byte {
	if x != nil {
		return x.TProofU
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Phase 4 of the GG20 ECDSA GG20 signing protocol.
type SignRound4Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DeCommitment [][]byte `protobuf:"bytes,1,rep,name=de_commitment,json=deCommitment,proto3" json:"de_commitment,omitempty"`
}

func (x *SignRound4Message) Reset() {
	*x = SignRound4Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound4Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound4Message) ProtoMessage() {}

func (x *SignRound4Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound4Message.ProtoReflect.Descriptor instead.
func (*SignRound4Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{4}
}

func (x *SignRound4Message) GetDeCommitment() [][]byte {
	if x != nil {
		return x.DeCommitment
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Phase 5 of the GG20 ECDSA GG20 signing protocol.
type SignRound5Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RI             *common.ECPoint `protobuf:"bytes,1,opt,name=r_i,json=rI,proto3" json:"r_i,omitempty"`
	ProofPdlWSlack [][]byte        `protobuf:"bytes,2,rep,name=proof_pdl_w_slack,json=proofPdlWSlack,proto3" json:"proof_pdl_w_slack,omitempty"`
}

func (x *SignRound5Message) Reset() {
	*x = SignRound5Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound5Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound5Message) ProtoMessage() {}

func (x *SignRound5Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound5Message.ProtoReflect.Descriptor instead.
func (*SignRound5Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{5}
}

func (x *SignRound5Message) GetRI() *common.ECPoint {
	if x != nil {
		return x.RI
	}
	return nil
}

func (x *SignRound5Message) GetProofPdlWSlack() [][]byte {
	if x != nil {
		return x.ProofPdlWSlack
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Phase 6 of the GG20 ECDSA GG20 signing protocol.
type SignRound6Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Content:
	//	*SignRound6Message_Success
	//	*SignRound6Message_Abort
	Content isSignRound6Message_Content `protobuf_oneof:"content"`
}

func (x *SignRound6Message) Reset() {
	*x = SignRound6Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound6Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound6Message) ProtoMessage() {}

func (x *SignRound6Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound6Message.ProtoReflect.Descriptor instead.
func (*SignRound6Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{6}
}

func (m *SignRound6Message) GetContent() isSignRound6Message_Content {
	if m != nil {
		return m.Content
	}
	return nil
}

func (x *SignRound6Message) GetSuccess() *SignRound6Message_SuccessData {
	if x, ok := x.GetContent().(*SignRound6Message_Success); ok {
		return x.Success
	}
	return nil
}

func (x *SignRound6Message) GetAbort() *SignRound6Message_AbortData {
	if x, ok := x.GetContent().(*SignRound6Message_Abort); ok {
		return x.Abort
	}
	return nil
}

type isSignRound6Message_Content interface {
	isSignRound6Message_Content()
}

type SignRound6Message_Success struct {
	Success *SignRound6Message_SuccessData `protobuf:"bytes,1,opt,name=success,proto3,oneof"`
}

type SignRound6Message_Abort struct {
	Abort *SignRound6Message_AbortData `protobuf:"bytes,2,opt,name=abort,proto3,oneof"`
}

func (*SignRound6Message_Success) isSignRound6Message_Content() {}

func (*SignRound6Message_Abort) isSignRound6Message_Content() {}

// Represents a BROADCAST message sent to all parties during online mode Phase 7 of the GG20 ECDSA GG20 signing protocol.
type SignRound7Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Content:
	//	*SignRound7Message_SI
	//	*SignRound7Message_Abort
	Content isSignRound7Message_Content `protobuf_oneof:"content"`
}

func (x *SignRound7Message) Reset() {
	*x = SignRound7Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound7Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound7Message) ProtoMessage() {}

func (x *SignRound7Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound7Message.ProtoReflect.Descriptor instead.
func (*SignRound7Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{7}
}

func (m *SignRound7Message) GetContent() isSignRound7Message_Content {
	if m != nil {
		return m.Content
	}
	return nil
}

func (x *SignRound7Message) GetSI() []byte {
	if x, ok := x.GetContent().(*SignRound7Message_SI); ok {
		return x.SI
	}
	return nil
}

func (x *SignRound7Message) GetAbort() *SignRound7Message_AbortData {
	if x, ok := x.GetContent().(*SignRound7Message_Abort); ok {
		return x.Abort
	}
	return nil
}

type isSignRound7Message_Content interface {
	isSignRound7Message_Content()
}

type SignRound7Message_SI struct {
	SI []byte `protobuf:"bytes,1,opt,name=s_i,json=sI,proto3,oneof"`
}

type SignRound7Message_Abort struct {
	Abort *SignRound7Message_AbortData `protobuf:"bytes,2,opt,name=abort,proto3,oneof"`
}

func (*SignRound7Message_SI) isSignRound7Message_Content() {}

func (*SignRound7Message_Abort) isSignRound7Message_Content() {}

type SignRound6Message_SuccessData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SI           *common.ECPoint `protobuf:"bytes,1,opt,name=s_i,json=sI,proto3" json:"s_i,omitempty"`
	StProofAlpha *common.ECPoint `protobuf:"bytes,2,opt,name=st_proof_alpha,json=stProofAlpha,proto3" json:"st_proof_alpha,omitempty"`
	StProofBeta  *common.ECPoint `protobuf:"bytes,3,opt,name=st_proof_beta,json=stProofBeta,proto3" json:"st_proof_beta,omitempty"`
	StProofT     []byte          `protobuf:"bytes,4,opt,name=st_proof_t,json=stProofT,proto3" json:"st_proof_t,omitempty"`
	StProofU     []byte          `protobuf:"bytes,5,opt,name=st_proof_u,json=stProofU,proto3" json:"st_proof_u,omitempty"`
}

func (x *SignRound6Message_SuccessData) Reset() {
	*x = SignRound6Message_SuccessData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound6Message_SuccessData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound6Message_SuccessData) ProtoMessage() {}

func (x *SignRound6Message_SuccessData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound6Message_SuccessData.ProtoReflect.Descriptor instead.
func (*SignRound6Message_SuccessData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{6, 0}
}

func (x *SignRound6Message_SuccessData) GetSI() *common.ECPoint {
	if x != nil {
		return x.SI
	}
	return nil
}

func (x *SignRound6Message_SuccessData) GetStProofAlpha() *common.ECPoint {
	if x != nil {
		return x.StProofAlpha
	}
	return nil
}

func (x *SignRound6Message_SuccessData) GetStProofBeta() *common.ECPoint {
	if x != nil {
		return x.StProofBeta
	}
	return nil
}

func (x *SignRound6Message_SuccessData) GetStProofT() []byte {
	if x != nil {
		return x.StProofT
	}
	return nil
}

func (x *SignRound6Message_SuccessData) GetStProofU() []byte {
	if x != nil {
		return x.StProofU
	}
	return nil
}

type SignRound6Message_AbortData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KI      []byte   `protobuf:"bytes,1,opt,name=k_i,json=kI,proto3" json:"k_i,omitempty"`
	GammaI  []byte   `protobuf:"bytes,3,opt,name=gamma_i,json=gammaI,proto3" json:"gamma_i,omitempty"`
	AlphaIJ [][]byte `protobuf:"bytes,4,rep,name=alpha_i_j,json=alphaIJ,proto3" json:"alpha_i_j,omitempty"`
	BetaJI  [][]byte `protobuf:"bytes,5,rep,name=beta_j_i,json=betaJI,proto3" json:"beta_j_i,omitempty"`
}

func (x *SignRound6Message_AbortData) Reset() {
	*x = SignRound6Message_AbortData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound6Message_AbortData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound6Message_AbortData) ProtoMessage() {}

func (x *SignRound6Message_AbortData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound6Message_AbortData.ProtoReflect.Descriptor instead.
func (*SignRound6Message_AbortData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{6, 1}
}

func (x *SignRound6Message_AbortData) GetKI() []byte {
	if x != nil {
		return x.KI
	}
	return nil
}

func (x *SignRound6Message_AbortData) GetGammaI() []byte {
	if x != nil {
		return x.GammaI
	}
	return nil
}

func (x *SignRound6Message_AbortData) GetAlphaIJ() [][]byte {
	if x != nil {
		return x.AlphaIJ
	}
	return nil
}

func (x *SignRound6Message_AbortData) GetBetaJI() [][]byte {
	if x != nil {
		return x.BetaJI
	}
	return nil
}

type SignRound7Message_AbortData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KI           []byte          `protobuf:"bytes,1,opt,name=k_i,json=kI,proto3" json:"k_i,omitempty"`
	KRandI       []byte          `protobuf:"bytes,2,opt,name=k_rand_i,json=kRandI,proto3" json:"k_rand_i,omitempty"`
	MuIJ         [][]byte        `protobuf:"bytes,3,rep,name=mu_i_j,json=muIJ,proto3" json:"mu_i_j,omitempty"`
	MuRandIJ     [][]byte        `protobuf:"bytes,4,rep,name=mu_rand_i_j,json=muRandIJ,proto3" json:"mu_rand_i_j,omitempty"`
	EcddhProofA1 *common.ECPoint `protobuf:"bytes,5,opt,name=ecddh_proof_a1,json=ecddhProofA1,proto3" json:"ecddh_proof_a1,omitempty"`
	EcddhProofA2 *common.ECPoint `protobuf:"bytes,6,opt,name=ecddh_proof_a2,json=ecddhProofA2,proto3" json:"ecddh_proof_a2,omitempty"`
	EcddhProofZ  []byte          `protobuf:"bytes,7,opt,name=ecddh_proof_z,json=ecddhProofZ,proto3" json:"ecddh_proof_z,omitempty"`
}

func (x *SignRound7Message_AbortData) Reset() {
	*x = SignRound7Message_AbortData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signing_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound7Message_AbortData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound7Message_AbortData) ProtoMessage() {}

func (x *SignRound7Message_AbortData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signing_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound7Message_AbortData.ProtoReflect.Descriptor instead.
func (*SignRound7Message_AbortData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signing_proto_rawDescGZIP(), []int{7, 0}
}

func (x *SignRound7Message_AbortData) GetKI() []byte {
	if x != nil {
		return x.KI
	}
	return nil
}

func (x *SignRound7Message_AbortData) GetKRandI() []byte {
	if x != nil {
		return x.KRandI
	}
	return nil
}

func (x *SignRound7Message_AbortData) GetMuIJ() [][]byte {
	if x != nil {
		return x.MuIJ
	}
	return nil
}

func (x *SignRound7Message_AbortData) GetMuRandIJ() [][]byte {
	if x != nil {
		return x.MuRandIJ
	}
	return nil
}

func (x *SignRound7Message_AbortData) GetEcddhProofA1() *common.ECPoint {
	if x != nil {
		return x.EcddhProofA1
	}
	return nil
}

func (x *SignRound7Message_AbortData) GetEcddhProofA2() *common.ECPoint {
	if x != nil {
		return x.EcddhProofA2
	}
	return nil
}

func (x *SignRound7Message_AbortData) GetEcddhProofZ() []byte {
	if x != nil {
		return x.EcddhProofZ
	}
	return nil
}

var File_protob_ecdsa_signing_proto protoreflect.FileDescriptor

var file_protob_ecdsa_signing_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73,
	0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x4e, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x0c, 0x0a, 0x01, 0x63, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x01, 0x63, 0x12, 0x2a, 0x0a, 0x11, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x70,
	0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x0f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x41, 0x6c, 0x69, 0x63,
	0x65, 0x22, 0x34, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x72, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x0e, 0x0a, 0x02,
	0x63, 0x31, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x63, 0x31, 0x12, 0x0e, 0x0a, 0x02,
	0x63, 0x32, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x63, 0x32, 0x12, 0x1b, 0x0a, 0x09,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x62, 0x6f, 0x62, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x08, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x6f, 0x62, 0x12, 0x20, 0x0a, 0x0c, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x5f, 0x62, 0x6f, 0x62, 0x5f, 0x77, 0x63, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52,
	0x0a, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x6f, 0x62, 0x57, 0x63, 0x22, 0xad, 0x01, 0x0a, 0x11,
	0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x17, 0x0a, 0x07, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x5f, 0x69, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x06, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x49, 0x12, 0x19, 0x0a, 0x03, 0x74, 0x5f,
	0x69, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f, 0x69, 0x6e,
	0x74, 0x52, 0x02, 0x74, 0x49, 0x12, 0x2c, 0x0a, 0x0d, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x5f, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45,
	0x43, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0b, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x41, 0x6c,
	0x70, 0x68, 0x61, 0x12, 0x1a, 0x0a, 0x09, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x54, 0x12,
	0x1a, 0x0a, 0x09, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x75, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x55, 0x22, 0x38, 0x0a, 0x11, 0x53,
	0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x23, 0x0a, 0x0d, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x64, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x59, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x35, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x19, 0x0a, 0x03, 0x72, 0x5f,
	0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f, 0x69, 0x6e,
	0x74, 0x52, 0x02, 0x72, 0x49, 0x12, 0x29, 0x0a, 0x11, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x70,
	0x64, 0x6c, 0x5f, 0x77, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x0e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x50, 0x64, 0x6c, 0x57, 0x53, 0x6c, 0x61, 0x63, 0x6b,
	0x22, 0xc2, 0x03, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x36, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x3a, 0x0a, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x36, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x53, 0x75, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x44, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x12, 0x34, 0x0a, 0x05, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x36, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x48,
	0x00, 0x52, 0x05, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x1a, 0xc2, 0x01, 0x0a, 0x0b, 0x53, 0x75, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x44, 0x61, 0x74, 0x61, 0x12, 0x19, 0x0a, 0x03, 0x73, 0x5f, 0x69, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52,
	0x02, 0x73, 0x49, 0x12, 0x2e, 0x0a, 0x0e, 0x73, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0c, 0x73, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x41, 0x6c,
	0x70, 0x68, 0x61, 0x12, 0x2c, 0x0a, 0x0d, 0x73, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f,
	0x62, 0x65, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50,
	0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0b, 0x73, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x65, 0x74,
	0x61, 0x12, 0x1c, 0x0a, 0x0a, 0x73, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x54, 0x12,
	0x1c, 0x0a, 0x0a, 0x73, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x75, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x74, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x55, 0x1a, 0x6b, 0x0a,
	0x09, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x12, 0x0f, 0x0a, 0x03, 0x6b, 0x5f,
	0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x6b, 0x49, 0x12, 0x17, 0x0a, 0x07, 0x67,
	0x61, 0x6d, 0x6d, 0x61, 0x5f, 0x69, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x67, 0x61,
	0x6d, 0x6d, 0x61, 0x49, 0x12, 0x1a, 0x0a, 0x09, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x5f, 0x69, 0x5f,
	0x6a, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x49, 0x4a,
	0x12, 0x18, 0x0a, 0x08, 0x62, 0x65, 0x74, 0x61, 0x5f, 0x6a, 0x5f, 0x69, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x06, 0x62, 0x65, 0x74, 0x61, 0x4a, 0x49, 0x42, 0x09, 0x0a, 0x07, 0x63, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0xd9, 0x02, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x37, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x11, 0x0a, 0x03, 0x73,
	0x5f, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x02, 0x73, 0x49, 0x12, 0x34,
	0x0a, 0x05, 0x61, 0x62, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x37, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x2e, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x44, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x05, 0x61,
	0x62, 0x6f, 0x72, 0x74, 0x1a, 0xef, 0x01, 0x0a, 0x09, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x44, 0x61,
	0x74, 0x61, 0x12, 0x0f, 0x0a, 0x03, 0x6b, 0x5f, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x02, 0x6b, 0x49, 0x12, 0x18, 0x0a, 0x08, 0x6b, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x5f, 0x69, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6b, 0x52, 0x61, 0x6e, 0x64, 0x49, 0x12, 0x14, 0x0a,
	0x06, 0x6d, 0x75, 0x5f, 0x69, 0x5f, 0x6a, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x04, 0x6d,
	0x75, 0x49, 0x4a, 0x12, 0x1d, 0x0a, 0x0b, 0x6d, 0x75, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x5f, 0x69,
	0x5f, 0x6a, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x6d, 0x75, 0x52, 0x61, 0x6e, 0x64,
	0x49, 0x4a, 0x12, 0x2e, 0x0a, 0x0e, 0x65, 0x63, 0x64, 0x64, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x5f, 0x61, 0x31, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50,
	0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0c, 0x65, 0x63, 0x64, 0x64, 0x68, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x41, 0x31, 0x12, 0x2e, 0x0a, 0x0e, 0x65, 0x63, 0x64, 0x64, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x5f, 0x61, 0x32, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43, 0x50,
	0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0c, 0x65, 0x63, 0x64, 0x64, 0x68, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x41, 0x32, 0x12, 0x22, 0x0a, 0x0d, 0x65, 0x63, 0x64, 0x64, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x5f, 0x7a, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x65, 0x63, 0x64, 0x64, 0x68,
	0x50, 0x72, 0x6f, 0x6f, 0x66, 0x5a, 0x42, 0x09, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x42, 0x30, 0x5a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x74, 0x73,
	0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x73, 0x69, 0x67, 0x6e,
	0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_signing_proto_rawDescOnce sync.Once
	file_protob_ecdsa_signing_proto_rawDescData = file_protob_ecdsa_signing_proto_rawDesc
)

func file_protob_ecdsa_signing_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_signing_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_signing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_signing_proto_rawDescData)
	})
	return file_protob_ecdsa_signing_proto_rawDescData
}

var file_protob_ecdsa_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_protob_ecdsa_signing_proto_goTypes = []interface{}{
	(*SignRound1Message1)(nil),            // 0: SignRound1Message1
	(*SignRound1Message2)(nil),            // 1: SignRound1Message2
	(*SignRound2Message)(nil),             // 2: SignRound2Message
	(*SignRound3Message)(nil),             // 3: SignRound3Message
	(*SignRound4Message)(nil),             // 4: SignRound4Message
	(*SignRound5Message)(nil),             // 5: SignRound5Message
	(*SignRound6Message)(nil),             // 6: SignRound6Message
	(*SignRound7Message)(nil),             // 7: SignRound7Message
	(*SignRound6Message_SuccessData)(nil), // 8: SignRound6Message.SuccessData
	(*SignRound6Message_AbortData)(nil),   // 9: SignRound6Message.AbortData
	(*SignRound7Message_AbortData)(nil),   // 10: SignRound7Message.AbortData
	(*common.ECPoint)(nil),                // 11: ECPoint
}
var file_protob_ecdsa_signing_proto_depIdxs = []int32{
	11, // 0: SignRound3Message.t_i:type_name -> ECPoint
	11, // 1: SignRound3Message.t_proof_alpha:type_name -> ECPoint
	11, // 2: SignRound5Message.r_i:type_name -> ECPoint
	8,  // 3: SignRound6Message.success:type_name -> SignRound6Message.SuccessData
	9,  // 4: SignRound6Message.abort:type_name -> SignRound6Message.AbortData
	10, // 5: SignRound7Message.abort:type_name -> SignRound7Message.AbortData
	11, // 6: SignRound6Message.SuccessData.s_i:type_name -> ECPoint
	11, // 7: SignRound6Message.SuccessData.st_proof_alpha:type_name -> ECPoint
	11, // 8: SignRound6Message.SuccessData.st_proof_beta:type_name -> ECPoint
	11, // 9: SignRound7Message.AbortData.ecddh_proof_a1:type_name -> ECPoint
	11, // 10: SignRound7Message.AbortData.ecddh_proof_a2:type_name -> ECPoint
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_signing_proto_init() }
func file_protob_ecdsa_signing_proto_init() {
	if File_protob_ecdsa_signing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_signing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound4Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound5Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound6Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound7Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound6Message_SuccessData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound6Message_AbortData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_signing_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound7Message_AbortData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_protob_ecdsa_signing_proto_msgTypes[6].OneofWrappers = []interface{}{
		(*SignRound6Message_Success)(nil),
		(*SignRound6Message_Abort)(nil),
	}
	file_protob_ecdsa_signing_proto_msgTypes[7].OneofWrappers = []interface{}{
		(*SignRound7Message_SI)(nil),
		(*SignRound7Message_Abort)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_ecdsa_signing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_signing_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_signing_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_signing_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_signing_proto = out.File
	file_protob_ecdsa_signing_proto_rawDesc = nil
	file_protob_ecdsa_signing_proto_goTypes = nil
	file_protob_ecdsa_signing_proto_depIdxs = nil
}
