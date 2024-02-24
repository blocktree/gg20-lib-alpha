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

// State object for signatures, either partial (for offline/async "one round" signing) or full (contains the final ECDSA signature).
type SignatureData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature    *common.ECSignature         `protobuf:"bytes,10,opt,name=signature,proto3" json:"signature,omitempty"`
	OneRoundData *SignatureData_OneRoundData `protobuf:"bytes,11,opt,name=one_round_data,json=oneRoundData,proto3" json:"one_round_data,omitempty"`
}

func (x *SignatureData) Reset() {
	*x = SignatureData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signature_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureData) ProtoMessage() {}

func (x *SignatureData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signature_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureData.ProtoReflect.Descriptor instead.
func (*SignatureData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signature_proto_rawDescGZIP(), []int{0}
}

func (x *SignatureData) GetSignature() *common.ECSignature {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *SignatureData) GetOneRoundData() *SignatureData_OneRoundData {
	if x != nil {
		return x.OneRoundData
	}
	return nil
}

type SignatureData_OneRoundData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Sanity check in FinalizeGetAndVerifyFinalSig
	T int32 `protobuf:"varint,1,opt,name=t,proto3" json:"t,omitempty"`
	// Components to produce s = sum(s_i)
	KI      []byte          `protobuf:"bytes,2,opt,name=k_i,json=kI,proto3" json:"k_i,omitempty"`
	RSigmaI []byte          `protobuf:"bytes,3,opt,name=r_sigma_i,json=rSigmaI,proto3" json:"r_sigma_i,omitempty"`
	BigR    *common.ECPoint `protobuf:"bytes,4,opt,name=big_r,json=bigR,proto3" json:"big_r,omitempty"`
	// Components for identifiable aborts during the final phase
	BigRBarJ map[string]*common.ECPoint `protobuf:"bytes,5,rep,name=big_r_bar_j,json=bigRBarJ,proto3" json:"big_r_bar_j,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	BigSJ    map[string]*common.ECPoint `protobuf:"bytes,6,rep,name=big_s_j,json=bigSJ,proto3" json:"big_s_j,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *SignatureData_OneRoundData) Reset() {
	*x = SignatureData_OneRoundData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_signature_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignatureData_OneRoundData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureData_OneRoundData) ProtoMessage() {}

func (x *SignatureData_OneRoundData) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_signature_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureData_OneRoundData.ProtoReflect.Descriptor instead.
func (*SignatureData_OneRoundData) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_signature_proto_rawDescGZIP(), []int{0, 0}
}

func (x *SignatureData_OneRoundData) GetT() int32 {
	if x != nil {
		return x.T
	}
	return 0
}

func (x *SignatureData_OneRoundData) GetKI() []byte {
	if x != nil {
		return x.KI
	}
	return nil
}

func (x *SignatureData_OneRoundData) GetRSigmaI() []byte {
	if x != nil {
		return x.RSigmaI
	}
	return nil
}

func (x *SignatureData_OneRoundData) GetBigR() *common.ECPoint {
	if x != nil {
		return x.BigR
	}
	return nil
}

func (x *SignatureData_OneRoundData) GetBigRBarJ() map[string]*common.ECPoint {
	if x != nil {
		return x.BigRBarJ
	}
	return nil
}

func (x *SignatureData_OneRoundData) GetBigSJ() map[string]*common.ECPoint {
	if x != nil {
		return x.BigSJ
	}
	return nil
}

var File_protob_ecdsa_signature_proto protoreflect.FileDescriptor

var file_protob_ecdsa_signature_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xfe, 0x03, 0x0a, 0x0d, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x2a, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x45, 0x43, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x12, 0x41, 0x0a, 0x0e, 0x6f, 0x6e, 0x65, 0x5f, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x4f, 0x6e, 0x65, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x44, 0x61, 0x74, 0x61, 0x52, 0x0c, 0x6f, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x44, 0x61, 0x74, 0x61, 0x1a, 0xfd, 0x02, 0x0a, 0x0c, 0x4f, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x44, 0x61, 0x74, 0x61, 0x12, 0x0c, 0x0a, 0x01, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x01, 0x74, 0x12, 0x0f, 0x0a, 0x03, 0x6b, 0x5f, 0x69, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x02, 0x6b, 0x49, 0x12, 0x1a, 0x0a, 0x09, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x6d, 0x61, 0x5f,
	0x69, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x72, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x49,
	0x12, 0x1d, 0x0a, 0x05, 0x62, 0x69, 0x67, 0x5f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x04, 0x62, 0x69, 0x67, 0x52, 0x12,
	0x48, 0x0a, 0x0b, 0x62, 0x69, 0x67, 0x5f, 0x72, 0x5f, 0x62, 0x61, 0x72, 0x5f, 0x6a, 0x18, 0x05,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x44, 0x61, 0x74, 0x61, 0x2e, 0x4f, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x44, 0x61, 0x74,
	0x61, 0x2e, 0x42, 0x69, 0x67, 0x52, 0x42, 0x61, 0x72, 0x4a, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x08, 0x62, 0x69, 0x67, 0x52, 0x42, 0x61, 0x72, 0x4a, 0x12, 0x3e, 0x0a, 0x07, 0x62, 0x69, 0x67,
	0x5f, 0x73, 0x5f, 0x6a, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x4f, 0x6e, 0x65, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x42, 0x69, 0x67, 0x53, 0x4a, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x05, 0x62, 0x69, 0x67, 0x53, 0x4a, 0x1a, 0x45, 0x0a, 0x0d, 0x42, 0x69, 0x67,
	0x52, 0x42, 0x61, 0x72, 0x4a, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x1e, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x1a, 0x42, 0x0a, 0x0a, 0x42, 0x69, 0x67, 0x53, 0x4a, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x1e, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x08, 0x2e, 0x45, 0x43, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x42, 0x30, 0x5a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x63, 0x68, 0x61, 0x69, 0x6e,
	0x2f, 0x74, 0x73, 0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x73,
	0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_signature_proto_rawDescOnce sync.Once
	file_protob_ecdsa_signature_proto_rawDescData = file_protob_ecdsa_signature_proto_rawDesc
)

func file_protob_ecdsa_signature_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_signature_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_signature_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_signature_proto_rawDescData)
	})
	return file_protob_ecdsa_signature_proto_rawDescData
}

var file_protob_ecdsa_signature_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_protob_ecdsa_signature_proto_goTypes = []interface{}{
	(*SignatureData)(nil),              // 0: SignatureData
	(*SignatureData_OneRoundData)(nil), // 1: SignatureData.OneRoundData
	nil,                                // 2: SignatureData.OneRoundData.BigRBarJEntry
	nil,                                // 3: SignatureData.OneRoundData.BigSJEntry
	(*common.ECSignature)(nil),         // 4: ECSignature
	(*common.ECPoint)(nil),             // 5: ECPoint
}
var file_protob_ecdsa_signature_proto_depIdxs = []int32{
	4, // 0: SignatureData.signature:type_name -> ECSignature
	1, // 1: SignatureData.one_round_data:type_name -> SignatureData.OneRoundData
	5, // 2: SignatureData.OneRoundData.big_r:type_name -> ECPoint
	2, // 3: SignatureData.OneRoundData.big_r_bar_j:type_name -> SignatureData.OneRoundData.BigRBarJEntry
	3, // 4: SignatureData.OneRoundData.big_s_j:type_name -> SignatureData.OneRoundData.BigSJEntry
	5, // 5: SignatureData.OneRoundData.BigRBarJEntry.value:type_name -> ECPoint
	5, // 6: SignatureData.OneRoundData.BigSJEntry.value:type_name -> ECPoint
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_signature_proto_init() }
func file_protob_ecdsa_signature_proto_init() {
	if File_protob_ecdsa_signature_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_signature_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureData); i {
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
		file_protob_ecdsa_signature_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignatureData_OneRoundData); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_ecdsa_signature_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_signature_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_signature_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_signature_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_signature_proto = out.File
	file_protob_ecdsa_signature_proto_rawDesc = nil
	file_protob_ecdsa_signature_proto_goTypes = nil
	file_protob_ecdsa_signature_proto_depIdxs = nil
}
