package gg20

import (
	reflect "reflect"
	sync "sync"

	proto "github.com/golang/protobuf/proto"
	any "github.com/golang/protobuf/ptypes/any"
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

// Wrapper for GG20 messages, often read by the transport layer and not itself sent over the wire
type MessageWrapper struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Metadata optionally un-marshalled and used by the transport to route this message.
	IsBroadcast bool `protobuf:"varint,1,opt,name=is_broadcast,json=isBroadcast,proto3" json:"is_broadcast,omitempty"`
	// Metadata optionally un-marshalled and used by the transport to route this message.
	IsToOldCommittee bool `protobuf:"varint,2,opt,name=is_to_old_committee,json=isToOldCommittee,proto3" json:"is_to_old_committee,omitempty"` // used only in certain resharing messages
	// Metadata optionally un-marshalled and used by the transport to route this message.
	IsToOldAndNewCommittees bool `protobuf:"varint,5,opt,name=is_to_old_and_new_committees,json=isToOldAndNewCommittees,proto3" json:"is_to_old_and_new_committees,omitempty"` // used only in certain resharing messages
	// Metadata optionally un-marshalled and used by the transport to route this message.
	From *MessageWrapper_PartyID `protobuf:"bytes,3,opt,name=from,proto3" json:"from,omitempty"`
	// Metadata optionally un-marshalled and used by the transport to route this message.
	To []*MessageWrapper_PartyID `protobuf:"bytes,4,rep,name=to,proto3" json:"to,omitempty"`
	// This field is actually what is sent through the wire and consumed on the other end by UpdateFromBytes.
	// An Any contains an arbitrary serialized message as bytes, along with a URL that
	// acts as a globally unique identifier for and resolves to that message's type.
	Message *any.Any `protobuf:"bytes,10,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *MessageWrapper) Reset() {
	*x = MessageWrapper{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MessageWrapper) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageWrapper) ProtoMessage() {}

func (x *MessageWrapper) ProtoReflect() protoreflect.Message {
	mi := &file_protob_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageWrapper.ProtoReflect.Descriptor instead.
func (*MessageWrapper) Descriptor() ([]byte, []int) {
	return file_protob_message_proto_rawDescGZIP(), []int{0}
}

func (x *MessageWrapper) GetIsBroadcast() bool {
	if x != nil {
		return x.IsBroadcast
	}
	return false
}

func (x *MessageWrapper) GetIsToOldCommittee() bool {
	if x != nil {
		return x.IsToOldCommittee
	}
	return false
}

func (x *MessageWrapper) GetIsToOldAndNewCommittees() bool {
	if x != nil {
		return x.IsToOldAndNewCommittees
	}
	return false
}

func (x *MessageWrapper) GetFrom() *MessageWrapper_PartyID {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *MessageWrapper) GetTo() []*MessageWrapper_PartyID {
	if x != nil {
		return x.To
	}
	return nil
}

func (x *MessageWrapper) GetMessage() *any.Any {
	if x != nil {
		return x.Message
	}
	return nil
}

// PartyID represents a participant in the GG20 protocol rounds.
// Note: The `id` and `moniker` are provided for convenience to allow you to track participants easier.
// The `id` is intended to be a unique string representation of `key` and `moniker` can be anything (even left blank).
type MessageWrapper_PartyID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Moniker string `protobuf:"bytes,2,opt,name=moniker,proto3" json:"moniker,omitempty"`
	Key     []byte `protobuf:"bytes,3,opt,name=key,proto3" json:"key,omitempty"`
}

func (x *MessageWrapper_PartyID) Reset() {
	*x = MessageWrapper_PartyID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MessageWrapper_PartyID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageWrapper_PartyID) ProtoMessage() {}

func (x *MessageWrapper_PartyID) ProtoReflect() protoreflect.Message {
	mi := &file_protob_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageWrapper_PartyID.ProtoReflect.Descriptor instead.
func (*MessageWrapper_PartyID) Descriptor() ([]byte, []int) {
	return file_protob_message_proto_rawDescGZIP(), []int{0, 0}
}

func (x *MessageWrapper_PartyID) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *MessageWrapper_PartyID) GetMoniker() string {
	if x != nil {
		return x.Moniker
	}
	return ""
}

func (x *MessageWrapper_PartyID) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

var File_protob_message_proto protoreflect.FileDescriptor

var file_protob_message_proto_rawDesc = []byte{
	0x0a, 0x14, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xee, 0x02, 0x0a, 0x0e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x57, 0x72, 0x61,
	0x70, 0x70, 0x65, 0x72, 0x12, 0x21, 0x0a, 0x0c, 0x69, 0x73, 0x5f, 0x62, 0x72, 0x6f, 0x61, 0x64,
	0x63, 0x61, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x73, 0x42, 0x72,
	0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74, 0x12, 0x2d, 0x0a, 0x13, 0x69, 0x73, 0x5f, 0x74, 0x6f,
	0x5f, 0x6f, 0x6c, 0x64, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x69, 0x73, 0x54, 0x6f, 0x4f, 0x6c, 0x64, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x74, 0x65, 0x65, 0x12, 0x3d, 0x0a, 0x1c, 0x69, 0x73, 0x5f, 0x74, 0x6f, 0x5f,
	0x6f, 0x6c, 0x64, 0x5f, 0x61, 0x6e, 0x64, 0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x74, 0x65, 0x65, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x17, 0x69, 0x73,
	0x54, 0x6f, 0x4f, 0x6c, 0x64, 0x41, 0x6e, 0x64, 0x4e, 0x65, 0x77, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x74, 0x65, 0x65, 0x73, 0x12, 0x2b, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x57, 0x72, 0x61,
	0x70, 0x70, 0x65, 0x72, 0x2e, 0x50, 0x61, 0x72, 0x74, 0x79, 0x49, 0x44, 0x52, 0x04, 0x66, 0x72,
	0x6f, 0x6d, 0x12, 0x27, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2e,
	0x50, 0x61, 0x72, 0x74, 0x79, 0x49, 0x44, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x2e, 0x0a, 0x07, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41,
	0x6e, 0x79, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x45, 0x0a, 0x07, 0x50,
	0x61, 0x72, 0x74, 0x79, 0x49, 0x44, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x6f, 0x6e, 0x69, 0x6b, 0x65,
	0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x6f, 0x6e, 0x69, 0x6b, 0x65, 0x72,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x42, 0x26, 0x5a, 0x24, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2d, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x2f, 0x74,
	0x73, 0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x74, 0x73, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_protob_message_proto_rawDescOnce sync.Once
	file_protob_message_proto_rawDescData = file_protob_message_proto_rawDesc
)

func file_protob_message_proto_rawDescGZIP() []byte {
	file_protob_message_proto_rawDescOnce.Do(func() {
		file_protob_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_message_proto_rawDescData)
	})
	return file_protob_message_proto_rawDescData
}

var file_protob_message_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_protob_message_proto_goTypes = []interface{}{
	(*MessageWrapper)(nil),         // 0: MessageWrapper
	(*MessageWrapper_PartyID)(nil), // 1: MessageWrapper.PartyID
	(*any.Any)(nil),                // 2: google.protobuf.Any
}
var file_protob_message_proto_depIdxs = []int32{
	1, // 0: MessageWrapper.from:type_name -> MessageWrapper.PartyID
	1, // 1: MessageWrapper.to:type_name -> MessageWrapper.PartyID
	2, // 2: MessageWrapper.message:type_name -> google.protobuf.Any
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_protob_message_proto_init() }
func file_protob_message_proto_init() {
	if File_protob_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MessageWrapper); i {
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
		file_protob_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MessageWrapper_PartyID); i {
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
			RawDescriptor: file_protob_message_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_message_proto_goTypes,
		DependencyIndexes: file_protob_message_proto_depIdxs,
		MessageInfos:      file_protob_message_proto_msgTypes,
	}.Build()
	File_protob_message_proto = out.File
	file_protob_message_proto_rawDesc = nil
	file_protob_message_proto_goTypes = nil
	file_protob_message_proto_depIdxs = nil
}
