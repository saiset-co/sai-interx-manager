// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: kira/ethereum/query.proto

package types

import (
	_ "github.com/gogo/protobuf/gogoproto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RelayByAddressRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Addr []byte `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (x *RelayByAddressRequest) Reset() {
	*x = RelayByAddressRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_ethereum_query_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RelayByAddressRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RelayByAddressRequest) ProtoMessage() {}

func (x *RelayByAddressRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_ethereum_query_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RelayByAddressRequest.ProtoReflect.Descriptor instead.
func (*RelayByAddressRequest) Descriptor() ([]byte, []int) {
	return file_kira_ethereum_query_proto_rawDescGZIP(), []int{0}
}

func (x *RelayByAddressRequest) GetAddr() []byte {
	if x != nil {
		return x.Addr
	}
	return nil
}

type RelayByAddressResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MsgRelay *MsgRelay `protobuf:"bytes,1,opt,name=msg_relay,json=msgRelay,proto3" json:"msg_relay,omitempty"`
}

func (x *RelayByAddressResponse) Reset() {
	*x = RelayByAddressResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_ethereum_query_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RelayByAddressResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RelayByAddressResponse) ProtoMessage() {}

func (x *RelayByAddressResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_ethereum_query_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RelayByAddressResponse.ProtoReflect.Descriptor instead.
func (*RelayByAddressResponse) Descriptor() ([]byte, []int) {
	return file_kira_ethereum_query_proto_rawDescGZIP(), []int{1}
}

func (x *RelayByAddressResponse) GetMsgRelay() *MsgRelay {
	if x != nil {
		return x.MsgRelay
	}
	return nil
}

var File_kira_ethereum_query_proto protoreflect.FileDescriptor

var file_kira_ethereum_query_proto_rawDesc = []byte{
	0x0a, 0x19, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2f,
	0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6b, 0x69, 0x72,
	0x61, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c,
	0x6b, 0x69, 0x72, 0x61, 0x2f, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2f, 0x65, 0x74,
	0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x6b, 0x69,
	0x72, 0x61, 0x2f, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2f, 0x74, 0x78, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x6d, 0x0a, 0x15, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x42, 0x79, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x54, 0x0a,
	0x04, 0x61, 0x64, 0x64, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x40, 0xf2, 0xde, 0x1f,
	0x0b, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x61, 0x64, 0x64, 0x72, 0x22, 0xfa, 0xde, 0x1f, 0x2d,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70,
	0x65, 0x73, 0x2e, 0x41, 0x63, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x04, 0x61,
	0x64, 0x64, 0x72, 0x22, 0x4e, 0x0a, 0x16, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x42, 0x79, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x34, 0x0a,
	0x09, 0x6d, 0x73, 0x67, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d,
	0x2e, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x52, 0x08, 0x6d, 0x73, 0x67, 0x52, 0x65,
	0x6c, 0x61, 0x79, 0x32, 0x8c, 0x01, 0x0a, 0x05, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x82, 0x01,
	0x0a, 0x0e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x42, 0x79, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x12, 0x24, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d,
	0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x42, 0x79, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x65, 0x74,
	0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x52, 0x65, 0x6c, 0x61, 0x79, 0x42, 0x79, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x23, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x1d, 0x12, 0x1b, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x65, 0x74, 0x68,
	0x65, 0x72, 0x65, 0x75, 0x6d, 0x2f, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x2f, 0x7b, 0x61, 0x64, 0x64,
	0x72, 0x7d, 0x42, 0x2c, 0x5a, 0x2a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x4b, 0x69, 0x72, 0x61, 0x43, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x65, 0x6b, 0x61, 0x69, 0x2f,
	0x78, 0x2f, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_kira_ethereum_query_proto_rawDescOnce sync.Once
	file_kira_ethereum_query_proto_rawDescData = file_kira_ethereum_query_proto_rawDesc
)

func file_kira_ethereum_query_proto_rawDescGZIP() []byte {
	file_kira_ethereum_query_proto_rawDescOnce.Do(func() {
		file_kira_ethereum_query_proto_rawDescData = protoimpl.X.CompressGZIP(file_kira_ethereum_query_proto_rawDescData)
	})
	return file_kira_ethereum_query_proto_rawDescData
}

var file_kira_ethereum_query_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_kira_ethereum_query_proto_goTypes = []interface{}{
	(*RelayByAddressRequest)(nil),  // 0: kira.ethereum.RelayByAddressRequest
	(*RelayByAddressResponse)(nil), // 1: kira.ethereum.RelayByAddressResponse
	(*MsgRelay)(nil),               // 2: kira.ethereum.MsgRelay
}
var file_kira_ethereum_query_proto_depIdxs = []int32{
	2, // 0: kira.ethereum.RelayByAddressResponse.msg_relay:type_name -> kira.ethereum.MsgRelay
	0, // 1: kira.ethereum.Query.RelayByAddress:input_type -> kira.ethereum.RelayByAddressRequest
	1, // 2: kira.ethereum.Query.RelayByAddress:output_type -> kira.ethereum.RelayByAddressResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_kira_ethereum_query_proto_init() }
func file_kira_ethereum_query_proto_init() {
	if File_kira_ethereum_query_proto != nil {
		return
	}
	file_kira_ethereum_ethereum_proto_init()
	file_kira_ethereum_tx_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_kira_ethereum_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RelayByAddressRequest); i {
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
		file_kira_ethereum_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RelayByAddressResponse); i {
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
			RawDescriptor: file_kira_ethereum_query_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_kira_ethereum_query_proto_goTypes,
		DependencyIndexes: file_kira_ethereum_query_proto_depIdxs,
		MessageInfos:      file_kira_ethereum_query_proto_msgTypes,
	}.Build()
	File_kira_ethereum_query_proto = out.File
	file_kira_ethereum_query_proto_rawDesc = nil
	file_kira_ethereum_query_proto_goTypes = nil
	file_kira_ethereum_query_proto_depIdxs = nil
}
