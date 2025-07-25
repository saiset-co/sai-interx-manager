// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: kira/slashing/v1beta1/genesis.proto

package types

import (
	_ "github.com/gogo/protobuf/gogoproto"
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

// GenesisState defines the slashing module's genesis state.
type GenesisState struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// signing_infos represents a map between validator addresses and their
	// signing infos.
	SigningInfos []*SigningInfo `protobuf:"bytes,1,rep,name=signing_infos,json=signingInfos,proto3" json:"signing_infos,omitempty"`
}

func (x *GenesisState) Reset() {
	*x = GenesisState{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_slashing_v1beta1_genesis_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenesisState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenesisState) ProtoMessage() {}

func (x *GenesisState) ProtoReflect() protoreflect.Message {
	mi := &file_kira_slashing_v1beta1_genesis_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenesisState.ProtoReflect.Descriptor instead.
func (*GenesisState) Descriptor() ([]byte, []int) {
	return file_kira_slashing_v1beta1_genesis_proto_rawDescGZIP(), []int{0}
}

func (x *GenesisState) GetSigningInfos() []*SigningInfo {
	if x != nil {
		return x.SigningInfos
	}
	return nil
}

// SigningInfo stores validator signing info of corresponding address.
type SigningInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// address is the validator address.
	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	// validator_signing_info represents the signing info of this validator.
	ValidatorSigningInfo *ValidatorSigningInfo `protobuf:"bytes,2,opt,name=validator_signing_info,json=validatorSigningInfo,proto3" json:"validator_signing_info,omitempty"`
}

func (x *SigningInfo) Reset() {
	*x = SigningInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_slashing_v1beta1_genesis_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SigningInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningInfo) ProtoMessage() {}

func (x *SigningInfo) ProtoReflect() protoreflect.Message {
	mi := &file_kira_slashing_v1beta1_genesis_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningInfo.ProtoReflect.Descriptor instead.
func (*SigningInfo) Descriptor() ([]byte, []int) {
	return file_kira_slashing_v1beta1_genesis_proto_rawDescGZIP(), []int{1}
}

func (x *SigningInfo) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *SigningInfo) GetValidatorSigningInfo() *ValidatorSigningInfo {
	if x != nil {
		return x.ValidatorSigningInfo
	}
	return nil
}

var File_kira_slashing_v1beta1_genesis_proto protoreflect.FileDescriptor

var file_kira_slashing_v1beta1_genesis_proto_rawDesc = []byte{
	0x0a, 0x23, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2f,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x73, 0x69, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x73, 0x6c, 0x61, 0x73,
	0x68, 0x69, 0x6e, 0x67, 0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x6b, 0x69, 0x72, 0x61,
	0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61,
	0x31, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x6d, 0x0a, 0x0c, 0x47, 0x65, 0x6e, 0x65, 0x73, 0x69, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x12, 0x5d, 0x0a, 0x0d, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x69, 0x6e, 0x66, 0x6f,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x73,
	0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49,
	0x6e, 0x66, 0x6f, 0x42, 0x1c, 0xc8, 0xde, 0x1f, 0x00, 0xf2, 0xde, 0x1f, 0x14, 0x79, 0x61, 0x6d,
	0x6c, 0x3a, 0x22, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x73,
	0x22, 0x52, 0x0c, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x73, 0x22,
	0xaa, 0x01, 0x0a, 0x0b, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x12,
	0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x80, 0x01, 0x0a, 0x16, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f,
	0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x6b, 0x69, 0x72,
	0x61, 0x2e, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x6f, 0x72, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x42,
	0x25, 0xc8, 0xde, 0x1f, 0x00, 0xf2, 0xde, 0x1f, 0x1d, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x22, 0x52, 0x14, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f,
	0x72, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x2c, 0x5a, 0x2a,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x69, 0x72, 0x61, 0x43,
	0x6f, 0x72, 0x65, 0x2f, 0x73, 0x65, 0x6b, 0x61, 0x69, 0x2f, 0x78, 0x2f, 0x73, 0x6c, 0x61, 0x73,
	0x68, 0x69, 0x6e, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_kira_slashing_v1beta1_genesis_proto_rawDescOnce sync.Once
	file_kira_slashing_v1beta1_genesis_proto_rawDescData = file_kira_slashing_v1beta1_genesis_proto_rawDesc
)

func file_kira_slashing_v1beta1_genesis_proto_rawDescGZIP() []byte {
	file_kira_slashing_v1beta1_genesis_proto_rawDescOnce.Do(func() {
		file_kira_slashing_v1beta1_genesis_proto_rawDescData = protoimpl.X.CompressGZIP(file_kira_slashing_v1beta1_genesis_proto_rawDescData)
	})
	return file_kira_slashing_v1beta1_genesis_proto_rawDescData
}

var file_kira_slashing_v1beta1_genesis_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_kira_slashing_v1beta1_genesis_proto_goTypes = []interface{}{
	(*GenesisState)(nil),         // 0: kira.slashing.GenesisState
	(*SigningInfo)(nil),          // 1: kira.slashing.SigningInfo
	(*ValidatorSigningInfo)(nil), // 2: kira.slashing.ValidatorSigningInfo
}
var file_kira_slashing_v1beta1_genesis_proto_depIdxs = []int32{
	1, // 0: kira.slashing.GenesisState.signing_infos:type_name -> kira.slashing.SigningInfo
	2, // 1: kira.slashing.SigningInfo.validator_signing_info:type_name -> kira.slashing.ValidatorSigningInfo
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_kira_slashing_v1beta1_genesis_proto_init() }
func file_kira_slashing_v1beta1_genesis_proto_init() {
	if File_kira_slashing_v1beta1_genesis_proto != nil {
		return
	}
	file_kira_slashing_v1beta1_slashing_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_kira_slashing_v1beta1_genesis_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenesisState); i {
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
		file_kira_slashing_v1beta1_genesis_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SigningInfo); i {
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
			RawDescriptor: file_kira_slashing_v1beta1_genesis_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_kira_slashing_v1beta1_genesis_proto_goTypes,
		DependencyIndexes: file_kira_slashing_v1beta1_genesis_proto_depIdxs,
		MessageInfos:      file_kira_slashing_v1beta1_genesis_proto_msgTypes,
	}.Build()
	File_kira_slashing_v1beta1_genesis_proto = out.File
	file_kira_slashing_v1beta1_genesis_proto_rawDesc = nil
	file_kira_slashing_v1beta1_genesis_proto_goTypes = nil
	file_kira_slashing_v1beta1_genesis_proto_depIdxs = nil
}
