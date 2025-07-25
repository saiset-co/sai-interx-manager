// Since: cosmos-sdk 0.47

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/consensus/v1/tx.proto

package types

import (
	types "github.com/cometbft/cometbft/proto/tendermint/types"
	_ "github.com/cosmos/cosmos-proto"
	_ "github.com/cosmos/cosmos-sdk/types/msgservice"
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

// MsgUpdateParams is the Msg/UpdateParams request type.
type MsgUpdateParams struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// authority is the address that controls the module (defaults to x/gov unless overwritten).
	Authority string `protobuf:"bytes,1,opt,name=authority,proto3" json:"authority,omitempty"`
	// params defines the x/consensus parameters to update.
	// VersionsParams is not included in this Msg because it is tracked
	// separarately in x/upgrade.
	//
	// NOTE: All parameters must be supplied.
	Block     *types.BlockParams     `protobuf:"bytes,2,opt,name=block,proto3" json:"block,omitempty"`
	Evidence  *types.EvidenceParams  `protobuf:"bytes,3,opt,name=evidence,proto3" json:"evidence,omitempty"`
	Validator *types.ValidatorParams `protobuf:"bytes,4,opt,name=validator,proto3" json:"validator,omitempty"`
}

func (x *MsgUpdateParams) Reset() {
	*x = MsgUpdateParams{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_consensus_v1_tx_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MsgUpdateParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgUpdateParams) ProtoMessage() {}

func (x *MsgUpdateParams) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_consensus_v1_tx_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgUpdateParams.ProtoReflect.Descriptor instead.
func (*MsgUpdateParams) Descriptor() ([]byte, []int) {
	return file_cosmos_consensus_v1_tx_proto_rawDescGZIP(), []int{0}
}

func (x *MsgUpdateParams) GetAuthority() string {
	if x != nil {
		return x.Authority
	}
	return ""
}

func (x *MsgUpdateParams) GetBlock() *types.BlockParams {
	if x != nil {
		return x.Block
	}
	return nil
}

func (x *MsgUpdateParams) GetEvidence() *types.EvidenceParams {
	if x != nil {
		return x.Evidence
	}
	return nil
}

func (x *MsgUpdateParams) GetValidator() *types.ValidatorParams {
	if x != nil {
		return x.Validator
	}
	return nil
}

// MsgUpdateParamsResponse defines the response structure for executing a
// MsgUpdateParams message.
type MsgUpdateParamsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *MsgUpdateParamsResponse) Reset() {
	*x = MsgUpdateParamsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_consensus_v1_tx_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MsgUpdateParamsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgUpdateParamsResponse) ProtoMessage() {}

func (x *MsgUpdateParamsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_consensus_v1_tx_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgUpdateParamsResponse.ProtoReflect.Descriptor instead.
func (*MsgUpdateParamsResponse) Descriptor() ([]byte, []int) {
	return file_cosmos_consensus_v1_tx_proto_rawDescGZIP(), []int{1}
}

var File_cosmos_consensus_v1_tx_proto protoreflect.FileDescriptor

var file_cosmos_consensus_v1_tx_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73,
	0x75, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73,
	0x2e, 0x76, 0x31, 0x1a, 0x19, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x5f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x6d, 0x73, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x73,
	0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x6d,
	0x69, 0x6e, 0x74, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8d, 0x02, 0x0a, 0x0f, 0x4d, 0x73, 0x67, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x36, 0x0a, 0x09, 0x61, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x18, 0xd2,
	0xb4, 0x2d, 0x14, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x09, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x12, 0x33, 0x0a, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1d, 0x2e, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x74, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73,
	0x52, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x3c, 0x0a, 0x08, 0x65, 0x76, 0x69, 0x64, 0x65,
	0x6e, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x74, 0x65, 0x6e, 0x64,
	0x65, 0x72, 0x6d, 0x69, 0x6e, 0x74, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x45, 0x76, 0x69,
	0x64, 0x65, 0x6e, 0x63, 0x65, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x52, 0x08, 0x65, 0x76, 0x69,
	0x64, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x3f, 0x0a, 0x09, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x74, 0x65, 0x6e, 0x64, 0x65,
	0x72, 0x6d, 0x69, 0x6e, 0x74, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x56, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x6f, 0x72, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x52, 0x09, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x3a, 0x0e, 0x82, 0xe7, 0xb0, 0x2a, 0x09, 0x61, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x22, 0x19, 0x0a, 0x17, 0x4d, 0x73, 0x67, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x32, 0x69, 0x0a, 0x03, 0x4d, 0x73, 0x67, 0x12, 0x62, 0x0a, 0x0c, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x24, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4d,
	0x73, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x1a, 0x2c,
	0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x73, 0x67, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x61,
	0x72, 0x61, 0x6d, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x4a, 0x5a, 0x48,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x69, 0x73, 0x65,
	0x74, 0x2d, 0x63, 0x6f, 0x2f, 0x73, 0x61, 0x69, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x78, 0x2d,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2d, 0x67, 0x65,
	0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73,
	0x75, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cosmos_consensus_v1_tx_proto_rawDescOnce sync.Once
	file_cosmos_consensus_v1_tx_proto_rawDescData = file_cosmos_consensus_v1_tx_proto_rawDesc
)

func file_cosmos_consensus_v1_tx_proto_rawDescGZIP() []byte {
	file_cosmos_consensus_v1_tx_proto_rawDescOnce.Do(func() {
		file_cosmos_consensus_v1_tx_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_consensus_v1_tx_proto_rawDescData)
	})
	return file_cosmos_consensus_v1_tx_proto_rawDescData
}

var file_cosmos_consensus_v1_tx_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cosmos_consensus_v1_tx_proto_goTypes = []interface{}{
	(*MsgUpdateParams)(nil),         // 0: cosmos.consensus.v1.MsgUpdateParams
	(*MsgUpdateParamsResponse)(nil), // 1: cosmos.consensus.v1.MsgUpdateParamsResponse
	(*types.BlockParams)(nil),       // 2: tendermint.types.BlockParams
	(*types.EvidenceParams)(nil),    // 3: tendermint.types.EvidenceParams
	(*types.ValidatorParams)(nil),   // 4: tendermint.types.ValidatorParams
}
var file_cosmos_consensus_v1_tx_proto_depIdxs = []int32{
	2, // 0: cosmos.consensus.v1.MsgUpdateParams.block:type_name -> tendermint.types.BlockParams
	3, // 1: cosmos.consensus.v1.MsgUpdateParams.evidence:type_name -> tendermint.types.EvidenceParams
	4, // 2: cosmos.consensus.v1.MsgUpdateParams.validator:type_name -> tendermint.types.ValidatorParams
	0, // 3: cosmos.consensus.v1.Msg.UpdateParams:input_type -> cosmos.consensus.v1.MsgUpdateParams
	1, // 4: cosmos.consensus.v1.Msg.UpdateParams:output_type -> cosmos.consensus.v1.MsgUpdateParamsResponse
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_cosmos_consensus_v1_tx_proto_init() }
func file_cosmos_consensus_v1_tx_proto_init() {
	if File_cosmos_consensus_v1_tx_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cosmos_consensus_v1_tx_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MsgUpdateParams); i {
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
		file_cosmos_consensus_v1_tx_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MsgUpdateParamsResponse); i {
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
			RawDescriptor: file_cosmos_consensus_v1_tx_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cosmos_consensus_v1_tx_proto_goTypes,
		DependencyIndexes: file_cosmos_consensus_v1_tx_proto_depIdxs,
		MessageInfos:      file_cosmos_consensus_v1_tx_proto_msgTypes,
	}.Build()
	File_cosmos_consensus_v1_tx_proto = out.File
	file_cosmos_consensus_v1_tx_proto_rawDesc = nil
	file_cosmos_consensus_v1_tx_proto_goTypes = nil
	file_cosmos_consensus_v1_tx_proto_depIdxs = nil
}
