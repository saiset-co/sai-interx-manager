// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/slashing/v1beta1/genesis.proto

package types

import (
	_ "github.com/cosmos/cosmos-proto"
	_ "github.com/cosmos/cosmos-sdk/types/tx/amino"
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

	// params defines all the parameters of the module.
	Params *Params `protobuf:"bytes,1,opt,name=params,proto3" json:"params,omitempty"`
	// signing_infos represents a map between validator addresses and their
	// signing infos.
	SigningInfos []*SigningInfo `protobuf:"bytes,2,rep,name=signing_infos,json=signingInfos,proto3" json:"signing_infos,omitempty"`
	// missed_blocks represents a map between validator addresses and their
	// missed blocks.
	MissedBlocks []*ValidatorMissedBlocks `protobuf:"bytes,3,rep,name=missed_blocks,json=missedBlocks,proto3" json:"missed_blocks,omitempty"`
}

func (x *GenesisState) Reset() {
	*x = GenesisState{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenesisState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenesisState) ProtoMessage() {}

func (x *GenesisState) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[0]
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
	return file_cosmos_slashing_v1beta1_genesis_proto_rawDescGZIP(), []int{0}
}

func (x *GenesisState) GetParams() *Params {
	if x != nil {
		return x.Params
	}
	return nil
}

func (x *GenesisState) GetSigningInfos() []*SigningInfo {
	if x != nil {
		return x.SigningInfos
	}
	return nil
}

func (x *GenesisState) GetMissedBlocks() []*ValidatorMissedBlocks {
	if x != nil {
		return x.MissedBlocks
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
		mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SigningInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningInfo) ProtoMessage() {}

func (x *SigningInfo) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[1]
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
	return file_cosmos_slashing_v1beta1_genesis_proto_rawDescGZIP(), []int{1}
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

// ValidatorMissedBlocks contains array of missed blocks of corresponding
// address.
type ValidatorMissedBlocks struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// address is the validator address.
	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	// missed_blocks is an array of missed blocks by the validator.
	MissedBlocks []*MissedBlock `protobuf:"bytes,2,rep,name=missed_blocks,json=missedBlocks,proto3" json:"missed_blocks,omitempty"`
}

func (x *ValidatorMissedBlocks) Reset() {
	*x = ValidatorMissedBlocks{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValidatorMissedBlocks) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidatorMissedBlocks) ProtoMessage() {}

func (x *ValidatorMissedBlocks) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidatorMissedBlocks.ProtoReflect.Descriptor instead.
func (*ValidatorMissedBlocks) Descriptor() ([]byte, []int) {
	return file_cosmos_slashing_v1beta1_genesis_proto_rawDescGZIP(), []int{2}
}

func (x *ValidatorMissedBlocks) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *ValidatorMissedBlocks) GetMissedBlocks() []*MissedBlock {
	if x != nil {
		return x.MissedBlocks
	}
	return nil
}

// MissedBlock contains height and missed status as boolean.
type MissedBlock struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// index is the height at which the block was missed.
	Index int64 `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	// missed is the missed status.
	Missed bool `protobuf:"varint,2,opt,name=missed,proto3" json:"missed,omitempty"`
}

func (x *MissedBlock) Reset() {
	*x = MissedBlock{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MissedBlock) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MissedBlock) ProtoMessage() {}

func (x *MissedBlock) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MissedBlock.ProtoReflect.Descriptor instead.
func (*MissedBlock) Descriptor() ([]byte, []int) {
	return file_cosmos_slashing_v1beta1_genesis_proto_rawDescGZIP(), []int{3}
}

func (x *MissedBlock) GetIndex() int64 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *MissedBlock) GetMissed() bool {
	if x != nil {
		return x.Missed
	}
	return false
}

var File_cosmos_slashing_v1beta1_genesis_proto protoreflect.FileDescriptor

var file_cosmos_slashing_v1beta1_genesis_proto_rawDesc = []byte{
	0x0a, 0x25, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e,
	0x67, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x73, 0x69,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e,
	0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x67, 0x6f,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x26, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x73,
	0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f,
	0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x73,
	0x6d, 0x6f, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x61, 0x6d, 0x69, 0x6e, 0x6f,
	0x2f, 0x61, 0x6d, 0x69, 0x6e, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x88, 0x02, 0x0a,
	0x0c, 0x47, 0x65, 0x6e, 0x65, 0x73, 0x69, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x42, 0x0a,
	0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x42, 0x09,
	0xc8, 0xde, 0x1f, 0x00, 0xa8, 0xe7, 0xb0, 0x2a, 0x01, 0x52, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d,
	0x73, 0x12, 0x54, 0x0a, 0x0d, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x69, 0x6e, 0x66,
	0x6f, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2e, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x09,
	0xc8, 0xde, 0x1f, 0x00, 0xa8, 0xe7, 0xb0, 0x2a, 0x01, 0x52, 0x0c, 0x73, 0x69, 0x67, 0x6e, 0x69,
	0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x73, 0x12, 0x5e, 0x0a, 0x0d, 0x6d, 0x69, 0x73, 0x73, 0x65,
	0x64, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e,
	0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67,
	0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x6f, 0x72, 0x4d, 0x69, 0x73, 0x73, 0x65, 0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x42, 0x09,
	0xc8, 0xde, 0x1f, 0x00, 0xa8, 0xe7, 0xb0, 0x2a, 0x01, 0x52, 0x0c, 0x6d, 0x69, 0x73, 0x73, 0x65,
	0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x22, 0xb1, 0x01, 0x0a, 0x0b, 0x53, 0x69, 0x67, 0x6e,
	0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x32, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x18, 0xd2, 0xb4, 0x2d, 0x14, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x6e, 0x0a, 0x16, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31,
	0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x53,
	0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x09, 0xc8, 0xde, 0x1f, 0x00,
	0xa8, 0xe7, 0xb0, 0x2a, 0x01, 0x52, 0x14, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72,
	0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x22, 0xa1, 0x01, 0x0a, 0x15,
	0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x4d, 0x69, 0x73, 0x73, 0x65, 0x64, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x12, 0x32, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x18, 0xd2, 0xb4, 0x2d, 0x14, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x54, 0x0a, 0x0d, 0x6d, 0x69, 0x73,
	0x73, 0x65, 0x64, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x24, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69,
	0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x4d, 0x69, 0x73, 0x73, 0x65,
	0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x42, 0x09, 0xc8, 0xde, 0x1f, 0x00, 0xa8, 0xe7, 0xb0, 0x2a,
	0x01, 0x52, 0x0c, 0x6d, 0x69, 0x73, 0x73, 0x65, 0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x22,
	0x3b, 0x0a, 0x0b, 0x4d, 0x69, 0x73, 0x73, 0x65, 0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x14,
	0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x69, 0x73, 0x73, 0x65, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x6d, 0x69, 0x73, 0x73, 0x65, 0x64, 0x42, 0x49, 0x5a, 0x47,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x69, 0x73, 0x65,
	0x74, 0x2d, 0x63, 0x6f, 0x2f, 0x73, 0x61, 0x69, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x78, 0x2d,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2d, 0x67, 0x65,
	0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e,
	0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cosmos_slashing_v1beta1_genesis_proto_rawDescOnce sync.Once
	file_cosmos_slashing_v1beta1_genesis_proto_rawDescData = file_cosmos_slashing_v1beta1_genesis_proto_rawDesc
)

func file_cosmos_slashing_v1beta1_genesis_proto_rawDescGZIP() []byte {
	file_cosmos_slashing_v1beta1_genesis_proto_rawDescOnce.Do(func() {
		file_cosmos_slashing_v1beta1_genesis_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_slashing_v1beta1_genesis_proto_rawDescData)
	})
	return file_cosmos_slashing_v1beta1_genesis_proto_rawDescData
}

var file_cosmos_slashing_v1beta1_genesis_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_cosmos_slashing_v1beta1_genesis_proto_goTypes = []interface{}{
	(*GenesisState)(nil),          // 0: cosmos.slashing.v1beta1.GenesisState
	(*SigningInfo)(nil),           // 1: cosmos.slashing.v1beta1.SigningInfo
	(*ValidatorMissedBlocks)(nil), // 2: cosmos.slashing.v1beta1.ValidatorMissedBlocks
	(*MissedBlock)(nil),           // 3: cosmos.slashing.v1beta1.MissedBlock
	(*Params)(nil),                // 4: cosmos.slashing.v1beta1.Params
	(*ValidatorSigningInfo)(nil),  // 5: cosmos.slashing.v1beta1.ValidatorSigningInfo
}
var file_cosmos_slashing_v1beta1_genesis_proto_depIdxs = []int32{
	4, // 0: cosmos.slashing.v1beta1.GenesisState.params:type_name -> cosmos.slashing.v1beta1.Params
	1, // 1: cosmos.slashing.v1beta1.GenesisState.signing_infos:type_name -> cosmos.slashing.v1beta1.SigningInfo
	2, // 2: cosmos.slashing.v1beta1.GenesisState.missed_blocks:type_name -> cosmos.slashing.v1beta1.ValidatorMissedBlocks
	5, // 3: cosmos.slashing.v1beta1.SigningInfo.validator_signing_info:type_name -> cosmos.slashing.v1beta1.ValidatorSigningInfo
	3, // 4: cosmos.slashing.v1beta1.ValidatorMissedBlocks.missed_blocks:type_name -> cosmos.slashing.v1beta1.MissedBlock
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_cosmos_slashing_v1beta1_genesis_proto_init() }
func file_cosmos_slashing_v1beta1_genesis_proto_init() {
	if File_cosmos_slashing_v1beta1_genesis_proto != nil {
		return
	}
	file_cosmos_slashing_v1beta1_slashing_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValidatorMissedBlocks); i {
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
		file_cosmos_slashing_v1beta1_genesis_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MissedBlock); i {
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
			RawDescriptor: file_cosmos_slashing_v1beta1_genesis_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cosmos_slashing_v1beta1_genesis_proto_goTypes,
		DependencyIndexes: file_cosmos_slashing_v1beta1_genesis_proto_depIdxs,
		MessageInfos:      file_cosmos_slashing_v1beta1_genesis_proto_msgTypes,
	}.Build()
	File_cosmos_slashing_v1beta1_genesis_proto = out.File
	file_cosmos_slashing_v1beta1_genesis_proto_rawDesc = nil
	file_cosmos_slashing_v1beta1_genesis_proto_goTypes = nil
	file_cosmos_slashing_v1beta1_genesis_proto_depIdxs = nil
}
