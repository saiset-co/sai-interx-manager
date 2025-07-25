// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: kira/tokens/rate.proto

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

type TokenRate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Denom       string `protobuf:"bytes,1,opt,name=denom,proto3" json:"denom,omitempty"`                                 // denomination target
	FeeRate     string `protobuf:"bytes,2,opt,name=fee_rate,json=feeRate,proto3" json:"fee_rate,omitempty"`              // Exchange rate in terms of KEX token
	FeePayments bool   `protobuf:"varint,3,opt,name=fee_payments,json=feePayments,proto3" json:"fee_payments,omitempty"` // Properties defining if it is enabled or disabled as fee payment method
	StakeCap    string `protobuf:"bytes,4,opt,name=stake_cap,json=stakeCap,proto3" json:"stake_cap,omitempty"`           // rewards cap, sum should be lower than 100%
	StakeMin    string `protobuf:"bytes,5,opt,name=stake_min,json=stakeMin,proto3" json:"stake_min,omitempty"`
	StakeToken  bool   `protobuf:"varint,6,opt,name=stake_token,json=stakeToken,proto3" json:"stake_token,omitempty"`
	Invalidated bool   `protobuf:"varint,7,opt,name=invalidated,proto3" json:"invalidated,omitempty"` // flag that the token is invalidated or not
}

func (x *TokenRate) Reset() {
	*x = TokenRate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_tokens_rate_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TokenRate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TokenRate) ProtoMessage() {}

func (x *TokenRate) ProtoReflect() protoreflect.Message {
	mi := &file_kira_tokens_rate_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TokenRate.ProtoReflect.Descriptor instead.
func (*TokenRate) Descriptor() ([]byte, []int) {
	return file_kira_tokens_rate_proto_rawDescGZIP(), []int{0}
}

func (x *TokenRate) GetDenom() string {
	if x != nil {
		return x.Denom
	}
	return ""
}

func (x *TokenRate) GetFeeRate() string {
	if x != nil {
		return x.FeeRate
	}
	return ""
}

func (x *TokenRate) GetFeePayments() bool {
	if x != nil {
		return x.FeePayments
	}
	return false
}

func (x *TokenRate) GetStakeCap() string {
	if x != nil {
		return x.StakeCap
	}
	return ""
}

func (x *TokenRate) GetStakeMin() string {
	if x != nil {
		return x.StakeMin
	}
	return ""
}

func (x *TokenRate) GetStakeToken() bool {
	if x != nil {
		return x.StakeToken
	}
	return false
}

func (x *TokenRate) GetInvalidated() bool {
	if x != nil {
		return x.Invalidated
	}
	return false
}

type MsgUpsertTokenRate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Denom       string `protobuf:"bytes,1,opt,name=denom,proto3" json:"denom,omitempty"`                                 // denomination target
	Rate        string `protobuf:"bytes,2,opt,name=rate,proto3" json:"rate,omitempty"`                                   // Exchange rate in terms of KEX token
	FeePayments bool   `protobuf:"varint,3,opt,name=fee_payments,json=feePayments,proto3" json:"fee_payments,omitempty"` // Properties defining if it is enabled or disabled as fee payment method
	StakeCap    string `protobuf:"bytes,4,opt,name=stake_cap,json=stakeCap,proto3" json:"stake_cap,omitempty"`           // rewards cap, sum should be lower than 100%
	StakeMin    string `protobuf:"bytes,5,opt,name=stake_min,json=stakeMin,proto3" json:"stake_min,omitempty"`
	StakeToken  bool   `protobuf:"varint,6,opt,name=stake_token,json=stakeToken,proto3" json:"stake_token,omitempty"`
	Invalidated bool   `protobuf:"varint,7,opt,name=invalidated,proto3" json:"invalidated,omitempty"` // flag that the token is invalidated or not
	Proposer    []byte `protobuf:"bytes,8,opt,name=proposer,proto3" json:"proposer,omitempty"`
}

func (x *MsgUpsertTokenRate) Reset() {
	*x = MsgUpsertTokenRate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_tokens_rate_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MsgUpsertTokenRate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgUpsertTokenRate) ProtoMessage() {}

func (x *MsgUpsertTokenRate) ProtoReflect() protoreflect.Message {
	mi := &file_kira_tokens_rate_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgUpsertTokenRate.ProtoReflect.Descriptor instead.
func (*MsgUpsertTokenRate) Descriptor() ([]byte, []int) {
	return file_kira_tokens_rate_proto_rawDescGZIP(), []int{1}
}

func (x *MsgUpsertTokenRate) GetDenom() string {
	if x != nil {
		return x.Denom
	}
	return ""
}

func (x *MsgUpsertTokenRate) GetRate() string {
	if x != nil {
		return x.Rate
	}
	return ""
}

func (x *MsgUpsertTokenRate) GetFeePayments() bool {
	if x != nil {
		return x.FeePayments
	}
	return false
}

func (x *MsgUpsertTokenRate) GetStakeCap() string {
	if x != nil {
		return x.StakeCap
	}
	return ""
}

func (x *MsgUpsertTokenRate) GetStakeMin() string {
	if x != nil {
		return x.StakeMin
	}
	return ""
}

func (x *MsgUpsertTokenRate) GetStakeToken() bool {
	if x != nil {
		return x.StakeToken
	}
	return false
}

func (x *MsgUpsertTokenRate) GetInvalidated() bool {
	if x != nil {
		return x.Invalidated
	}
	return false
}

func (x *MsgUpsertTokenRate) GetProposer() []byte {
	if x != nil {
		return x.Proposer
	}
	return nil
}

var File_kira_tokens_rate_proto protoreflect.FileDescriptor

var file_kira_tokens_rate_proto_rawDesc = []byte{
	0x0a, 0x16, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2f, 0x72, 0x61,
	0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa7, 0x03, 0x0a, 0x09,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6e,
	0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x64, 0x65, 0x6e, 0x6f, 0x6d, 0x12,
	0x5c, 0x0a, 0x08, 0x66, 0x65, 0x65, 0x5f, 0x72, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x41, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x73,
	0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x65,
	0x63, 0xf2, 0xde, 0x1f, 0x0f, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x66, 0x65, 0x65, 0x5f, 0x72,
	0x61, 0x74, 0x65, 0x22, 0x52, 0x07, 0x66, 0x65, 0x65, 0x52, 0x61, 0x74, 0x65, 0x12, 0x21, 0x0a,
	0x0c, 0x66, 0x65, 0x65, 0x5f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0b, 0x66, 0x65, 0x65, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73,
	0x12, 0x5f, 0x0a, 0x09, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x63, 0x61, 0x70, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x42, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x26, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63,
	0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x44, 0x65, 0x63, 0xf2, 0xde, 0x1f, 0x10, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x73, 0x74, 0x61,
	0x6b, 0x65, 0x5f, 0x63, 0x61, 0x70, 0x22, 0x52, 0x08, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x43, 0x61,
	0x70, 0x12, 0x5f, 0x0a, 0x09, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x6d, 0x69, 0x6e, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x42, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x26, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x2e, 0x49, 0x6e, 0x74, 0xf2, 0xde, 0x1f, 0x10, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x73, 0x74,
	0x61, 0x6b, 0x65, 0x5f, 0x6d, 0x69, 0x6e, 0x22, 0x52, 0x08, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x4d,
	0x69, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x64, 0x22, 0x87, 0x04, 0x0a, 0x12, 0x4d, 0x73, 0x67, 0x55, 0x70, 0x73,
	0x65, 0x72, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x61, 0x74, 0x65, 0x12, 0x14, 0x0a, 0x05,
	0x64, 0x65, 0x6e, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x64, 0x65, 0x6e,
	0x6f, 0x6d, 0x12, 0x51, 0x0a, 0x04, 0x72, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x3d, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x65, 0x63,
	0xf2, 0xde, 0x1f, 0x0b, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x72, 0x61, 0x74, 0x65, 0x22, 0x52,
	0x04, 0x72, 0x61, 0x74, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x65, 0x65, 0x5f, 0x70, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x66, 0x65, 0x65,
	0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x5f, 0x0a, 0x09, 0x73, 0x74, 0x61, 0x6b,
	0x65, 0x5f, 0x63, 0x61, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x42, 0xc8, 0xde, 0x1f,
	0x00, 0xda, 0xde, 0x1f, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64,
	0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x65, 0x63, 0xf2, 0xde, 0x1f, 0x10, 0x79,
	0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x63, 0x61, 0x70, 0x22, 0x52,
	0x08, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x43, 0x61, 0x70, 0x12, 0x5f, 0x0a, 0x09, 0x73, 0x74, 0x61,
	0x6b, 0x65, 0x5f, 0x6d, 0x69, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x42, 0x42, 0xc8, 0xde,
	0x1f, 0x00, 0xda, 0xde, 0x1f, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73,
	0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x49, 0x6e, 0x74, 0xf2, 0xde, 0x1f, 0x10,
	0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x6d, 0x69, 0x6e, 0x22,
	0x52, 0x08, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x4d, 0x69, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x74,
	0x61, 0x6b, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0a, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x69,
	0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0b, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x64, 0x12, 0x60, 0x0a,
	0x08, 0x70, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x72, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x42,
	0x44, 0xf2, 0xde, 0x1f, 0x0f, 0x79, 0x61, 0x6d, 0x6c, 0x3a, 0x22, 0x70, 0x72, 0x6f, 0x70, 0x6f,
	0x73, 0x65, 0x72, 0x22, 0xfa, 0xde, 0x1f, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x41, 0x63, 0x63, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x72, 0x42,
	0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x69,
	0x72, 0x61, 0x43, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x65, 0x6b, 0x61, 0x69, 0x2f, 0x78, 0x2f, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_kira_tokens_rate_proto_rawDescOnce sync.Once
	file_kira_tokens_rate_proto_rawDescData = file_kira_tokens_rate_proto_rawDesc
)

func file_kira_tokens_rate_proto_rawDescGZIP() []byte {
	file_kira_tokens_rate_proto_rawDescOnce.Do(func() {
		file_kira_tokens_rate_proto_rawDescData = protoimpl.X.CompressGZIP(file_kira_tokens_rate_proto_rawDescData)
	})
	return file_kira_tokens_rate_proto_rawDescData
}

var file_kira_tokens_rate_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_kira_tokens_rate_proto_goTypes = []interface{}{
	(*TokenRate)(nil),          // 0: kira.tokens.TokenRate
	(*MsgUpsertTokenRate)(nil), // 1: kira.tokens.MsgUpsertTokenRate
}
var file_kira_tokens_rate_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_kira_tokens_rate_proto_init() }
func file_kira_tokens_rate_proto_init() {
	if File_kira_tokens_rate_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_kira_tokens_rate_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TokenRate); i {
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
		file_kira_tokens_rate_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MsgUpsertTokenRate); i {
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
			RawDescriptor: file_kira_tokens_rate_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_kira_tokens_rate_proto_goTypes,
		DependencyIndexes: file_kira_tokens_rate_proto_depIdxs,
		MessageInfos:      file_kira_tokens_rate_proto_msgTypes,
	}.Build()
	File_kira_tokens_rate_proto = out.File
	file_kira_tokens_rate_proto_rawDesc = nil
	file_kira_tokens_rate_proto_goTypes = nil
	file_kira_tokens_rate_proto_depIdxs = nil
}
