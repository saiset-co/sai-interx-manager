// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/staking/v1beta1/authz.proto

package types

import (
	_ "github.com/cosmos/cosmos-proto"
	_ "github.com/cosmos/cosmos-sdk/types/tx/amino"
	_ "github.com/gogo/protobuf/gogoproto"
	v1beta1 "github.com/saiset-co/sai-interx-manager/proto-gen/cosmos/base/v1beta1"
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

// AuthorizationType defines the type of staking module authorization type
//
// Since: cosmos-sdk 0.43
type AuthorizationType int32

const (
	// AUTHORIZATION_TYPE_UNSPECIFIED specifies an unknown authorization type
	AuthorizationType_AUTHORIZATION_TYPE_UNSPECIFIED AuthorizationType = 0
	// AUTHORIZATION_TYPE_DELEGATE defines an authorization type for Msg/Delegate
	AuthorizationType_AUTHORIZATION_TYPE_DELEGATE AuthorizationType = 1
	// AUTHORIZATION_TYPE_UNDELEGATE defines an authorization type for Msg/Undelegate
	AuthorizationType_AUTHORIZATION_TYPE_UNDELEGATE AuthorizationType = 2
	// AUTHORIZATION_TYPE_REDELEGATE defines an authorization type for Msg/BeginRedelegate
	AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE AuthorizationType = 3
)

// Enum value maps for AuthorizationType.
var (
	AuthorizationType_name = map[int32]string{
		0: "AUTHORIZATION_TYPE_UNSPECIFIED",
		1: "AUTHORIZATION_TYPE_DELEGATE",
		2: "AUTHORIZATION_TYPE_UNDELEGATE",
		3: "AUTHORIZATION_TYPE_REDELEGATE",
	}
	AuthorizationType_value = map[string]int32{
		"AUTHORIZATION_TYPE_UNSPECIFIED": 0,
		"AUTHORIZATION_TYPE_DELEGATE":    1,
		"AUTHORIZATION_TYPE_UNDELEGATE":  2,
		"AUTHORIZATION_TYPE_REDELEGATE":  3,
	}
)

func (x AuthorizationType) Enum() *AuthorizationType {
	p := new(AuthorizationType)
	*p = x
	return p
}

func (x AuthorizationType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AuthorizationType) Descriptor() protoreflect.EnumDescriptor {
	return file_cosmos_staking_v1beta1_authz_proto_enumTypes[0].Descriptor()
}

func (AuthorizationType) Type() protoreflect.EnumType {
	return &file_cosmos_staking_v1beta1_authz_proto_enumTypes[0]
}

func (x AuthorizationType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AuthorizationType.Descriptor instead.
func (AuthorizationType) EnumDescriptor() ([]byte, []int) {
	return file_cosmos_staking_v1beta1_authz_proto_rawDescGZIP(), []int{0}
}

// StakeAuthorization defines authorization for delegate/undelegate/redelegate.
//
// Since: cosmos-sdk 0.43
type StakeAuthorization struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// max_tokens specifies the maximum amount of tokens can be delegate to a validator. If it is
	// empty, there is no spend limit and any amount of coins can be delegated.
	MaxTokens *v1beta1.Coin `protobuf:"bytes,1,opt,name=max_tokens,json=maxTokens,proto3" json:"max_tokens,omitempty"`
	// validators is the oneof that represents either allow_list or deny_list
	//
	// Types that are assignable to Validators:
	//
	//	*StakeAuthorization_AllowList
	//	*StakeAuthorization_DenyList
	Validators isStakeAuthorization_Validators `protobuf_oneof:"validators"`
	// authorization_type defines one of AuthorizationType.
	AuthorizationType AuthorizationType `protobuf:"varint,4,opt,name=authorization_type,json=authorizationType,proto3,enum=cosmos.staking.v1beta1.AuthorizationType" json:"authorization_type,omitempty"`
}

func (x *StakeAuthorization) Reset() {
	*x = StakeAuthorization{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_staking_v1beta1_authz_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StakeAuthorization) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StakeAuthorization) ProtoMessage() {}

func (x *StakeAuthorization) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_staking_v1beta1_authz_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StakeAuthorization.ProtoReflect.Descriptor instead.
func (*StakeAuthorization) Descriptor() ([]byte, []int) {
	return file_cosmos_staking_v1beta1_authz_proto_rawDescGZIP(), []int{0}
}

func (x *StakeAuthorization) GetMaxTokens() *v1beta1.Coin {
	if x != nil {
		return x.MaxTokens
	}
	return nil
}

func (m *StakeAuthorization) GetValidators() isStakeAuthorization_Validators {
	if m != nil {
		return m.Validators
	}
	return nil
}

func (x *StakeAuthorization) GetAllowList() *StakeAuthorization_Validators {
	if x, ok := x.GetValidators().(*StakeAuthorization_AllowList); ok {
		return x.AllowList
	}
	return nil
}

func (x *StakeAuthorization) GetDenyList() *StakeAuthorization_Validators {
	if x, ok := x.GetValidators().(*StakeAuthorization_DenyList); ok {
		return x.DenyList
	}
	return nil
}

func (x *StakeAuthorization) GetAuthorizationType() AuthorizationType {
	if x != nil {
		return x.AuthorizationType
	}
	return AuthorizationType_AUTHORIZATION_TYPE_UNSPECIFIED
}

type isStakeAuthorization_Validators interface {
	isStakeAuthorization_Validators()
}

type StakeAuthorization_AllowList struct {
	// allow_list specifies list of validator addresses to whom grantee can delegate tokens on behalf of granter's
	// account.
	AllowList *StakeAuthorization_Validators `protobuf:"bytes,2,opt,name=allow_list,json=allowList,proto3,oneof"`
}

type StakeAuthorization_DenyList struct {
	// deny_list specifies list of validator addresses to whom grantee can not delegate tokens.
	DenyList *StakeAuthorization_Validators `protobuf:"bytes,3,opt,name=deny_list,json=denyList,proto3,oneof"`
}

func (*StakeAuthorization_AllowList) isStakeAuthorization_Validators() {}

func (*StakeAuthorization_DenyList) isStakeAuthorization_Validators() {}

// Validators defines list of validator addresses.
type StakeAuthorization_Validators struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address []string `protobuf:"bytes,1,rep,name=address,proto3" json:"address,omitempty"`
}

func (x *StakeAuthorization_Validators) Reset() {
	*x = StakeAuthorization_Validators{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_staking_v1beta1_authz_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StakeAuthorization_Validators) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StakeAuthorization_Validators) ProtoMessage() {}

func (x *StakeAuthorization_Validators) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_staking_v1beta1_authz_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StakeAuthorization_Validators.ProtoReflect.Descriptor instead.
func (*StakeAuthorization_Validators) Descriptor() ([]byte, []int) {
	return file_cosmos_staking_v1beta1_authz_proto_rawDescGZIP(), []int{0, 0}
}

func (x *StakeAuthorization_Validators) GetAddress() []string {
	if x != nil {
		return x.Address
	}
	return nil
}

var File_cosmos_staking_v1beta1_authz_proto protoreflect.FileDescriptor

var file_cosmos_staking_v1beta1_authz_proto_rawDesc = []byte{
	0x0a, 0x22, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67,
	0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61,
	0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x14, 0x67, 0x6f,
	0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x19, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x63,
	0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2f, 0x63, 0x6f, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x61,
	0x6d, 0x69, 0x6e, 0x6f, 0x2f, 0x61, 0x6d, 0x69, 0x6e, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x9d, 0x04, 0x0a, 0x12, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x65, 0x0a, 0x0a, 0x6d, 0x61, 0x78, 0x5f, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61,
	0x31, 0x2e, 0x43, 0x6f, 0x69, 0x6e, 0x42, 0x2b, 0xaa, 0xdf, 0x1f, 0x27, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x43,
	0x6f, 0x69, 0x6e, 0x52, 0x09, 0x6d, 0x61, 0x78, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x12, 0x56,
	0x0a, 0x0a, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x35, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x6b,
	0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x6b,
	0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x56,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x73, 0x48, 0x00, 0x52, 0x09, 0x61, 0x6c, 0x6c,
	0x6f, 0x77, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x54, 0x0a, 0x09, 0x64, 0x65, 0x6e, 0x79, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x73,
	0x48, 0x00, 0x52, 0x08, 0x64, 0x65, 0x6e, 0x79, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x58, 0x0a, 0x12,
	0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2e, 0x73, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61,
	0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x11, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x1a, 0x40, 0x0a, 0x0a, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x6f, 0x72, 0x73, 0x12, 0x32, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x42, 0x18, 0xd2, 0xb4, 0x2d, 0x14, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52,
	0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x3a, 0x48, 0xca, 0xb4, 0x2d, 0x22, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x7a, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x8a, 0xe7, 0xb0, 0x2a, 0x1d, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f,
	0x53, 0x74, 0x61, 0x6b, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x42, 0x0c, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x73,
	0x2a, 0x9e, 0x01, 0x0a, 0x11, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x22, 0x0a, 0x1e, 0x41, 0x55, 0x54, 0x48, 0x4f, 0x52,
	0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1f, 0x0a, 0x1b, 0x41, 0x55,
	0x54, 0x48, 0x4f, 0x52, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x54, 0x59, 0x50, 0x45,
	0x5f, 0x44, 0x45, 0x4c, 0x45, 0x47, 0x41, 0x54, 0x45, 0x10, 0x01, 0x12, 0x21, 0x0a, 0x1d, 0x41,
	0x55, 0x54, 0x48, 0x4f, 0x52, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x55, 0x4e, 0x44, 0x45, 0x4c, 0x45, 0x47, 0x41, 0x54, 0x45, 0x10, 0x02, 0x12, 0x21,
	0x0a, 0x1d, 0x41, 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x52, 0x45, 0x44, 0x45, 0x4c, 0x45, 0x47, 0x41, 0x54, 0x45, 0x10,
	0x03, 0x42, 0x48, 0x5a, 0x46, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x73, 0x61, 0x69, 0x73, 0x65, 0x74, 0x2d, 0x63, 0x6f, 0x2f, 0x73, 0x61, 0x69, 0x2d, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x78, 0x2d, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x73, 0x74,
	0x61, 0x6b, 0x69, 0x6e, 0x67, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_cosmos_staking_v1beta1_authz_proto_rawDescOnce sync.Once
	file_cosmos_staking_v1beta1_authz_proto_rawDescData = file_cosmos_staking_v1beta1_authz_proto_rawDesc
)

func file_cosmos_staking_v1beta1_authz_proto_rawDescGZIP() []byte {
	file_cosmos_staking_v1beta1_authz_proto_rawDescOnce.Do(func() {
		file_cosmos_staking_v1beta1_authz_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_staking_v1beta1_authz_proto_rawDescData)
	})
	return file_cosmos_staking_v1beta1_authz_proto_rawDescData
}

var file_cosmos_staking_v1beta1_authz_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_cosmos_staking_v1beta1_authz_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cosmos_staking_v1beta1_authz_proto_goTypes = []interface{}{
	(AuthorizationType)(0),                // 0: cosmos.staking.v1beta1.AuthorizationType
	(*StakeAuthorization)(nil),            // 1: cosmos.staking.v1beta1.StakeAuthorization
	(*StakeAuthorization_Validators)(nil), // 2: cosmos.staking.v1beta1.StakeAuthorization.Validators
	(*v1beta1.Coin)(nil),                  // 3: cosmos.base.v1beta1.Coin
}
var file_cosmos_staking_v1beta1_authz_proto_depIdxs = []int32{
	3, // 0: cosmos.staking.v1beta1.StakeAuthorization.max_tokens:type_name -> cosmos.base.v1beta1.Coin
	2, // 1: cosmos.staking.v1beta1.StakeAuthorization.allow_list:type_name -> cosmos.staking.v1beta1.StakeAuthorization.Validators
	2, // 2: cosmos.staking.v1beta1.StakeAuthorization.deny_list:type_name -> cosmos.staking.v1beta1.StakeAuthorization.Validators
	0, // 3: cosmos.staking.v1beta1.StakeAuthorization.authorization_type:type_name -> cosmos.staking.v1beta1.AuthorizationType
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_cosmos_staking_v1beta1_authz_proto_init() }
func file_cosmos_staking_v1beta1_authz_proto_init() {
	if File_cosmos_staking_v1beta1_authz_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cosmos_staking_v1beta1_authz_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StakeAuthorization); i {
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
		file_cosmos_staking_v1beta1_authz_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StakeAuthorization_Validators); i {
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
	file_cosmos_staking_v1beta1_authz_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*StakeAuthorization_AllowList)(nil),
		(*StakeAuthorization_DenyList)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cosmos_staking_v1beta1_authz_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cosmos_staking_v1beta1_authz_proto_goTypes,
		DependencyIndexes: file_cosmos_staking_v1beta1_authz_proto_depIdxs,
		EnumInfos:         file_cosmos_staking_v1beta1_authz_proto_enumTypes,
		MessageInfos:      file_cosmos_staking_v1beta1_authz_proto_msgTypes,
	}.Build()
	File_cosmos_staking_v1beta1_authz_proto = out.File
	file_cosmos_staking_v1beta1_authz_proto_rawDesc = nil
	file_cosmos_staking_v1beta1_authz_proto_goTypes = nil
	file_cosmos_staking_v1beta1_authz_proto_depIdxs = nil
}
