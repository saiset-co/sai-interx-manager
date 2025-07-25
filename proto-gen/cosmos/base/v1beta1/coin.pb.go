// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/base/v1beta1/coin.proto

package v1beta1

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

// Coin defines a token with a denomination and an amount.
//
// NOTE: The amount field is an Int which implements the custom method
// signatures required by gogoproto.
type Coin struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Denom  string `protobuf:"bytes,1,opt,name=denom,proto3" json:"denom,omitempty"`
	Amount string `protobuf:"bytes,2,opt,name=amount,proto3" json:"amount,omitempty"`
}

func (x *Coin) Reset() {
	*x = Coin{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Coin) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Coin) ProtoMessage() {}

func (x *Coin) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Coin.ProtoReflect.Descriptor instead.
func (*Coin) Descriptor() ([]byte, []int) {
	return file_cosmos_base_v1beta1_coin_proto_rawDescGZIP(), []int{0}
}

func (x *Coin) GetDenom() string {
	if x != nil {
		return x.Denom
	}
	return ""
}

func (x *Coin) GetAmount() string {
	if x != nil {
		return x.Amount
	}
	return ""
}

// DecCoin defines a token with a denomination and a decimal amount.
//
// NOTE: The amount field is an Dec which implements the custom method
// signatures required by gogoproto.
type DecCoin struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Denom  string `protobuf:"bytes,1,opt,name=denom,proto3" json:"denom,omitempty"`
	Amount string `protobuf:"bytes,2,opt,name=amount,proto3" json:"amount,omitempty"`
}

func (x *DecCoin) Reset() {
	*x = DecCoin{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecCoin) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecCoin) ProtoMessage() {}

func (x *DecCoin) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecCoin.ProtoReflect.Descriptor instead.
func (*DecCoin) Descriptor() ([]byte, []int) {
	return file_cosmos_base_v1beta1_coin_proto_rawDescGZIP(), []int{1}
}

func (x *DecCoin) GetDenom() string {
	if x != nil {
		return x.Denom
	}
	return ""
}

func (x *DecCoin) GetAmount() string {
	if x != nil {
		return x.Amount
	}
	return ""
}

// IntProto defines a Protobuf wrapper around an Int object.
type IntProto struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Int string `protobuf:"bytes,1,opt,name=int,proto3" json:"int,omitempty"`
}

func (x *IntProto) Reset() {
	*x = IntProto{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IntProto) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntProto) ProtoMessage() {}

func (x *IntProto) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntProto.ProtoReflect.Descriptor instead.
func (*IntProto) Descriptor() ([]byte, []int) {
	return file_cosmos_base_v1beta1_coin_proto_rawDescGZIP(), []int{2}
}

func (x *IntProto) GetInt() string {
	if x != nil {
		return x.Int
	}
	return ""
}

// DecProto defines a Protobuf wrapper around a Dec object.
type DecProto struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Dec string `protobuf:"bytes,1,opt,name=dec,proto3" json:"dec,omitempty"`
}

func (x *DecProto) Reset() {
	*x = DecProto{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecProto) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecProto) ProtoMessage() {}

func (x *DecProto) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_v1beta1_coin_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecProto.ProtoReflect.Descriptor instead.
func (*DecProto) Descriptor() ([]byte, []int) {
	return file_cosmos_base_v1beta1_coin_proto_rawDescGZIP(), []int{3}
}

func (x *DecProto) GetDec() string {
	if x != nil {
		return x.Dec
	}
	return ""
}

var File_cosmos_base_v1beta1_coin_proto protoreflect.FileDescriptor

var file_cosmos_base_v1beta1_coin_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2f, 0x76, 0x31,
	0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x63, 0x6f, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x13, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x76, 0x31,
	0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x63, 0x6f, 0x73,
	0x6d, 0x6f, 0x73, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x61, 0x6d, 0x69, 0x6e, 0x6f, 0x2f, 0x61, 0x6d,
	0x69, 0x6e, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5a, 0x0a, 0x04, 0x43, 0x6f, 0x69,
	0x6e, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6e, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x64, 0x65, 0x6e, 0x6f, 0x6d, 0x12, 0x36, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f,
	0x03, 0x49, 0x6e, 0x74, 0xd2, 0xb4, 0x2d, 0x0a, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x49,
	0x6e, 0x74, 0xa8, 0xe7, 0xb0, 0x2a, 0x01, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x3a,
	0x04, 0xe8, 0xa0, 0x1f, 0x01, 0x22, 0x58, 0x0a, 0x07, 0x44, 0x65, 0x63, 0x43, 0x6f, 0x69, 0x6e,
	0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6e, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x64, 0x65, 0x6e, 0x6f, 0x6d, 0x12, 0x31, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x19, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x03,
	0x44, 0x65, 0x63, 0xd2, 0xb4, 0x2d, 0x0a, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x44, 0x65,
	0x63, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x3a, 0x04, 0xe8, 0xa0, 0x1f, 0x01, 0x22,
	0x37, 0x0a, 0x08, 0x49, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x2b, 0x0a, 0x03, 0x69,
	0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x19, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde,
	0x1f, 0x03, 0x49, 0x6e, 0x74, 0xd2, 0xb4, 0x2d, 0x0a, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e,
	0x49, 0x6e, 0x74, 0x52, 0x03, 0x69, 0x6e, 0x74, 0x22, 0x37, 0x0a, 0x08, 0x44, 0x65, 0x63, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x2b, 0x0a, 0x03, 0x64, 0x65, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x42, 0x19, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x03, 0x44, 0x65, 0x63, 0xd2, 0xb4,
	0x2d, 0x0a, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x44, 0x65, 0x63, 0x52, 0x03, 0x64, 0x65,
	0x63, 0x42, 0x4f, 0x5a, 0x45, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x73, 0x61, 0x69, 0x73, 0x65, 0x74, 0x2d, 0x63, 0x6f, 0x2f, 0x73, 0x61, 0x69, 0x2d, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x78, 0x2d, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x62, 0x61,
	0x73, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0xd8, 0xe1, 0x1e, 0x00, 0x80, 0xe2,
	0x1e, 0x00, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cosmos_base_v1beta1_coin_proto_rawDescOnce sync.Once
	file_cosmos_base_v1beta1_coin_proto_rawDescData = file_cosmos_base_v1beta1_coin_proto_rawDesc
)

func file_cosmos_base_v1beta1_coin_proto_rawDescGZIP() []byte {
	file_cosmos_base_v1beta1_coin_proto_rawDescOnce.Do(func() {
		file_cosmos_base_v1beta1_coin_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_base_v1beta1_coin_proto_rawDescData)
	})
	return file_cosmos_base_v1beta1_coin_proto_rawDescData
}

var file_cosmos_base_v1beta1_coin_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_cosmos_base_v1beta1_coin_proto_goTypes = []interface{}{
	(*Coin)(nil),     // 0: cosmos.base.v1beta1.Coin
	(*DecCoin)(nil),  // 1: cosmos.base.v1beta1.DecCoin
	(*IntProto)(nil), // 2: cosmos.base.v1beta1.IntProto
	(*DecProto)(nil), // 3: cosmos.base.v1beta1.DecProto
}
var file_cosmos_base_v1beta1_coin_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_cosmos_base_v1beta1_coin_proto_init() }
func file_cosmos_base_v1beta1_coin_proto_init() {
	if File_cosmos_base_v1beta1_coin_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cosmos_base_v1beta1_coin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Coin); i {
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
		file_cosmos_base_v1beta1_coin_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecCoin); i {
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
		file_cosmos_base_v1beta1_coin_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IntProto); i {
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
		file_cosmos_base_v1beta1_coin_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecProto); i {
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
			RawDescriptor: file_cosmos_base_v1beta1_coin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cosmos_base_v1beta1_coin_proto_goTypes,
		DependencyIndexes: file_cosmos_base_v1beta1_coin_proto_depIdxs,
		MessageInfos:      file_cosmos_base_v1beta1_coin_proto_msgTypes,
	}.Build()
	File_cosmos_base_v1beta1_coin_proto = out.File
	file_cosmos_base_v1beta1_coin_proto_rawDesc = nil
	file_cosmos_base_v1beta1_coin_proto_goTypes = nil
	file_cosmos_base_v1beta1_coin_proto_depIdxs = nil
}
