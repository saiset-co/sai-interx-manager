// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/base/kv/v1beta1/kv.proto

package kv

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

// Pairs defines a repeated slice of Pair objects.
type Pairs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pairs []*Pair `protobuf:"bytes,1,rep,name=pairs,proto3" json:"pairs,omitempty"`
}

func (x *Pairs) Reset() {
	*x = Pairs{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_kv_v1beta1_kv_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Pairs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Pairs) ProtoMessage() {}

func (x *Pairs) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_kv_v1beta1_kv_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Pairs.ProtoReflect.Descriptor instead.
func (*Pairs) Descriptor() ([]byte, []int) {
	return file_cosmos_base_kv_v1beta1_kv_proto_rawDescGZIP(), []int{0}
}

func (x *Pairs) GetPairs() []*Pair {
	if x != nil {
		return x.Pairs
	}
	return nil
}

// Pair defines a key/value bytes tuple.
type Pair struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Pair) Reset() {
	*x = Pair{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_kv_v1beta1_kv_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Pair) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Pair) ProtoMessage() {}

func (x *Pair) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_kv_v1beta1_kv_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Pair.ProtoReflect.Descriptor instead.
func (*Pair) Descriptor() ([]byte, []int) {
	return file_cosmos_base_kv_v1beta1_kv_proto_rawDescGZIP(), []int{1}
}

func (x *Pair) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *Pair) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

var File_cosmos_base_kv_v1beta1_kv_proto protoreflect.FileDescriptor

var file_cosmos_base_kv_v1beta1_kv_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2f, 0x6b, 0x76,
	0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x6b, 0x76, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x16, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x6b,
	0x76, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x14, 0x67, 0x6f, 0x67, 0x6f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x41, 0x0a, 0x05, 0x50, 0x61, 0x69, 0x72, 0x73, 0x12, 0x38, 0x0a, 0x05, 0x70, 0x61, 0x69, 0x72,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x6b, 0x76, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x50, 0x61, 0x69, 0x72, 0x42, 0x04, 0xc8, 0xde, 0x1f, 0x00, 0x52, 0x05, 0x70, 0x61, 0x69,
	0x72, 0x73, 0x22, 0x2e, 0x0a, 0x04, 0x50, 0x61, 0x69, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x42, 0x27, 0x5a, 0x25, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73,
	0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x6b, 0x76, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_cosmos_base_kv_v1beta1_kv_proto_rawDescOnce sync.Once
	file_cosmos_base_kv_v1beta1_kv_proto_rawDescData = file_cosmos_base_kv_v1beta1_kv_proto_rawDesc
)

func file_cosmos_base_kv_v1beta1_kv_proto_rawDescGZIP() []byte {
	file_cosmos_base_kv_v1beta1_kv_proto_rawDescOnce.Do(func() {
		file_cosmos_base_kv_v1beta1_kv_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_base_kv_v1beta1_kv_proto_rawDescData)
	})
	return file_cosmos_base_kv_v1beta1_kv_proto_rawDescData
}

var file_cosmos_base_kv_v1beta1_kv_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cosmos_base_kv_v1beta1_kv_proto_goTypes = []interface{}{
	(*Pairs)(nil), // 0: cosmos.base.kv.v1beta1.Pairs
	(*Pair)(nil),  // 1: cosmos.base.kv.v1beta1.Pair
}
var file_cosmos_base_kv_v1beta1_kv_proto_depIdxs = []int32{
	1, // 0: cosmos.base.kv.v1beta1.Pairs.pairs:type_name -> cosmos.base.kv.v1beta1.Pair
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_cosmos_base_kv_v1beta1_kv_proto_init() }
func file_cosmos_base_kv_v1beta1_kv_proto_init() {
	if File_cosmos_base_kv_v1beta1_kv_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cosmos_base_kv_v1beta1_kv_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Pairs); i {
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
		file_cosmos_base_kv_v1beta1_kv_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Pair); i {
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
			RawDescriptor: file_cosmos_base_kv_v1beta1_kv_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cosmos_base_kv_v1beta1_kv_proto_goTypes,
		DependencyIndexes: file_cosmos_base_kv_v1beta1_kv_proto_depIdxs,
		MessageInfos:      file_cosmos_base_kv_v1beta1_kv_proto_msgTypes,
	}.Build()
	File_cosmos_base_kv_v1beta1_kv_proto = out.File
	file_cosmos_base_kv_v1beta1_kv_proto_rawDesc = nil
	file_cosmos_base_kv_v1beta1_kv_proto_goTypes = nil
	file_cosmos_base_kv_v1beta1_kv_proto_depIdxs = nil
}
