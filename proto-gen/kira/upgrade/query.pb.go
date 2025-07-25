// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: kira/upgrade/query.proto

package types

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// QueryCurrentPlanRequest is the request type for the Query/CurrentPlan RPC
// method.
type QueryCurrentPlanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QueryCurrentPlanRequest) Reset() {
	*x = QueryCurrentPlanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_upgrade_query_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryCurrentPlanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryCurrentPlanRequest) ProtoMessage() {}

func (x *QueryCurrentPlanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_upgrade_query_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryCurrentPlanRequest.ProtoReflect.Descriptor instead.
func (*QueryCurrentPlanRequest) Descriptor() ([]byte, []int) {
	return file_kira_upgrade_query_proto_rawDescGZIP(), []int{0}
}

// QueryCurrentPlanResponse is the response type for the Query/CurrentPlan RPC
// method.
type QueryCurrentPlanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// plan is the current plan.
	Plan *Plan `protobuf:"bytes,1,opt,name=plan,proto3" json:"plan,omitempty"`
}

func (x *QueryCurrentPlanResponse) Reset() {
	*x = QueryCurrentPlanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_upgrade_query_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryCurrentPlanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryCurrentPlanResponse) ProtoMessage() {}

func (x *QueryCurrentPlanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_upgrade_query_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryCurrentPlanResponse.ProtoReflect.Descriptor instead.
func (*QueryCurrentPlanResponse) Descriptor() ([]byte, []int) {
	return file_kira_upgrade_query_proto_rawDescGZIP(), []int{1}
}

func (x *QueryCurrentPlanResponse) GetPlan() *Plan {
	if x != nil {
		return x.Plan
	}
	return nil
}

// QueryNextPlanRequest is the request type for the Query/CurrentPlan RPC
// method.
type QueryNextPlanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QueryNextPlanRequest) Reset() {
	*x = QueryNextPlanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_upgrade_query_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryNextPlanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryNextPlanRequest) ProtoMessage() {}

func (x *QueryNextPlanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_upgrade_query_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryNextPlanRequest.ProtoReflect.Descriptor instead.
func (*QueryNextPlanRequest) Descriptor() ([]byte, []int) {
	return file_kira_upgrade_query_proto_rawDescGZIP(), []int{2}
}

// QueryNextPlanResponse is the response type for the Query/CurrentPlan RPC
// method.
type QueryNextPlanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// plan is the next upgrade plan.
	Plan *Plan `protobuf:"bytes,1,opt,name=plan,proto3" json:"plan,omitempty"`
}

func (x *QueryNextPlanResponse) Reset() {
	*x = QueryNextPlanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_upgrade_query_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryNextPlanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryNextPlanResponse) ProtoMessage() {}

func (x *QueryNextPlanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_upgrade_query_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryNextPlanResponse.ProtoReflect.Descriptor instead.
func (*QueryNextPlanResponse) Descriptor() ([]byte, []int) {
	return file_kira_upgrade_query_proto_rawDescGZIP(), []int{3}
}

func (x *QueryNextPlanResponse) GetPlan() *Plan {
	if x != nil {
		return x.Plan
	}
	return nil
}

var File_kira_upgrade_query_proto protoreflect.FileDescriptor

var file_kira_upgrade_query_proto_rawDesc = []byte{
	0x0a, 0x18, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x71,
	0x75, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6b, 0x69, 0x72, 0x61,
	0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1a, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f,
	0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x6b,
	0x69, 0x72, 0x61, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x70, 0x6c, 0x61, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x19, 0x0a, 0x17, 0x51, 0x75, 0x65, 0x72, 0x79, 0x43,
	0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x22, 0x42, 0x0a, 0x18, 0x51, 0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e,
	0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x0a,
	0x04, 0x70, 0x6c, 0x61, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6b, 0x69,
	0x72, 0x61, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x50, 0x6c, 0x61, 0x6e, 0x52,
	0x04, 0x70, 0x6c, 0x61, 0x6e, 0x22, 0x16, 0x0a, 0x14, 0x51, 0x75, 0x65, 0x72, 0x79, 0x4e, 0x65,
	0x78, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x3f, 0x0a,
	0x15, 0x51, 0x75, 0x65, 0x72, 0x79, 0x4e, 0x65, 0x78, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x0a, 0x04, 0x70, 0x6c, 0x61, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x75, 0x70, 0x67, 0x72,
	0x61, 0x64, 0x65, 0x2e, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x04, 0x70, 0x6c, 0x61, 0x6e, 0x32, 0x80,
	0x02, 0x0a, 0x05, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x80, 0x01, 0x0a, 0x0b, 0x43, 0x75, 0x72,
	0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x12, 0x25, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e,
	0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72,
	0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x26, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x22, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1c, 0x12,
	0x1a, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x63,
	0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x12, 0x74, 0x0a, 0x08, 0x4e,
	0x65, 0x78, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x12, 0x22, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x75,
	0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x4e, 0x65, 0x78, 0x74,
	0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x6b, 0x69,
	0x72, 0x61, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x4e, 0x65, 0x78, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x1f, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x19, 0x12, 0x17, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f,
	0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x70, 0x6c, 0x61,
	0x6e, 0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x4b, 0x69, 0x72, 0x61, 0x43, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x65, 0x6b, 0x61, 0x69, 0x2f, 0x78,
	0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_kira_upgrade_query_proto_rawDescOnce sync.Once
	file_kira_upgrade_query_proto_rawDescData = file_kira_upgrade_query_proto_rawDesc
)

func file_kira_upgrade_query_proto_rawDescGZIP() []byte {
	file_kira_upgrade_query_proto_rawDescOnce.Do(func() {
		file_kira_upgrade_query_proto_rawDescData = protoimpl.X.CompressGZIP(file_kira_upgrade_query_proto_rawDescData)
	})
	return file_kira_upgrade_query_proto_rawDescData
}

var file_kira_upgrade_query_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_kira_upgrade_query_proto_goTypes = []interface{}{
	(*QueryCurrentPlanRequest)(nil),  // 0: kira.upgrade.QueryCurrentPlanRequest
	(*QueryCurrentPlanResponse)(nil), // 1: kira.upgrade.QueryCurrentPlanResponse
	(*QueryNextPlanRequest)(nil),     // 2: kira.upgrade.QueryNextPlanRequest
	(*QueryNextPlanResponse)(nil),    // 3: kira.upgrade.QueryNextPlanResponse
	(*Plan)(nil),                     // 4: kira.upgrade.Plan
}
var file_kira_upgrade_query_proto_depIdxs = []int32{
	4, // 0: kira.upgrade.QueryCurrentPlanResponse.plan:type_name -> kira.upgrade.Plan
	4, // 1: kira.upgrade.QueryNextPlanResponse.plan:type_name -> kira.upgrade.Plan
	0, // 2: kira.upgrade.Query.CurrentPlan:input_type -> kira.upgrade.QueryCurrentPlanRequest
	2, // 3: kira.upgrade.Query.NextPlan:input_type -> kira.upgrade.QueryNextPlanRequest
	1, // 4: kira.upgrade.Query.CurrentPlan:output_type -> kira.upgrade.QueryCurrentPlanResponse
	3, // 5: kira.upgrade.Query.NextPlan:output_type -> kira.upgrade.QueryNextPlanResponse
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_kira_upgrade_query_proto_init() }
func file_kira_upgrade_query_proto_init() {
	if File_kira_upgrade_query_proto != nil {
		return
	}
	file_kira_upgrade_upgrade_proto_init()
	file_kira_upgrade_plan_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_kira_upgrade_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryCurrentPlanRequest); i {
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
		file_kira_upgrade_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryCurrentPlanResponse); i {
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
		file_kira_upgrade_query_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryNextPlanRequest); i {
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
		file_kira_upgrade_query_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryNextPlanResponse); i {
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
			RawDescriptor: file_kira_upgrade_query_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_kira_upgrade_query_proto_goTypes,
		DependencyIndexes: file_kira_upgrade_query_proto_depIdxs,
		MessageInfos:      file_kira_upgrade_query_proto_msgTypes,
	}.Build()
	File_kira_upgrade_query_proto = out.File
	file_kira_upgrade_query_proto_rawDesc = nil
	file_kira_upgrade_query_proto_goTypes = nil
	file_kira_upgrade_query_proto_depIdxs = nil
}
