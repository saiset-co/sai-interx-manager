// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/upgrade/v1beta1/query.proto

package types

import (
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
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryCurrentPlanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryCurrentPlanRequest) ProtoMessage() {}

func (x *QueryCurrentPlanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[0]
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
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{0}
}

// QueryCurrentPlanResponse is the response type for the Query/CurrentPlan RPC
// method.
type QueryCurrentPlanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// plan is the current upgrade plan.
	Plan *Plan `protobuf:"bytes,1,opt,name=plan,proto3" json:"plan,omitempty"`
}

func (x *QueryCurrentPlanResponse) Reset() {
	*x = QueryCurrentPlanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryCurrentPlanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryCurrentPlanResponse) ProtoMessage() {}

func (x *QueryCurrentPlanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[1]
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
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{1}
}

func (x *QueryCurrentPlanResponse) GetPlan() *Plan {
	if x != nil {
		return x.Plan
	}
	return nil
}

// QueryCurrentPlanRequest is the request type for the Query/AppliedPlan RPC
// method.
type QueryAppliedPlanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the applied plan to query for.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *QueryAppliedPlanRequest) Reset() {
	*x = QueryAppliedPlanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryAppliedPlanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryAppliedPlanRequest) ProtoMessage() {}

func (x *QueryAppliedPlanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryAppliedPlanRequest.ProtoReflect.Descriptor instead.
func (*QueryAppliedPlanRequest) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{2}
}

func (x *QueryAppliedPlanRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// QueryAppliedPlanResponse is the response type for the Query/AppliedPlan RPC
// method.
type QueryAppliedPlanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// height is the block height at which the plan was applied.
	Height int64 `protobuf:"varint,1,opt,name=height,proto3" json:"height,omitempty"`
}

func (x *QueryAppliedPlanResponse) Reset() {
	*x = QueryAppliedPlanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryAppliedPlanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryAppliedPlanResponse) ProtoMessage() {}

func (x *QueryAppliedPlanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryAppliedPlanResponse.ProtoReflect.Descriptor instead.
func (*QueryAppliedPlanResponse) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{3}
}

func (x *QueryAppliedPlanResponse) GetHeight() int64 {
	if x != nil {
		return x.Height
	}
	return 0
}

// QueryUpgradedConsensusStateRequest is the request type for the Query/UpgradedConsensusState
// RPC method.
//
// Deprecated: Do not use.
type QueryUpgradedConsensusStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// last height of the current chain must be sent in request
	// as this is the height under which next consensus state is stored
	LastHeight int64 `protobuf:"varint,1,opt,name=last_height,json=lastHeight,proto3" json:"last_height,omitempty"`
}

func (x *QueryUpgradedConsensusStateRequest) Reset() {
	*x = QueryUpgradedConsensusStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryUpgradedConsensusStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryUpgradedConsensusStateRequest) ProtoMessage() {}

func (x *QueryUpgradedConsensusStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryUpgradedConsensusStateRequest.ProtoReflect.Descriptor instead.
func (*QueryUpgradedConsensusStateRequest) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{4}
}

func (x *QueryUpgradedConsensusStateRequest) GetLastHeight() int64 {
	if x != nil {
		return x.LastHeight
	}
	return 0
}

// QueryUpgradedConsensusStateResponse is the response type for the Query/UpgradedConsensusState
// RPC method.
//
// Deprecated: Do not use.
type QueryUpgradedConsensusStateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Since: cosmos-sdk 0.43
	UpgradedConsensusState []byte `protobuf:"bytes,2,opt,name=upgraded_consensus_state,json=upgradedConsensusState,proto3" json:"upgraded_consensus_state,omitempty"`
}

func (x *QueryUpgradedConsensusStateResponse) Reset() {
	*x = QueryUpgradedConsensusStateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryUpgradedConsensusStateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryUpgradedConsensusStateResponse) ProtoMessage() {}

func (x *QueryUpgradedConsensusStateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryUpgradedConsensusStateResponse.ProtoReflect.Descriptor instead.
func (*QueryUpgradedConsensusStateResponse) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{5}
}

func (x *QueryUpgradedConsensusStateResponse) GetUpgradedConsensusState() []byte {
	if x != nil {
		return x.UpgradedConsensusState
	}
	return nil
}

// QueryModuleVersionsRequest is the request type for the Query/ModuleVersions
// RPC method.
//
// Since: cosmos-sdk 0.43
type QueryModuleVersionsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// module_name is a field to query a specific module
	// consensus version from state. Leaving this empty will
	// fetch the full list of module versions from state
	ModuleName string `protobuf:"bytes,1,opt,name=module_name,json=moduleName,proto3" json:"module_name,omitempty"`
}

func (x *QueryModuleVersionsRequest) Reset() {
	*x = QueryModuleVersionsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryModuleVersionsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryModuleVersionsRequest) ProtoMessage() {}

func (x *QueryModuleVersionsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryModuleVersionsRequest.ProtoReflect.Descriptor instead.
func (*QueryModuleVersionsRequest) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{6}
}

func (x *QueryModuleVersionsRequest) GetModuleName() string {
	if x != nil {
		return x.ModuleName
	}
	return ""
}

// QueryModuleVersionsResponse is the response type for the Query/ModuleVersions
// RPC method.
//
// Since: cosmos-sdk 0.43
type QueryModuleVersionsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// module_versions is a list of module names with their consensus versions.
	ModuleVersions []*ModuleVersion `protobuf:"bytes,1,rep,name=module_versions,json=moduleVersions,proto3" json:"module_versions,omitempty"`
}

func (x *QueryModuleVersionsResponse) Reset() {
	*x = QueryModuleVersionsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryModuleVersionsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryModuleVersionsResponse) ProtoMessage() {}

func (x *QueryModuleVersionsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryModuleVersionsResponse.ProtoReflect.Descriptor instead.
func (*QueryModuleVersionsResponse) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{7}
}

func (x *QueryModuleVersionsResponse) GetModuleVersions() []*ModuleVersion {
	if x != nil {
		return x.ModuleVersions
	}
	return nil
}

// QueryAuthorityRequest is the request type for Query/Authority
//
// Since: cosmos-sdk 0.46
type QueryAuthorityRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QueryAuthorityRequest) Reset() {
	*x = QueryAuthorityRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryAuthorityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryAuthorityRequest) ProtoMessage() {}

func (x *QueryAuthorityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryAuthorityRequest.ProtoReflect.Descriptor instead.
func (*QueryAuthorityRequest) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{8}
}

// QueryAuthorityResponse is the response type for Query/Authority
//
// Since: cosmos-sdk 0.46
type QueryAuthorityResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
}

func (x *QueryAuthorityResponse) Reset() {
	*x = QueryAuthorityResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryAuthorityResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryAuthorityResponse) ProtoMessage() {}

func (x *QueryAuthorityResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_upgrade_v1beta1_query_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryAuthorityResponse.ProtoReflect.Descriptor instead.
func (*QueryAuthorityResponse) Descriptor() ([]byte, []int) {
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP(), []int{9}
}

func (x *QueryAuthorityResponse) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

var File_cosmos_upgrade_v1beta1_query_proto protoreflect.FileDescriptor

var file_cosmos_upgrade_v1beta1_query_proto_rawDesc = []byte{
	0x0a, 0x22, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65,
	0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67,
	0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x19, 0x0a, 0x17, 0x51, 0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74,
	0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x4c, 0x0a, 0x18, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x30, 0x0a, 0x04, 0x70, 0x6c, 0x61, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x75,
	0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x50,
	0x6c, 0x61, 0x6e, 0x52, 0x04, 0x70, 0x6c, 0x61, 0x6e, 0x22, 0x2d, 0x0a, 0x17, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x65, 0x64, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x32, 0x0a, 0x18, 0x51, 0x75, 0x65, 0x72,
	0x79, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x65, 0x64, 0x50, 0x6c, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x49, 0x0a, 0x22,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x64, 0x43, 0x6f, 0x6e,
	0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x68, 0x65, 0x69, 0x67, 0x68,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x6c, 0x61, 0x73, 0x74, 0x48, 0x65, 0x69,
	0x67, 0x68, 0x74, 0x3a, 0x02, 0x18, 0x01, 0x22, 0x69, 0x0a, 0x23, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75,
	0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x38,
	0x0a, 0x18, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x73, 0x65,
	0x6e, 0x73, 0x75, 0x73, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x16, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e,
	0x73, 0x75, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x3a, 0x02, 0x18, 0x01, 0x4a, 0x04, 0x08, 0x01,
	0x10, 0x02, 0x22, 0x3d, 0x0a, 0x1a, 0x51, 0x75, 0x65, 0x72, 0x79, 0x4d, 0x6f, 0x64, 0x75, 0x6c,
	0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1f, 0x0a, 0x0b, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x4e, 0x61, 0x6d,
	0x65, 0x22, 0x6d, 0x0a, 0x1b, 0x51, 0x75, 0x65, 0x72, 0x79, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x4e, 0x0a, 0x0f, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x0e, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x22, 0x17, 0x0a, 0x15, 0x51, 0x75, 0x65, 0x72, 0x79, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x32, 0x0a, 0x16, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x32, 0xf4, 0x06,
	0x0a, 0x05, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x9e, 0x01, 0x0a, 0x0b, 0x43, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61, 0x6e, 0x12, 0x2f, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c, 0x61,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61,
	0x31, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x50, 0x6c,
	0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2c, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x26, 0x12, 0x24, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67, 0x72,
	0x61, 0x64, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x63, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x74, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x12, 0xa5, 0x01, 0x0a, 0x0b, 0x41, 0x70, 0x70,
	0x6c, 0x69, 0x65, 0x64, 0x50, 0x6c, 0x61, 0x6e, 0x12, 0x2f, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f,
	0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61,
	0x31, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x65, 0x64, 0x50, 0x6c,
	0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x65, 0x64, 0x50,
	0x6c, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x33, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x2d, 0x12, 0x2b, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67,
	0x72, 0x61, 0x64, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x61, 0x70, 0x70,
	0x6c, 0x69, 0x65, 0x64, 0x5f, 0x70, 0x6c, 0x61, 0x6e, 0x2f, 0x7b, 0x6e, 0x61, 0x6d, 0x65, 0x7d,
	0x12, 0xdc, 0x01, 0x0a, 0x16, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x64, 0x43, 0x6f, 0x6e,
	0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x3a, 0x2e, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62,
	0x65, 0x74, 0x61, 0x31, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64,
	0x65, 0x64, 0x43, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x3b, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x64, 0x43, 0x6f,
	0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x49, 0x88, 0x02, 0x01, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x40, 0x12,
	0x3e, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65,
	0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65,
	0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x5f, 0x73, 0x74, 0x61, 0x74,
	0x65, 0x2f, 0x7b, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x7d, 0x12,
	0xaa, 0x01, 0x0a, 0x0e, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x12, 0x32, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67, 0x72,
	0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x51, 0x75, 0x65, 0x72,
	0x79, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x33, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e,
	0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2f, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x29, 0x12, 0x27, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67,
	0x72, 0x61, 0x64, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x6d, 0x6f, 0x64,
	0x75, 0x6c, 0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x95, 0x01, 0x0a,
	0x09, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x2d, 0x2e, 0x63, 0x6f, 0x73,
	0x6d, 0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65,
	0x74, 0x61, 0x31, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2e, 0x2e, 0x63, 0x6f, 0x73, 0x6d,
	0x6f, 0x73, 0x2e, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x29, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x23, 0x12, 0x21, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x75, 0x70, 0x67, 0x72, 0x61,
	0x64, 0x65, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x74, 0x79, 0x42, 0x48, 0x5a, 0x46, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x69, 0x73, 0x65, 0x74, 0x2d, 0x63, 0x6f, 0x2f, 0x73, 0x61, 0x69,
	0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x78, 0x2d, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73,
	0x2f, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cosmos_upgrade_v1beta1_query_proto_rawDescOnce sync.Once
	file_cosmos_upgrade_v1beta1_query_proto_rawDescData = file_cosmos_upgrade_v1beta1_query_proto_rawDesc
)

func file_cosmos_upgrade_v1beta1_query_proto_rawDescGZIP() []byte {
	file_cosmos_upgrade_v1beta1_query_proto_rawDescOnce.Do(func() {
		file_cosmos_upgrade_v1beta1_query_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_upgrade_v1beta1_query_proto_rawDescData)
	})
	return file_cosmos_upgrade_v1beta1_query_proto_rawDescData
}

var file_cosmos_upgrade_v1beta1_query_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_cosmos_upgrade_v1beta1_query_proto_goTypes = []interface{}{
	(*QueryCurrentPlanRequest)(nil),             // 0: cosmos.upgrade.v1beta1.QueryCurrentPlanRequest
	(*QueryCurrentPlanResponse)(nil),            // 1: cosmos.upgrade.v1beta1.QueryCurrentPlanResponse
	(*QueryAppliedPlanRequest)(nil),             // 2: cosmos.upgrade.v1beta1.QueryAppliedPlanRequest
	(*QueryAppliedPlanResponse)(nil),            // 3: cosmos.upgrade.v1beta1.QueryAppliedPlanResponse
	(*QueryUpgradedConsensusStateRequest)(nil),  // 4: cosmos.upgrade.v1beta1.QueryUpgradedConsensusStateRequest
	(*QueryUpgradedConsensusStateResponse)(nil), // 5: cosmos.upgrade.v1beta1.QueryUpgradedConsensusStateResponse
	(*QueryModuleVersionsRequest)(nil),          // 6: cosmos.upgrade.v1beta1.QueryModuleVersionsRequest
	(*QueryModuleVersionsResponse)(nil),         // 7: cosmos.upgrade.v1beta1.QueryModuleVersionsResponse
	(*QueryAuthorityRequest)(nil),               // 8: cosmos.upgrade.v1beta1.QueryAuthorityRequest
	(*QueryAuthorityResponse)(nil),              // 9: cosmos.upgrade.v1beta1.QueryAuthorityResponse
	(*Plan)(nil),                                // 10: cosmos.upgrade.v1beta1.Plan
	(*ModuleVersion)(nil),                       // 11: cosmos.upgrade.v1beta1.ModuleVersion
}
var file_cosmos_upgrade_v1beta1_query_proto_depIdxs = []int32{
	10, // 0: cosmos.upgrade.v1beta1.QueryCurrentPlanResponse.plan:type_name -> cosmos.upgrade.v1beta1.Plan
	11, // 1: cosmos.upgrade.v1beta1.QueryModuleVersionsResponse.module_versions:type_name -> cosmos.upgrade.v1beta1.ModuleVersion
	0,  // 2: cosmos.upgrade.v1beta1.Query.CurrentPlan:input_type -> cosmos.upgrade.v1beta1.QueryCurrentPlanRequest
	2,  // 3: cosmos.upgrade.v1beta1.Query.AppliedPlan:input_type -> cosmos.upgrade.v1beta1.QueryAppliedPlanRequest
	4,  // 4: cosmos.upgrade.v1beta1.Query.UpgradedConsensusState:input_type -> cosmos.upgrade.v1beta1.QueryUpgradedConsensusStateRequest
	6,  // 5: cosmos.upgrade.v1beta1.Query.ModuleVersions:input_type -> cosmos.upgrade.v1beta1.QueryModuleVersionsRequest
	8,  // 6: cosmos.upgrade.v1beta1.Query.Authority:input_type -> cosmos.upgrade.v1beta1.QueryAuthorityRequest
	1,  // 7: cosmos.upgrade.v1beta1.Query.CurrentPlan:output_type -> cosmos.upgrade.v1beta1.QueryCurrentPlanResponse
	3,  // 8: cosmos.upgrade.v1beta1.Query.AppliedPlan:output_type -> cosmos.upgrade.v1beta1.QueryAppliedPlanResponse
	5,  // 9: cosmos.upgrade.v1beta1.Query.UpgradedConsensusState:output_type -> cosmos.upgrade.v1beta1.QueryUpgradedConsensusStateResponse
	7,  // 10: cosmos.upgrade.v1beta1.Query.ModuleVersions:output_type -> cosmos.upgrade.v1beta1.QueryModuleVersionsResponse
	9,  // 11: cosmos.upgrade.v1beta1.Query.Authority:output_type -> cosmos.upgrade.v1beta1.QueryAuthorityResponse
	7,  // [7:12] is the sub-list for method output_type
	2,  // [2:7] is the sub-list for method input_type
	2,  // [2:2] is the sub-list for extension type_name
	2,  // [2:2] is the sub-list for extension extendee
	0,  // [0:2] is the sub-list for field type_name
}

func init() { file_cosmos_upgrade_v1beta1_query_proto_init() }
func file_cosmos_upgrade_v1beta1_query_proto_init() {
	if File_cosmos_upgrade_v1beta1_query_proto != nil {
		return
	}
	file_cosmos_upgrade_v1beta1_upgrade_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryAppliedPlanRequest); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryAppliedPlanResponse); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryUpgradedConsensusStateRequest); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryUpgradedConsensusStateResponse); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryModuleVersionsRequest); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryModuleVersionsResponse); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryAuthorityRequest); i {
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
		file_cosmos_upgrade_v1beta1_query_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryAuthorityResponse); i {
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
			RawDescriptor: file_cosmos_upgrade_v1beta1_query_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cosmos_upgrade_v1beta1_query_proto_goTypes,
		DependencyIndexes: file_cosmos_upgrade_v1beta1_query_proto_depIdxs,
		MessageInfos:      file_cosmos_upgrade_v1beta1_query_proto_msgTypes,
	}.Build()
	File_cosmos_upgrade_v1beta1_query_proto = out.File
	file_cosmos_upgrade_v1beta1_query_proto_rawDesc = nil
	file_cosmos_upgrade_v1beta1_query_proto_goTypes = nil
	file_cosmos_upgrade_v1beta1_query_proto_depIdxs = nil
}
