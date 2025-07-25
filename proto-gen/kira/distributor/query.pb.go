// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: kira/distributor/query.proto

package types

import (
	_ "github.com/cosmos/cosmos-sdk/types/query"
	_ "github.com/gogo/protobuf/gogoproto"
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

type QueryFeesTreasuryRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QueryFeesTreasuryRequest) Reset() {
	*x = QueryFeesTreasuryRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryFeesTreasuryRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryFeesTreasuryRequest) ProtoMessage() {}

func (x *QueryFeesTreasuryRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryFeesTreasuryRequest.ProtoReflect.Descriptor instead.
func (*QueryFeesTreasuryRequest) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{0}
}

type QueryFeesTreasuryResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Coins []string `protobuf:"bytes,1,rep,name=coins,proto3" json:"coins,omitempty"`
}

func (x *QueryFeesTreasuryResponse) Reset() {
	*x = QueryFeesTreasuryResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryFeesTreasuryResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryFeesTreasuryResponse) ProtoMessage() {}

func (x *QueryFeesTreasuryResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryFeesTreasuryResponse.ProtoReflect.Descriptor instead.
func (*QueryFeesTreasuryResponse) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{1}
}

func (x *QueryFeesTreasuryResponse) GetCoins() []string {
	if x != nil {
		return x.Coins
	}
	return nil
}

type QuerySnapshotPeriodRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QuerySnapshotPeriodRequest) Reset() {
	*x = QuerySnapshotPeriodRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuerySnapshotPeriodRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuerySnapshotPeriodRequest) ProtoMessage() {}

func (x *QuerySnapshotPeriodRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuerySnapshotPeriodRequest.ProtoReflect.Descriptor instead.
func (*QuerySnapshotPeriodRequest) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{2}
}

type QuerySnapshotPeriodResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SnapshotPeriod int64 `protobuf:"varint,1,opt,name=snapshot_period,json=snapshotPeriod,proto3" json:"snapshot_period,omitempty"`
}

func (x *QuerySnapshotPeriodResponse) Reset() {
	*x = QuerySnapshotPeriodResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuerySnapshotPeriodResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuerySnapshotPeriodResponse) ProtoMessage() {}

func (x *QuerySnapshotPeriodResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuerySnapshotPeriodResponse.ProtoReflect.Descriptor instead.
func (*QuerySnapshotPeriodResponse) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{3}
}

func (x *QuerySnapshotPeriodResponse) GetSnapshotPeriod() int64 {
	if x != nil {
		return x.SnapshotPeriod
	}
	return 0
}

type QuerySnapshotPeriodPerformanceRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ValidatorAddress string `protobuf:"bytes,1,opt,name=validator_address,json=validatorAddress,proto3" json:"validator_address,omitempty"`
}

func (x *QuerySnapshotPeriodPerformanceRequest) Reset() {
	*x = QuerySnapshotPeriodPerformanceRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuerySnapshotPeriodPerformanceRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuerySnapshotPeriodPerformanceRequest) ProtoMessage() {}

func (x *QuerySnapshotPeriodPerformanceRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuerySnapshotPeriodPerformanceRequest.ProtoReflect.Descriptor instead.
func (*QuerySnapshotPeriodPerformanceRequest) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{4}
}

func (x *QuerySnapshotPeriodPerformanceRequest) GetValidatorAddress() string {
	if x != nil {
		return x.ValidatorAddress
	}
	return ""
}

type QuerySnapshotPeriodPerformanceResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Performance    int64 `protobuf:"varint,1,opt,name=performance,proto3" json:"performance,omitempty"`
	SnapshotPeriod int64 `protobuf:"varint,2,opt,name=snapshot_period,json=snapshotPeriod,proto3" json:"snapshot_period,omitempty"`
}

func (x *QuerySnapshotPeriodPerformanceResponse) Reset() {
	*x = QuerySnapshotPeriodPerformanceResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuerySnapshotPeriodPerformanceResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuerySnapshotPeriodPerformanceResponse) ProtoMessage() {}

func (x *QuerySnapshotPeriodPerformanceResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuerySnapshotPeriodPerformanceResponse.ProtoReflect.Descriptor instead.
func (*QuerySnapshotPeriodPerformanceResponse) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{5}
}

func (x *QuerySnapshotPeriodPerformanceResponse) GetPerformance() int64 {
	if x != nil {
		return x.Performance
	}
	return 0
}

func (x *QuerySnapshotPeriodPerformanceResponse) GetSnapshotPeriod() int64 {
	if x != nil {
		return x.SnapshotPeriod
	}
	return 0
}

type QueryYearStartSnapshotRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QueryYearStartSnapshotRequest) Reset() {
	*x = QueryYearStartSnapshotRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryYearStartSnapshotRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryYearStartSnapshotRequest) ProtoMessage() {}

func (x *QueryYearStartSnapshotRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryYearStartSnapshotRequest.ProtoReflect.Descriptor instead.
func (*QueryYearStartSnapshotRequest) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{6}
}

type QueryYearStartSnapshotResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Snapshot *SupplySnapshot `protobuf:"bytes,1,opt,name=snapshot,proto3" json:"snapshot,omitempty"`
}

func (x *QueryYearStartSnapshotResponse) Reset() {
	*x = QueryYearStartSnapshotResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryYearStartSnapshotResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryYearStartSnapshotResponse) ProtoMessage() {}

func (x *QueryYearStartSnapshotResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryYearStartSnapshotResponse.ProtoReflect.Descriptor instead.
func (*QueryYearStartSnapshotResponse) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{7}
}

func (x *QueryYearStartSnapshotResponse) GetSnapshot() *SupplySnapshot {
	if x != nil {
		return x.Snapshot
	}
	return nil
}

type QueryPeriodicSnapshotRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *QueryPeriodicSnapshotRequest) Reset() {
	*x = QueryPeriodicSnapshotRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryPeriodicSnapshotRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryPeriodicSnapshotRequest) ProtoMessage() {}

func (x *QueryPeriodicSnapshotRequest) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryPeriodicSnapshotRequest.ProtoReflect.Descriptor instead.
func (*QueryPeriodicSnapshotRequest) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{8}
}

type QueryPeriodicSnapshotResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Snapshot *SupplySnapshot `protobuf:"bytes,1,opt,name=snapshot,proto3" json:"snapshot,omitempty"`
}

func (x *QueryPeriodicSnapshotResponse) Reset() {
	*x = QueryPeriodicSnapshotResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kira_distributor_query_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryPeriodicSnapshotResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryPeriodicSnapshotResponse) ProtoMessage() {}

func (x *QueryPeriodicSnapshotResponse) ProtoReflect() protoreflect.Message {
	mi := &file_kira_distributor_query_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryPeriodicSnapshotResponse.ProtoReflect.Descriptor instead.
func (*QueryPeriodicSnapshotResponse) Descriptor() ([]byte, []int) {
	return file_kira_distributor_query_proto_rawDescGZIP(), []int{9}
}

func (x *QueryPeriodicSnapshotResponse) GetSnapshot() *SupplySnapshot {
	if x != nil {
		return x.Snapshot
	}
	return nil
}

var File_kira_distributor_query_proto protoreflect.FileDescriptor

var file_kira_distributor_query_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x6f, 0x72, 0x2f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10,
	0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72,
	0x1a, 0x2a, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2f, 0x71, 0x75,
	0x65, 0x72, 0x79, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x70, 0x61, 0x67, 0x69,
	0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x67, 0x6f,
	0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x6b, 0x69, 0x72,
	0x61, 0x2f, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x67, 0x65,
	0x6e, 0x65, 0x73, 0x69, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1a, 0x0a, 0x18, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x46, 0x65, 0x65, 0x73, 0x54, 0x72, 0x65, 0x61, 0x73, 0x75, 0x72, 0x79,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x62, 0x0a, 0x19, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x46, 0x65, 0x65, 0x73, 0x54, 0x72, 0x65, 0x61, 0x73, 0x75, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x45, 0x0a, 0x05, 0x63, 0x6f, 0x69, 0x6e, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x42, 0x2f, 0xc8, 0xde, 0x1f, 0x00, 0xda, 0xde, 0x1f, 0x27, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x63,
	0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x43, 0x6f, 0x69, 0x6e, 0x52, 0x05, 0x63, 0x6f, 0x69, 0x6e, 0x73, 0x22, 0x1c, 0x0a, 0x1a, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69,
	0x6f, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x46, 0x0a, 0x1b, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x73, 0x6e, 0x61, 0x70,
	0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x0e, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f,
	0x64, 0x22, 0x54, 0x0a, 0x25, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68,
	0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61,
	0x6e, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2b, 0x0a, 0x11, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x22, 0x73, 0x0a, 0x26, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x50, 0x65,
	0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x20, 0x0a, 0x0b, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61,
	0x6e, 0x63, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f,
	0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x73, 0x6e,
	0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x22, 0x1f, 0x0a, 0x1d,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x59, 0x65, 0x61, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6e,
	0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x64, 0x0a,
	0x1e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x59, 0x65, 0x61, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53,
	0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x42, 0x0a, 0x08, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x20, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62,
	0x75, 0x74, 0x6f, 0x72, 0x2e, 0x53, 0x75, 0x70, 0x70, 0x6c, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73,
	0x68, 0x6f, 0x74, 0x42, 0x04, 0xc8, 0xde, 0x1f, 0x00, 0x52, 0x08, 0x73, 0x6e, 0x61, 0x70, 0x73,
	0x68, 0x6f, 0x74, 0x22, 0x1e, 0x0a, 0x1c, 0x51, 0x75, 0x65, 0x72, 0x79, 0x50, 0x65, 0x72, 0x69,
	0x6f, 0x64, 0x69, 0x63, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x63, 0x0a, 0x1d, 0x51, 0x75, 0x65, 0x72, 0x79, 0x50, 0x65, 0x72, 0x69,
	0x6f, 0x64, 0x69, 0x63, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x42, 0x0a, 0x08, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69,
	0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x53, 0x75, 0x70, 0x70, 0x6c, 0x79,
	0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x42, 0x04, 0xc8, 0xde, 0x1f, 0x00, 0x52, 0x08,
	0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x32, 0x84, 0x07, 0x0a, 0x05, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x12, 0x98, 0x01, 0x0a, 0x0c, 0x46, 0x65, 0x65, 0x73, 0x54, 0x72, 0x65, 0x61, 0x73,
	0x75, 0x72, 0x79, 0x12, 0x2a, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72,
	0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x65, 0x65, 0x73,
	0x54, 0x72, 0x65, 0x61, 0x73, 0x75, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x2b, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x46, 0x65, 0x65, 0x73, 0x54, 0x72, 0x65, 0x61,
	0x73, 0x75, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2f, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x29, 0x12, 0x27, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x64, 0x69, 0x73, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f,
	0x66, 0x65, 0x65, 0x73, 0x5f, 0x74, 0x72, 0x65, 0x61, 0x73, 0x75, 0x72, 0x79, 0x12, 0xa0, 0x01,
	0x0a, 0x0e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64,
	0x12, 0x2c, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f,
	0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d,
	0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f,
	0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50,
	0x65, 0x72, 0x69, 0x6f, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x31, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x2b, 0x12, 0x29, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x64, 0x69, 0x73,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64,
	0x12, 0xe1, 0x01, 0x0a, 0x19, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72,
	0x69, 0x6f, 0x64, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65, 0x12, 0x37,
	0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f,
	0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50,
	0x65, 0x72, 0x69, 0x6f, 0x64, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x38, 0x2e, 0x6b, 0x69, 0x72, 0x61, 0x2e, 0x64,
	0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x50, 0x65,
	0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x51, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x4b, 0x12, 0x49, 0x2f, 0x6b, 0x69, 0x72, 0x61,
	0x2f, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x31, 0x62,
	0x65, 0x74, 0x61, 0x31, 0x2f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x65,
	0x72, 0x69, 0x6f, 0x64, 0x5f, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65,
	0x2f, 0x7b, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x61, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x7d, 0x12, 0xad, 0x01, 0x0a, 0x11, 0x59, 0x65, 0x61, 0x72, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x12, 0x2f, 0x2e, 0x6b, 0x69, 0x72,
	0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x59, 0x65, 0x61, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6e, 0x61, 0x70,
	0x73, 0x68, 0x6f, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e, 0x6b, 0x69,
	0x72, 0x61, 0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x59, 0x65, 0x61, 0x72, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x35, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x2f, 0x12, 0x2d, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x64, 0x69, 0x73,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2f, 0x79, 0x65, 0x61, 0x72, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x73, 0x6e, 0x61, 0x70,
	0x73, 0x68, 0x6f, 0x74, 0x12, 0xa8, 0x01, 0x0a, 0x10, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69,
	0x63, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x12, 0x2e, 0x2e, 0x6b, 0x69, 0x72, 0x61,
	0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68,
	0x6f, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2f, 0x2e, 0x6b, 0x69, 0x72, 0x61,
	0x2e, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x69, 0x63, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68,
	0x6f, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x33, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x2d, 0x12, 0x2b, 0x2f, 0x6b, 0x69, 0x72, 0x61, 0x2f, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69,
	0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x70, 0x65,
	0x72, 0x69, 0x6f, 0x64, 0x69, 0x63, 0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x42,
	0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x4b, 0x69,
	0x72, 0x61, 0x43, 0x6f, 0x72, 0x65, 0x2f, 0x73, 0x65, 0x6b, 0x61, 0x69, 0x2f, 0x78, 0x2f, 0x64,
	0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_kira_distributor_query_proto_rawDescOnce sync.Once
	file_kira_distributor_query_proto_rawDescData = file_kira_distributor_query_proto_rawDesc
)

func file_kira_distributor_query_proto_rawDescGZIP() []byte {
	file_kira_distributor_query_proto_rawDescOnce.Do(func() {
		file_kira_distributor_query_proto_rawDescData = protoimpl.X.CompressGZIP(file_kira_distributor_query_proto_rawDescData)
	})
	return file_kira_distributor_query_proto_rawDescData
}

var file_kira_distributor_query_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_kira_distributor_query_proto_goTypes = []interface{}{
	(*QueryFeesTreasuryRequest)(nil),               // 0: kira.distributor.QueryFeesTreasuryRequest
	(*QueryFeesTreasuryResponse)(nil),              // 1: kira.distributor.QueryFeesTreasuryResponse
	(*QuerySnapshotPeriodRequest)(nil),             // 2: kira.distributor.QuerySnapshotPeriodRequest
	(*QuerySnapshotPeriodResponse)(nil),            // 3: kira.distributor.QuerySnapshotPeriodResponse
	(*QuerySnapshotPeriodPerformanceRequest)(nil),  // 4: kira.distributor.QuerySnapshotPeriodPerformanceRequest
	(*QuerySnapshotPeriodPerformanceResponse)(nil), // 5: kira.distributor.QuerySnapshotPeriodPerformanceResponse
	(*QueryYearStartSnapshotRequest)(nil),          // 6: kira.distributor.QueryYearStartSnapshotRequest
	(*QueryYearStartSnapshotResponse)(nil),         // 7: kira.distributor.QueryYearStartSnapshotResponse
	(*QueryPeriodicSnapshotRequest)(nil),           // 8: kira.distributor.QueryPeriodicSnapshotRequest
	(*QueryPeriodicSnapshotResponse)(nil),          // 9: kira.distributor.QueryPeriodicSnapshotResponse
	(*SupplySnapshot)(nil),                         // 10: kira.distributor.SupplySnapshot
}
var file_kira_distributor_query_proto_depIdxs = []int32{
	10, // 0: kira.distributor.QueryYearStartSnapshotResponse.snapshot:type_name -> kira.distributor.SupplySnapshot
	10, // 1: kira.distributor.QueryPeriodicSnapshotResponse.snapshot:type_name -> kira.distributor.SupplySnapshot
	0,  // 2: kira.distributor.Query.FeesTreasury:input_type -> kira.distributor.QueryFeesTreasuryRequest
	2,  // 3: kira.distributor.Query.SnapshotPeriod:input_type -> kira.distributor.QuerySnapshotPeriodRequest
	4,  // 4: kira.distributor.Query.SnapshotPeriodPerformance:input_type -> kira.distributor.QuerySnapshotPeriodPerformanceRequest
	6,  // 5: kira.distributor.Query.YearStartSnapshot:input_type -> kira.distributor.QueryYearStartSnapshotRequest
	8,  // 6: kira.distributor.Query.PeriodicSnapshot:input_type -> kira.distributor.QueryPeriodicSnapshotRequest
	1,  // 7: kira.distributor.Query.FeesTreasury:output_type -> kira.distributor.QueryFeesTreasuryResponse
	3,  // 8: kira.distributor.Query.SnapshotPeriod:output_type -> kira.distributor.QuerySnapshotPeriodResponse
	5,  // 9: kira.distributor.Query.SnapshotPeriodPerformance:output_type -> kira.distributor.QuerySnapshotPeriodPerformanceResponse
	7,  // 10: kira.distributor.Query.YearStartSnapshot:output_type -> kira.distributor.QueryYearStartSnapshotResponse
	9,  // 11: kira.distributor.Query.PeriodicSnapshot:output_type -> kira.distributor.QueryPeriodicSnapshotResponse
	7,  // [7:12] is the sub-list for method output_type
	2,  // [2:7] is the sub-list for method input_type
	2,  // [2:2] is the sub-list for extension type_name
	2,  // [2:2] is the sub-list for extension extendee
	0,  // [0:2] is the sub-list for field type_name
}

func init() { file_kira_distributor_query_proto_init() }
func file_kira_distributor_query_proto_init() {
	if File_kira_distributor_query_proto != nil {
		return
	}
	file_kira_distributor_genesis_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_kira_distributor_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryFeesTreasuryRequest); i {
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
		file_kira_distributor_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryFeesTreasuryResponse); i {
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
		file_kira_distributor_query_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuerySnapshotPeriodRequest); i {
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
		file_kira_distributor_query_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuerySnapshotPeriodResponse); i {
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
		file_kira_distributor_query_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuerySnapshotPeriodPerformanceRequest); i {
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
		file_kira_distributor_query_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuerySnapshotPeriodPerformanceResponse); i {
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
		file_kira_distributor_query_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryYearStartSnapshotRequest); i {
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
		file_kira_distributor_query_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryYearStartSnapshotResponse); i {
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
		file_kira_distributor_query_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryPeriodicSnapshotRequest); i {
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
		file_kira_distributor_query_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryPeriodicSnapshotResponse); i {
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
			RawDescriptor: file_kira_distributor_query_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_kira_distributor_query_proto_goTypes,
		DependencyIndexes: file_kira_distributor_query_proto_depIdxs,
		MessageInfos:      file_kira_distributor_query_proto_msgTypes,
	}.Build()
	File_kira_distributor_query_proto = out.File
	file_kira_distributor_query_proto_rawDesc = nil
	file_kira_distributor_query_proto_goTypes = nil
	file_kira_distributor_query_proto_depIdxs = nil
}
