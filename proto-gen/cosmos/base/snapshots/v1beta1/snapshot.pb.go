// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.1
// source: cosmos/base/snapshots/v1beta1/snapshot.proto

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

// Snapshot contains Tendermint state sync snapshot info.
type Snapshot struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Height   uint64    `protobuf:"varint,1,opt,name=height,proto3" json:"height,omitempty"`
	Format   uint32    `protobuf:"varint,2,opt,name=format,proto3" json:"format,omitempty"`
	Chunks   uint32    `protobuf:"varint,3,opt,name=chunks,proto3" json:"chunks,omitempty"`
	Hash     []byte    `protobuf:"bytes,4,opt,name=hash,proto3" json:"hash,omitempty"`
	Metadata *Metadata `protobuf:"bytes,5,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *Snapshot) Reset() {
	*x = Snapshot{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Snapshot) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Snapshot) ProtoMessage() {}

func (x *Snapshot) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Snapshot.ProtoReflect.Descriptor instead.
func (*Snapshot) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{0}
}

func (x *Snapshot) GetHeight() uint64 {
	if x != nil {
		return x.Height
	}
	return 0
}

func (x *Snapshot) GetFormat() uint32 {
	if x != nil {
		return x.Format
	}
	return 0
}

func (x *Snapshot) GetChunks() uint32 {
	if x != nil {
		return x.Chunks
	}
	return 0
}

func (x *Snapshot) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

func (x *Snapshot) GetMetadata() *Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

// Metadata contains SDK-specific snapshot metadata.
type Metadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChunkHashes [][]byte `protobuf:"bytes,1,rep,name=chunk_hashes,json=chunkHashes,proto3" json:"chunk_hashes,omitempty"` // SHA-256 chunk hashes
}

func (x *Metadata) Reset() {
	*x = Metadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Metadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Metadata) ProtoMessage() {}

func (x *Metadata) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Metadata.ProtoReflect.Descriptor instead.
func (*Metadata) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{1}
}

func (x *Metadata) GetChunkHashes() [][]byte {
	if x != nil {
		return x.ChunkHashes
	}
	return nil
}

// SnapshotItem is an item contained in a rootmulti.Store snapshot.
//
// Since: cosmos-sdk 0.46
type SnapshotItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// item is the specific type of snapshot item.
	//
	// Types that are assignable to Item:
	//
	//	*SnapshotItem_Store
	//	*SnapshotItem_Iavl
	//	*SnapshotItem_Extension
	//	*SnapshotItem_ExtensionPayload
	//	*SnapshotItem_Kv
	//	*SnapshotItem_Schema
	Item isSnapshotItem_Item `protobuf_oneof:"item"`
}

func (x *SnapshotItem) Reset() {
	*x = SnapshotItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotItem) ProtoMessage() {}

func (x *SnapshotItem) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotItem.ProtoReflect.Descriptor instead.
func (*SnapshotItem) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{2}
}

func (m *SnapshotItem) GetItem() isSnapshotItem_Item {
	if m != nil {
		return m.Item
	}
	return nil
}

func (x *SnapshotItem) GetStore() *SnapshotStoreItem {
	if x, ok := x.GetItem().(*SnapshotItem_Store); ok {
		return x.Store
	}
	return nil
}

func (x *SnapshotItem) GetIavl() *SnapshotIAVLItem {
	if x, ok := x.GetItem().(*SnapshotItem_Iavl); ok {
		return x.Iavl
	}
	return nil
}

func (x *SnapshotItem) GetExtension() *SnapshotExtensionMeta {
	if x, ok := x.GetItem().(*SnapshotItem_Extension); ok {
		return x.Extension
	}
	return nil
}

func (x *SnapshotItem) GetExtensionPayload() *SnapshotExtensionPayload {
	if x, ok := x.GetItem().(*SnapshotItem_ExtensionPayload); ok {
		return x.ExtensionPayload
	}
	return nil
}

// Deprecated: Do not use.
func (x *SnapshotItem) GetKv() *SnapshotKVItem {
	if x, ok := x.GetItem().(*SnapshotItem_Kv); ok {
		return x.Kv
	}
	return nil
}

// Deprecated: Do not use.
func (x *SnapshotItem) GetSchema() *SnapshotSchema {
	if x, ok := x.GetItem().(*SnapshotItem_Schema); ok {
		return x.Schema
	}
	return nil
}

type isSnapshotItem_Item interface {
	isSnapshotItem_Item()
}

type SnapshotItem_Store struct {
	Store *SnapshotStoreItem `protobuf:"bytes,1,opt,name=store,proto3,oneof"`
}

type SnapshotItem_Iavl struct {
	Iavl *SnapshotIAVLItem `protobuf:"bytes,2,opt,name=iavl,proto3,oneof"`
}

type SnapshotItem_Extension struct {
	Extension *SnapshotExtensionMeta `protobuf:"bytes,3,opt,name=extension,proto3,oneof"`
}

type SnapshotItem_ExtensionPayload struct {
	ExtensionPayload *SnapshotExtensionPayload `protobuf:"bytes,4,opt,name=extension_payload,json=extensionPayload,proto3,oneof"`
}

type SnapshotItem_Kv struct {
	// Deprecated: Do not use.
	Kv *SnapshotKVItem `protobuf:"bytes,5,opt,name=kv,proto3,oneof"`
}

type SnapshotItem_Schema struct {
	// Deprecated: Do not use.
	Schema *SnapshotSchema `protobuf:"bytes,6,opt,name=schema,proto3,oneof"`
}

func (*SnapshotItem_Store) isSnapshotItem_Item() {}

func (*SnapshotItem_Iavl) isSnapshotItem_Item() {}

func (*SnapshotItem_Extension) isSnapshotItem_Item() {}

func (*SnapshotItem_ExtensionPayload) isSnapshotItem_Item() {}

func (*SnapshotItem_Kv) isSnapshotItem_Item() {}

func (*SnapshotItem_Schema) isSnapshotItem_Item() {}

// SnapshotStoreItem contains metadata about a snapshotted store.
//
// Since: cosmos-sdk 0.46
type SnapshotStoreItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *SnapshotStoreItem) Reset() {
	*x = SnapshotStoreItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotStoreItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotStoreItem) ProtoMessage() {}

func (x *SnapshotStoreItem) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotStoreItem.ProtoReflect.Descriptor instead.
func (*SnapshotStoreItem) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{3}
}

func (x *SnapshotStoreItem) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// SnapshotIAVLItem is an exported IAVL node.
//
// Since: cosmos-sdk 0.46
type SnapshotIAVLItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	// version is block height
	Version int64 `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	// height is depth of the tree.
	Height int32 `protobuf:"varint,4,opt,name=height,proto3" json:"height,omitempty"`
}

func (x *SnapshotIAVLItem) Reset() {
	*x = SnapshotIAVLItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotIAVLItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotIAVLItem) ProtoMessage() {}

func (x *SnapshotIAVLItem) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotIAVLItem.ProtoReflect.Descriptor instead.
func (*SnapshotIAVLItem) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{4}
}

func (x *SnapshotIAVLItem) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *SnapshotIAVLItem) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *SnapshotIAVLItem) GetVersion() int64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *SnapshotIAVLItem) GetHeight() int32 {
	if x != nil {
		return x.Height
	}
	return 0
}

// SnapshotExtensionMeta contains metadata about an external snapshotter.
//
// Since: cosmos-sdk 0.46
type SnapshotExtensionMeta struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name   string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Format uint32 `protobuf:"varint,2,opt,name=format,proto3" json:"format,omitempty"`
}

func (x *SnapshotExtensionMeta) Reset() {
	*x = SnapshotExtensionMeta{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotExtensionMeta) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotExtensionMeta) ProtoMessage() {}

func (x *SnapshotExtensionMeta) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotExtensionMeta.ProtoReflect.Descriptor instead.
func (*SnapshotExtensionMeta) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{5}
}

func (x *SnapshotExtensionMeta) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SnapshotExtensionMeta) GetFormat() uint32 {
	if x != nil {
		return x.Format
	}
	return 0
}

// SnapshotExtensionPayload contains payloads of an external snapshotter.
//
// Since: cosmos-sdk 0.46
type SnapshotExtensionPayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Payload []byte `protobuf:"bytes,1,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *SnapshotExtensionPayload) Reset() {
	*x = SnapshotExtensionPayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotExtensionPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotExtensionPayload) ProtoMessage() {}

func (x *SnapshotExtensionPayload) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotExtensionPayload.ProtoReflect.Descriptor instead.
func (*SnapshotExtensionPayload) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{6}
}

func (x *SnapshotExtensionPayload) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

// SnapshotKVItem is an exported Key/Value Pair
//
// Since: cosmos-sdk 0.46
// Deprecated: This message was part of store/v2alpha1 which has been deleted from v0.47.
//
// Deprecated: Do not use.
type SnapshotKVItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *SnapshotKVItem) Reset() {
	*x = SnapshotKVItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotKVItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotKVItem) ProtoMessage() {}

func (x *SnapshotKVItem) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotKVItem.ProtoReflect.Descriptor instead.
func (*SnapshotKVItem) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{7}
}

func (x *SnapshotKVItem) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *SnapshotKVItem) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// SnapshotSchema is an exported schema of smt store
//
// Since: cosmos-sdk 0.46
// Deprecated: This message was part of store/v2alpha1 which has been deleted from v0.47.
//
// Deprecated: Do not use.
type SnapshotSchema struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Keys [][]byte `protobuf:"bytes,1,rep,name=keys,proto3" json:"keys,omitempty"`
}

func (x *SnapshotSchema) Reset() {
	*x = SnapshotSchema{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotSchema) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotSchema) ProtoMessage() {}

func (x *SnapshotSchema) ProtoReflect() protoreflect.Message {
	mi := &file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotSchema.ProtoReflect.Descriptor instead.
func (*SnapshotSchema) Descriptor() ([]byte, []int) {
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP(), []int{8}
}

func (x *SnapshotSchema) GetKeys() [][]byte {
	if x != nil {
		return x.Keys
	}
	return nil
}

var File_cosmos_base_snapshots_v1beta1_snapshot_proto protoreflect.FileDescriptor

var file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2f, 0x73, 0x6e,
	0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x73, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f,
	0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1d,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e, 0x61, 0x70,
	0x73, 0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x14, 0x67,
	0x6f, 0x67, 0x6f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xb1, 0x01, 0x0a, 0x08, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74,
	0x12, 0x16, 0x0a, 0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x6f, 0x72, 0x6d,
	0x61, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x12, 0x16, 0x0a, 0x06, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x06, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x49, 0x0a, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27,
	0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x42, 0x04, 0xc8, 0xde, 0x1f, 0x00, 0x52, 0x08, 0x6d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x2d, 0x0a, 0x08, 0x4d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x5f, 0x68, 0x61, 0x73,
	0x68, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x68, 0x75, 0x6e, 0x6b,
	0x48, 0x61, 0x73, 0x68, 0x65, 0x73, 0x22, 0x87, 0x04, 0x0a, 0x0c, 0x53, 0x6e, 0x61, 0x70, 0x73,
	0x68, 0x6f, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x48, 0x0a, 0x05, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e,
	0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76,
	0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x53,
	0x74, 0x6f, 0x72, 0x65, 0x49, 0x74, 0x65, 0x6d, 0x48, 0x00, 0x52, 0x05, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x12, 0x4f, 0x0a, 0x04, 0x69, 0x61, 0x76, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x2f, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e,
	0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e,
	0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x49, 0x41, 0x56, 0x4c, 0x49, 0x74, 0x65, 0x6d,
	0x42, 0x08, 0xe2, 0xde, 0x1f, 0x04, 0x49, 0x41, 0x56, 0x4c, 0x48, 0x00, 0x52, 0x04, 0x69, 0x61,
	0x76, 0x6c, 0x12, 0x54, 0x0a, 0x09, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x34, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62,
	0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31,
	0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x45, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x48, 0x00, 0x52, 0x09, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x66, 0x0a, 0x11, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x37, 0x2e, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73,
	0x65, 0x2e, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x62, 0x65,
	0x74, 0x61, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x45, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48, 0x00, 0x52, 0x10,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x12, 0x49, 0x0a, 0x02, 0x6b, 0x76, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63,
	0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e, 0x61, 0x70, 0x73,
	0x68, 0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x4b, 0x56, 0x49, 0x74, 0x65, 0x6d, 0x42, 0x08, 0x18, 0x01, 0xe2,
	0xde, 0x1f, 0x02, 0x4b, 0x56, 0x48, 0x00, 0x52, 0x02, 0x6b, 0x76, 0x12, 0x4b, 0x0a, 0x06, 0x73,
	0x63, 0x68, 0x65, 0x6d, 0x61, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f,
	0x73, 0x6d, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68,
	0x6f, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70,
	0x73, 0x68, 0x6f, 0x74, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x42, 0x02, 0x18, 0x01, 0x48, 0x00,
	0x52, 0x06, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x42, 0x06, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d,
	0x22, 0x27, 0x0a, 0x11, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x53, 0x74, 0x6f, 0x72,
	0x65, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x6c, 0x0a, 0x10, 0x53, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x49, 0x41, 0x56, 0x4c, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x16, 0x0a, 0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x43, 0x0a, 0x15, 0x53, 0x6e, 0x61, 0x70, 0x73,
	0x68, 0x6f, 0x74, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x74, 0x61,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x22, 0x34, 0x0a, 0x18,
	0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f,
	0x61, 0x64, 0x22, 0x3c, 0x0a, 0x0e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x4b, 0x56,
	0x49, 0x74, 0x65, 0x6d, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x18, 0x01,
	0x22, 0x28, 0x0a, 0x0e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x53, 0x63, 0x68, 0x65,
	0x6d, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x04, 0x6b, 0x65, 0x79, 0x73, 0x3a, 0x02, 0x18, 0x01, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2f,
	0x63, 0x6f, 0x73, 0x6d, 0x6f, 0x73, 0x2d, 0x73, 0x64, 0x6b, 0x2f, 0x73, 0x6e, 0x61, 0x70, 0x73,
	0x68, 0x6f, 0x74, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescOnce sync.Once
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescData = file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDesc
)

func file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescGZIP() []byte {
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescOnce.Do(func() {
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescData = protoimpl.X.CompressGZIP(file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescData)
	})
	return file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDescData
}

var file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_cosmos_base_snapshots_v1beta1_snapshot_proto_goTypes = []interface{}{
	(*Snapshot)(nil),                 // 0: cosmos.base.snapshots.v1beta1.Snapshot
	(*Metadata)(nil),                 // 1: cosmos.base.snapshots.v1beta1.Metadata
	(*SnapshotItem)(nil),             // 2: cosmos.base.snapshots.v1beta1.SnapshotItem
	(*SnapshotStoreItem)(nil),        // 3: cosmos.base.snapshots.v1beta1.SnapshotStoreItem
	(*SnapshotIAVLItem)(nil),         // 4: cosmos.base.snapshots.v1beta1.SnapshotIAVLItem
	(*SnapshotExtensionMeta)(nil),    // 5: cosmos.base.snapshots.v1beta1.SnapshotExtensionMeta
	(*SnapshotExtensionPayload)(nil), // 6: cosmos.base.snapshots.v1beta1.SnapshotExtensionPayload
	(*SnapshotKVItem)(nil),           // 7: cosmos.base.snapshots.v1beta1.SnapshotKVItem
	(*SnapshotSchema)(nil),           // 8: cosmos.base.snapshots.v1beta1.SnapshotSchema
}
var file_cosmos_base_snapshots_v1beta1_snapshot_proto_depIdxs = []int32{
	1, // 0: cosmos.base.snapshots.v1beta1.Snapshot.metadata:type_name -> cosmos.base.snapshots.v1beta1.Metadata
	3, // 1: cosmos.base.snapshots.v1beta1.SnapshotItem.store:type_name -> cosmos.base.snapshots.v1beta1.SnapshotStoreItem
	4, // 2: cosmos.base.snapshots.v1beta1.SnapshotItem.iavl:type_name -> cosmos.base.snapshots.v1beta1.SnapshotIAVLItem
	5, // 3: cosmos.base.snapshots.v1beta1.SnapshotItem.extension:type_name -> cosmos.base.snapshots.v1beta1.SnapshotExtensionMeta
	6, // 4: cosmos.base.snapshots.v1beta1.SnapshotItem.extension_payload:type_name -> cosmos.base.snapshots.v1beta1.SnapshotExtensionPayload
	7, // 5: cosmos.base.snapshots.v1beta1.SnapshotItem.kv:type_name -> cosmos.base.snapshots.v1beta1.SnapshotKVItem
	8, // 6: cosmos.base.snapshots.v1beta1.SnapshotItem.schema:type_name -> cosmos.base.snapshots.v1beta1.SnapshotSchema
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_cosmos_base_snapshots_v1beta1_snapshot_proto_init() }
func file_cosmos_base_snapshots_v1beta1_snapshot_proto_init() {
	if File_cosmos_base_snapshots_v1beta1_snapshot_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Snapshot); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Metadata); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotItem); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotStoreItem); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotIAVLItem); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotExtensionMeta); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotExtensionPayload); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotKVItem); i {
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
		file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotSchema); i {
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
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*SnapshotItem_Store)(nil),
		(*SnapshotItem_Iavl)(nil),
		(*SnapshotItem_Extension)(nil),
		(*SnapshotItem_ExtensionPayload)(nil),
		(*SnapshotItem_Kv)(nil),
		(*SnapshotItem_Schema)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cosmos_base_snapshots_v1beta1_snapshot_proto_goTypes,
		DependencyIndexes: file_cosmos_base_snapshots_v1beta1_snapshot_proto_depIdxs,
		MessageInfos:      file_cosmos_base_snapshots_v1beta1_snapshot_proto_msgTypes,
	}.Build()
	File_cosmos_base_snapshots_v1beta1_snapshot_proto = out.File
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_rawDesc = nil
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_goTypes = nil
	file_cosmos_base_snapshots_v1beta1_snapshot_proto_depIdxs = nil
}
