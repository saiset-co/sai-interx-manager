// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: kira/custody/tx.proto

package types

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Msg_CreateCustody_FullMethodName        = "/kira.custody.Msg/CreateCustody"
	Msg_DisableCustody_FullMethodName       = "/kira.custody.Msg/DisableCustody"
	Msg_DropCustody_FullMethodName          = "/kira.custody.Msg/DropCustody"
	Msg_AddToCustodians_FullMethodName      = "/kira.custody.Msg/AddToCustodians"
	Msg_RemoveFromCustodians_FullMethodName = "/kira.custody.Msg/RemoveFromCustodians"
	Msg_DropCustodians_FullMethodName       = "/kira.custody.Msg/DropCustodians"
	Msg_AddToWhiteList_FullMethodName       = "/kira.custody.Msg/AddToWhiteList"
	Msg_RemoveFromWhiteList_FullMethodName  = "/kira.custody.Msg/RemoveFromWhiteList"
	Msg_DropWhiteList_FullMethodName        = "/kira.custody.Msg/DropWhiteList"
	Msg_AddToLimits_FullMethodName          = "/kira.custody.Msg/AddToLimits"
	Msg_RemoveFromLimits_FullMethodName     = "/kira.custody.Msg/RemoveFromLimits"
	Msg_DropLimits_FullMethodName           = "/kira.custody.Msg/DropLimits"
	Msg_ApproveTransaction_FullMethodName   = "/kira.custody.Msg/ApproveTransaction"
	Msg_DeclineTransaction_FullMethodName   = "/kira.custody.Msg/DeclineTransaction"
	Msg_Send_FullMethodName                 = "/kira.custody.Msg/Send"
	Msg_PasswordConfirm_FullMethodName      = "/kira.custody.Msg/PasswordConfirm"
)

// MsgClient is the client API for Msg service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MsgClient interface {
	CreateCustody(ctx context.Context, in *MsgCreateCustodyRecord, opts ...grpc.CallOption) (*MsgCreateCustodyRecordResponse, error)
	DisableCustody(ctx context.Context, in *MsgDisableCustodyRecord, opts ...grpc.CallOption) (*MsgDisableCustodyRecordResponse, error)
	DropCustody(ctx context.Context, in *MsgDropCustodyRecord, opts ...grpc.CallOption) (*MsgDropCustodyRecordResponse, error)
	AddToCustodians(ctx context.Context, in *MsgAddToCustodyCustodians, opts ...grpc.CallOption) (*MsgAddToCustodyCustodiansResponse, error)
	RemoveFromCustodians(ctx context.Context, in *MsgRemoveFromCustodyCustodians, opts ...grpc.CallOption) (*MsgRemoveFromCustodyCustodiansResponse, error)
	DropCustodians(ctx context.Context, in *MsgDropCustodyCustodians, opts ...grpc.CallOption) (*MsgDropCustodyCustodiansResponse, error)
	AddToWhiteList(ctx context.Context, in *MsgAddToCustodyWhiteList, opts ...grpc.CallOption) (*MsgAddToCustodyWhiteListResponse, error)
	RemoveFromWhiteList(ctx context.Context, in *MsgRemoveFromCustodyWhiteList, opts ...grpc.CallOption) (*MsgRemoveFromCustodyWhiteListResponse, error)
	DropWhiteList(ctx context.Context, in *MsgDropCustodyWhiteList, opts ...grpc.CallOption) (*MsgDropCustodyWhiteListResponse, error)
	AddToLimits(ctx context.Context, in *MsgAddToCustodyLimits, opts ...grpc.CallOption) (*MsgAddToCustodyLimitsResponse, error)
	RemoveFromLimits(ctx context.Context, in *MsgRemoveFromCustodyLimits, opts ...grpc.CallOption) (*MsgRemoveFromCustodyLimitsResponse, error)
	DropLimits(ctx context.Context, in *MsgDropCustodyLimits, opts ...grpc.CallOption) (*MsgDropCustodyLimitsResponse, error)
	ApproveTransaction(ctx context.Context, in *MsgApproveCustodyTransaction, opts ...grpc.CallOption) (*MsgApproveCustodyTransactionResponse, error)
	DeclineTransaction(ctx context.Context, in *MsgDeclineCustodyTransaction, opts ...grpc.CallOption) (*MsgDeclineCustodyTransactionResponse, error)
	Send(ctx context.Context, in *MsgSend, opts ...grpc.CallOption) (*MsgSendResponse, error)
	PasswordConfirm(ctx context.Context, in *MsgPasswordConfirmTransaction, opts ...grpc.CallOption) (*MsgPasswordConfirmTransactionResponse, error)
}

type msgClient struct {
	cc grpc.ClientConnInterface
}

func NewMsgClient(cc grpc.ClientConnInterface) MsgClient {
	return &msgClient{cc}
}

func (c *msgClient) CreateCustody(ctx context.Context, in *MsgCreateCustodyRecord, opts ...grpc.CallOption) (*MsgCreateCustodyRecordResponse, error) {
	out := new(MsgCreateCustodyRecordResponse)
	err := c.cc.Invoke(ctx, Msg_CreateCustody_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DisableCustody(ctx context.Context, in *MsgDisableCustodyRecord, opts ...grpc.CallOption) (*MsgDisableCustodyRecordResponse, error) {
	out := new(MsgDisableCustodyRecordResponse)
	err := c.cc.Invoke(ctx, Msg_DisableCustody_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DropCustody(ctx context.Context, in *MsgDropCustodyRecord, opts ...grpc.CallOption) (*MsgDropCustodyRecordResponse, error) {
	out := new(MsgDropCustodyRecordResponse)
	err := c.cc.Invoke(ctx, Msg_DropCustody_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) AddToCustodians(ctx context.Context, in *MsgAddToCustodyCustodians, opts ...grpc.CallOption) (*MsgAddToCustodyCustodiansResponse, error) {
	out := new(MsgAddToCustodyCustodiansResponse)
	err := c.cc.Invoke(ctx, Msg_AddToCustodians_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) RemoveFromCustodians(ctx context.Context, in *MsgRemoveFromCustodyCustodians, opts ...grpc.CallOption) (*MsgRemoveFromCustodyCustodiansResponse, error) {
	out := new(MsgRemoveFromCustodyCustodiansResponse)
	err := c.cc.Invoke(ctx, Msg_RemoveFromCustodians_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DropCustodians(ctx context.Context, in *MsgDropCustodyCustodians, opts ...grpc.CallOption) (*MsgDropCustodyCustodiansResponse, error) {
	out := new(MsgDropCustodyCustodiansResponse)
	err := c.cc.Invoke(ctx, Msg_DropCustodians_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) AddToWhiteList(ctx context.Context, in *MsgAddToCustodyWhiteList, opts ...grpc.CallOption) (*MsgAddToCustodyWhiteListResponse, error) {
	out := new(MsgAddToCustodyWhiteListResponse)
	err := c.cc.Invoke(ctx, Msg_AddToWhiteList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) RemoveFromWhiteList(ctx context.Context, in *MsgRemoveFromCustodyWhiteList, opts ...grpc.CallOption) (*MsgRemoveFromCustodyWhiteListResponse, error) {
	out := new(MsgRemoveFromCustodyWhiteListResponse)
	err := c.cc.Invoke(ctx, Msg_RemoveFromWhiteList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DropWhiteList(ctx context.Context, in *MsgDropCustodyWhiteList, opts ...grpc.CallOption) (*MsgDropCustodyWhiteListResponse, error) {
	out := new(MsgDropCustodyWhiteListResponse)
	err := c.cc.Invoke(ctx, Msg_DropWhiteList_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) AddToLimits(ctx context.Context, in *MsgAddToCustodyLimits, opts ...grpc.CallOption) (*MsgAddToCustodyLimitsResponse, error) {
	out := new(MsgAddToCustodyLimitsResponse)
	err := c.cc.Invoke(ctx, Msg_AddToLimits_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) RemoveFromLimits(ctx context.Context, in *MsgRemoveFromCustodyLimits, opts ...grpc.CallOption) (*MsgRemoveFromCustodyLimitsResponse, error) {
	out := new(MsgRemoveFromCustodyLimitsResponse)
	err := c.cc.Invoke(ctx, Msg_RemoveFromLimits_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DropLimits(ctx context.Context, in *MsgDropCustodyLimits, opts ...grpc.CallOption) (*MsgDropCustodyLimitsResponse, error) {
	out := new(MsgDropCustodyLimitsResponse)
	err := c.cc.Invoke(ctx, Msg_DropLimits_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) ApproveTransaction(ctx context.Context, in *MsgApproveCustodyTransaction, opts ...grpc.CallOption) (*MsgApproveCustodyTransactionResponse, error) {
	out := new(MsgApproveCustodyTransactionResponse)
	err := c.cc.Invoke(ctx, Msg_ApproveTransaction_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DeclineTransaction(ctx context.Context, in *MsgDeclineCustodyTransaction, opts ...grpc.CallOption) (*MsgDeclineCustodyTransactionResponse, error) {
	out := new(MsgDeclineCustodyTransactionResponse)
	err := c.cc.Invoke(ctx, Msg_DeclineTransaction_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) Send(ctx context.Context, in *MsgSend, opts ...grpc.CallOption) (*MsgSendResponse, error) {
	out := new(MsgSendResponse)
	err := c.cc.Invoke(ctx, Msg_Send_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) PasswordConfirm(ctx context.Context, in *MsgPasswordConfirmTransaction, opts ...grpc.CallOption) (*MsgPasswordConfirmTransactionResponse, error) {
	out := new(MsgPasswordConfirmTransactionResponse)
	err := c.cc.Invoke(ctx, Msg_PasswordConfirm_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MsgServer is the server API for Msg service.
// All implementations must embed UnimplementedMsgServer
// for forward compatibility
type MsgServer interface {
	CreateCustody(context.Context, *MsgCreateCustodyRecord) (*MsgCreateCustodyRecordResponse, error)
	DisableCustody(context.Context, *MsgDisableCustodyRecord) (*MsgDisableCustodyRecordResponse, error)
	DropCustody(context.Context, *MsgDropCustodyRecord) (*MsgDropCustodyRecordResponse, error)
	AddToCustodians(context.Context, *MsgAddToCustodyCustodians) (*MsgAddToCustodyCustodiansResponse, error)
	RemoveFromCustodians(context.Context, *MsgRemoveFromCustodyCustodians) (*MsgRemoveFromCustodyCustodiansResponse, error)
	DropCustodians(context.Context, *MsgDropCustodyCustodians) (*MsgDropCustodyCustodiansResponse, error)
	AddToWhiteList(context.Context, *MsgAddToCustodyWhiteList) (*MsgAddToCustodyWhiteListResponse, error)
	RemoveFromWhiteList(context.Context, *MsgRemoveFromCustodyWhiteList) (*MsgRemoveFromCustodyWhiteListResponse, error)
	DropWhiteList(context.Context, *MsgDropCustodyWhiteList) (*MsgDropCustodyWhiteListResponse, error)
	AddToLimits(context.Context, *MsgAddToCustodyLimits) (*MsgAddToCustodyLimitsResponse, error)
	RemoveFromLimits(context.Context, *MsgRemoveFromCustodyLimits) (*MsgRemoveFromCustodyLimitsResponse, error)
	DropLimits(context.Context, *MsgDropCustodyLimits) (*MsgDropCustodyLimitsResponse, error)
	ApproveTransaction(context.Context, *MsgApproveCustodyTransaction) (*MsgApproveCustodyTransactionResponse, error)
	DeclineTransaction(context.Context, *MsgDeclineCustodyTransaction) (*MsgDeclineCustodyTransactionResponse, error)
	Send(context.Context, *MsgSend) (*MsgSendResponse, error)
	PasswordConfirm(context.Context, *MsgPasswordConfirmTransaction) (*MsgPasswordConfirmTransactionResponse, error)
	mustEmbedUnimplementedMsgServer()
}

// UnimplementedMsgServer must be embedded to have forward compatible implementations.
type UnimplementedMsgServer struct {
}

func (UnimplementedMsgServer) CreateCustody(context.Context, *MsgCreateCustodyRecord) (*MsgCreateCustodyRecordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateCustody not implemented")
}
func (UnimplementedMsgServer) DisableCustody(context.Context, *MsgDisableCustodyRecord) (*MsgDisableCustodyRecordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableCustody not implemented")
}
func (UnimplementedMsgServer) DropCustody(context.Context, *MsgDropCustodyRecord) (*MsgDropCustodyRecordResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DropCustody not implemented")
}
func (UnimplementedMsgServer) AddToCustodians(context.Context, *MsgAddToCustodyCustodians) (*MsgAddToCustodyCustodiansResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddToCustodians not implemented")
}
func (UnimplementedMsgServer) RemoveFromCustodians(context.Context, *MsgRemoveFromCustodyCustodians) (*MsgRemoveFromCustodyCustodiansResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveFromCustodians not implemented")
}
func (UnimplementedMsgServer) DropCustodians(context.Context, *MsgDropCustodyCustodians) (*MsgDropCustodyCustodiansResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DropCustodians not implemented")
}
func (UnimplementedMsgServer) AddToWhiteList(context.Context, *MsgAddToCustodyWhiteList) (*MsgAddToCustodyWhiteListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddToWhiteList not implemented")
}
func (UnimplementedMsgServer) RemoveFromWhiteList(context.Context, *MsgRemoveFromCustodyWhiteList) (*MsgRemoveFromCustodyWhiteListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveFromWhiteList not implemented")
}
func (UnimplementedMsgServer) DropWhiteList(context.Context, *MsgDropCustodyWhiteList) (*MsgDropCustodyWhiteListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DropWhiteList not implemented")
}
func (UnimplementedMsgServer) AddToLimits(context.Context, *MsgAddToCustodyLimits) (*MsgAddToCustodyLimitsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddToLimits not implemented")
}
func (UnimplementedMsgServer) RemoveFromLimits(context.Context, *MsgRemoveFromCustodyLimits) (*MsgRemoveFromCustodyLimitsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveFromLimits not implemented")
}
func (UnimplementedMsgServer) DropLimits(context.Context, *MsgDropCustodyLimits) (*MsgDropCustodyLimitsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DropLimits not implemented")
}
func (UnimplementedMsgServer) ApproveTransaction(context.Context, *MsgApproveCustodyTransaction) (*MsgApproveCustodyTransactionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApproveTransaction not implemented")
}
func (UnimplementedMsgServer) DeclineTransaction(context.Context, *MsgDeclineCustodyTransaction) (*MsgDeclineCustodyTransactionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeclineTransaction not implemented")
}
func (UnimplementedMsgServer) Send(context.Context, *MsgSend) (*MsgSendResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Send not implemented")
}
func (UnimplementedMsgServer) PasswordConfirm(context.Context, *MsgPasswordConfirmTransaction) (*MsgPasswordConfirmTransactionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PasswordConfirm not implemented")
}
func (UnimplementedMsgServer) mustEmbedUnimplementedMsgServer() {}

// UnsafeMsgServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MsgServer will
// result in compilation errors.
type UnsafeMsgServer interface {
	mustEmbedUnimplementedMsgServer()
}

func RegisterMsgServer(s grpc.ServiceRegistrar, srv MsgServer) {
	s.RegisterService(&Msg_ServiceDesc, srv)
}

func _Msg_CreateCustody_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgCreateCustodyRecord)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).CreateCustody(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_CreateCustody_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).CreateCustody(ctx, req.(*MsgCreateCustodyRecord))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DisableCustody_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDisableCustodyRecord)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DisableCustody(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DisableCustody_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DisableCustody(ctx, req.(*MsgDisableCustodyRecord))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DropCustody_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDropCustodyRecord)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DropCustody(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DropCustody_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DropCustody(ctx, req.(*MsgDropCustodyRecord))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_AddToCustodians_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgAddToCustodyCustodians)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).AddToCustodians(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_AddToCustodians_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).AddToCustodians(ctx, req.(*MsgAddToCustodyCustodians))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_RemoveFromCustodians_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgRemoveFromCustodyCustodians)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).RemoveFromCustodians(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_RemoveFromCustodians_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).RemoveFromCustodians(ctx, req.(*MsgRemoveFromCustodyCustodians))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DropCustodians_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDropCustodyCustodians)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DropCustodians(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DropCustodians_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DropCustodians(ctx, req.(*MsgDropCustodyCustodians))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_AddToWhiteList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgAddToCustodyWhiteList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).AddToWhiteList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_AddToWhiteList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).AddToWhiteList(ctx, req.(*MsgAddToCustodyWhiteList))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_RemoveFromWhiteList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgRemoveFromCustodyWhiteList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).RemoveFromWhiteList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_RemoveFromWhiteList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).RemoveFromWhiteList(ctx, req.(*MsgRemoveFromCustodyWhiteList))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DropWhiteList_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDropCustodyWhiteList)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DropWhiteList(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DropWhiteList_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DropWhiteList(ctx, req.(*MsgDropCustodyWhiteList))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_AddToLimits_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgAddToCustodyLimits)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).AddToLimits(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_AddToLimits_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).AddToLimits(ctx, req.(*MsgAddToCustodyLimits))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_RemoveFromLimits_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgRemoveFromCustodyLimits)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).RemoveFromLimits(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_RemoveFromLimits_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).RemoveFromLimits(ctx, req.(*MsgRemoveFromCustodyLimits))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DropLimits_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDropCustodyLimits)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DropLimits(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DropLimits_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DropLimits(ctx, req.(*MsgDropCustodyLimits))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_ApproveTransaction_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgApproveCustodyTransaction)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).ApproveTransaction(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_ApproveTransaction_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).ApproveTransaction(ctx, req.(*MsgApproveCustodyTransaction))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DeclineTransaction_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDeclineCustodyTransaction)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DeclineTransaction(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DeclineTransaction_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DeclineTransaction(ctx, req.(*MsgDeclineCustodyTransaction))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_Send_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgSend)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).Send(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_Send_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).Send(ctx, req.(*MsgSend))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_PasswordConfirm_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgPasswordConfirmTransaction)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).PasswordConfirm(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_PasswordConfirm_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).PasswordConfirm(ctx, req.(*MsgPasswordConfirmTransaction))
	}
	return interceptor(ctx, in, info, handler)
}

// Msg_ServiceDesc is the grpc.ServiceDesc for Msg service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Msg_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kira.custody.Msg",
	HandlerType: (*MsgServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateCustody",
			Handler:    _Msg_CreateCustody_Handler,
		},
		{
			MethodName: "DisableCustody",
			Handler:    _Msg_DisableCustody_Handler,
		},
		{
			MethodName: "DropCustody",
			Handler:    _Msg_DropCustody_Handler,
		},
		{
			MethodName: "AddToCustodians",
			Handler:    _Msg_AddToCustodians_Handler,
		},
		{
			MethodName: "RemoveFromCustodians",
			Handler:    _Msg_RemoveFromCustodians_Handler,
		},
		{
			MethodName: "DropCustodians",
			Handler:    _Msg_DropCustodians_Handler,
		},
		{
			MethodName: "AddToWhiteList",
			Handler:    _Msg_AddToWhiteList_Handler,
		},
		{
			MethodName: "RemoveFromWhiteList",
			Handler:    _Msg_RemoveFromWhiteList_Handler,
		},
		{
			MethodName: "DropWhiteList",
			Handler:    _Msg_DropWhiteList_Handler,
		},
		{
			MethodName: "AddToLimits",
			Handler:    _Msg_AddToLimits_Handler,
		},
		{
			MethodName: "RemoveFromLimits",
			Handler:    _Msg_RemoveFromLimits_Handler,
		},
		{
			MethodName: "DropLimits",
			Handler:    _Msg_DropLimits_Handler,
		},
		{
			MethodName: "ApproveTransaction",
			Handler:    _Msg_ApproveTransaction_Handler,
		},
		{
			MethodName: "DeclineTransaction",
			Handler:    _Msg_DeclineTransaction_Handler,
		},
		{
			MethodName: "Send",
			Handler:    _Msg_Send_Handler,
		},
		{
			MethodName: "PasswordConfirm",
			Handler:    _Msg_PasswordConfirm_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kira/custody/tx.proto",
}
