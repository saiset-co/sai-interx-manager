// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: kira/spending/tx.proto

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
	Msg_CreateSpendingPool_FullMethodName              = "/kira.spending.Msg/CreateSpendingPool"
	Msg_DepositSpendingPool_FullMethodName             = "/kira.spending.Msg/DepositSpendingPool"
	Msg_RegisterSpendingPoolBeneficiary_FullMethodName = "/kira.spending.Msg/RegisterSpendingPoolBeneficiary"
	Msg_ClaimSpendingPool_FullMethodName               = "/kira.spending.Msg/ClaimSpendingPool"
)

// MsgClient is the client API for Msg service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MsgClient interface {
	// spending-pool-create- a function to allow creating a new spending pool.
	// This function can be sent by any account. The person sending the transaction automatically becomes the pool owner.
	// The original owner should provide a unique pool name when sending create tx.
	CreateSpendingPool(ctx context.Context, in *MsgCreateSpendingPool, opts ...grpc.CallOption) (*MsgCreateSpendingPoolResponse, error)
	// spending-pool-deposit - a function to allow depositing tokens to the pool address (name).
	// Any KIRA address should be able to call this function and deposit tokens.
	DepositSpendingPool(ctx context.Context, in *MsgDepositSpendingPool, opts ...grpc.CallOption) (*MsgDepositSpendingPoolResponse, error)
	// spending-pool-register - a function to register beneficiary account to be
	// eligible for claims
	RegisterSpendingPoolBeneficiary(ctx context.Context, in *MsgRegisterSpendingPoolBeneficiary, opts ...grpc.CallOption) (*MsgRegisterSpendingPoolBeneficiaryResponse, error)
	// spending-pool-claim - a function to allow claiming tokens from the pool.
	// Only beneficiaries should be able to send this transaction.
	// Funds can be claimed only for the period between current bloct time and value set in the claims property in accordance to the current distribution rate. If the pool doesn't have a sufficient balance of a specific token as defined by tokens property then that specific token should NOT be sent in any amount. If the pool has sufficient funds as defined by the amount in the tokens property then exact amount owed should be sent to the beneficiary. All tokens that can be sent should be sent all at once to the account that is claiming them. If the claim expiration period elapsed and funds were NOT claimed by the beneficiary then the funds will NOT be sent. Beneficiary will only receive tokens if he already registered and his account is present in the claims array. Claiming of specific token should be only possible if and only if the spending pool has sufficient funds to distribute funds to ALL accounts eligible for claiming them (either all eligible accounts can claim a specific token or no one).
	ClaimSpendingPool(ctx context.Context, in *MsgClaimSpendingPool, opts ...grpc.CallOption) (*MsgClaimSpendingPoolResponse, error)
}

type msgClient struct {
	cc grpc.ClientConnInterface
}

func NewMsgClient(cc grpc.ClientConnInterface) MsgClient {
	return &msgClient{cc}
}

func (c *msgClient) CreateSpendingPool(ctx context.Context, in *MsgCreateSpendingPool, opts ...grpc.CallOption) (*MsgCreateSpendingPoolResponse, error) {
	out := new(MsgCreateSpendingPoolResponse)
	err := c.cc.Invoke(ctx, Msg_CreateSpendingPool_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DepositSpendingPool(ctx context.Context, in *MsgDepositSpendingPool, opts ...grpc.CallOption) (*MsgDepositSpendingPoolResponse, error) {
	out := new(MsgDepositSpendingPoolResponse)
	err := c.cc.Invoke(ctx, Msg_DepositSpendingPool_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) RegisterSpendingPoolBeneficiary(ctx context.Context, in *MsgRegisterSpendingPoolBeneficiary, opts ...grpc.CallOption) (*MsgRegisterSpendingPoolBeneficiaryResponse, error) {
	out := new(MsgRegisterSpendingPoolBeneficiaryResponse)
	err := c.cc.Invoke(ctx, Msg_RegisterSpendingPoolBeneficiary_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) ClaimSpendingPool(ctx context.Context, in *MsgClaimSpendingPool, opts ...grpc.CallOption) (*MsgClaimSpendingPoolResponse, error) {
	out := new(MsgClaimSpendingPoolResponse)
	err := c.cc.Invoke(ctx, Msg_ClaimSpendingPool_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MsgServer is the server API for Msg service.
// All implementations must embed UnimplementedMsgServer
// for forward compatibility
type MsgServer interface {
	// spending-pool-create- a function to allow creating a new spending pool.
	// This function can be sent by any account. The person sending the transaction automatically becomes the pool owner.
	// The original owner should provide a unique pool name when sending create tx.
	CreateSpendingPool(context.Context, *MsgCreateSpendingPool) (*MsgCreateSpendingPoolResponse, error)
	// spending-pool-deposit - a function to allow depositing tokens to the pool address (name).
	// Any KIRA address should be able to call this function and deposit tokens.
	DepositSpendingPool(context.Context, *MsgDepositSpendingPool) (*MsgDepositSpendingPoolResponse, error)
	// spending-pool-register - a function to register beneficiary account to be
	// eligible for claims
	RegisterSpendingPoolBeneficiary(context.Context, *MsgRegisterSpendingPoolBeneficiary) (*MsgRegisterSpendingPoolBeneficiaryResponse, error)
	// spending-pool-claim - a function to allow claiming tokens from the pool.
	// Only beneficiaries should be able to send this transaction.
	// Funds can be claimed only for the period between current bloct time and value set in the claims property in accordance to the current distribution rate. If the pool doesn't have a sufficient balance of a specific token as defined by tokens property then that specific token should NOT be sent in any amount. If the pool has sufficient funds as defined by the amount in the tokens property then exact amount owed should be sent to the beneficiary. All tokens that can be sent should be sent all at once to the account that is claiming them. If the claim expiration period elapsed and funds were NOT claimed by the beneficiary then the funds will NOT be sent. Beneficiary will only receive tokens if he already registered and his account is present in the claims array. Claiming of specific token should be only possible if and only if the spending pool has sufficient funds to distribute funds to ALL accounts eligible for claiming them (either all eligible accounts can claim a specific token or no one).
	ClaimSpendingPool(context.Context, *MsgClaimSpendingPool) (*MsgClaimSpendingPoolResponse, error)
	mustEmbedUnimplementedMsgServer()
}

// UnimplementedMsgServer must be embedded to have forward compatible implementations.
type UnimplementedMsgServer struct {
}

func (UnimplementedMsgServer) CreateSpendingPool(context.Context, *MsgCreateSpendingPool) (*MsgCreateSpendingPoolResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSpendingPool not implemented")
}
func (UnimplementedMsgServer) DepositSpendingPool(context.Context, *MsgDepositSpendingPool) (*MsgDepositSpendingPoolResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DepositSpendingPool not implemented")
}
func (UnimplementedMsgServer) RegisterSpendingPoolBeneficiary(context.Context, *MsgRegisterSpendingPoolBeneficiary) (*MsgRegisterSpendingPoolBeneficiaryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterSpendingPoolBeneficiary not implemented")
}
func (UnimplementedMsgServer) ClaimSpendingPool(context.Context, *MsgClaimSpendingPool) (*MsgClaimSpendingPoolResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ClaimSpendingPool not implemented")
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

func _Msg_CreateSpendingPool_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgCreateSpendingPool)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).CreateSpendingPool(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_CreateSpendingPool_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).CreateSpendingPool(ctx, req.(*MsgCreateSpendingPool))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DepositSpendingPool_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDepositSpendingPool)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DepositSpendingPool(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DepositSpendingPool_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DepositSpendingPool(ctx, req.(*MsgDepositSpendingPool))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_RegisterSpendingPoolBeneficiary_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgRegisterSpendingPoolBeneficiary)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).RegisterSpendingPoolBeneficiary(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_RegisterSpendingPoolBeneficiary_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).RegisterSpendingPoolBeneficiary(ctx, req.(*MsgRegisterSpendingPoolBeneficiary))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_ClaimSpendingPool_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgClaimSpendingPool)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).ClaimSpendingPool(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_ClaimSpendingPool_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).ClaimSpendingPool(ctx, req.(*MsgClaimSpendingPool))
	}
	return interceptor(ctx, in, info, handler)
}

// Msg_ServiceDesc is the grpc.ServiceDesc for Msg service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Msg_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kira.spending.Msg",
	HandlerType: (*MsgServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateSpendingPool",
			Handler:    _Msg_CreateSpendingPool_Handler,
		},
		{
			MethodName: "DepositSpendingPool",
			Handler:    _Msg_DepositSpendingPool_Handler,
		},
		{
			MethodName: "RegisterSpendingPoolBeneficiary",
			Handler:    _Msg_RegisterSpendingPoolBeneficiary_Handler,
		},
		{
			MethodName: "ClaimSpendingPool",
			Handler:    _Msg_ClaimSpendingPool_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kira/spending/tx.proto",
}
