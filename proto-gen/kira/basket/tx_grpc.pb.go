// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: kira/basket/tx.proto

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
	Msg_DisableBasketDeposits_FullMethodName  = "/kira.basket.Msg/DisableBasketDeposits"
	Msg_DisableBasketWithdraws_FullMethodName = "/kira.basket.Msg/DisableBasketWithdraws"
	Msg_DisableBasketSwaps_FullMethodName     = "/kira.basket.Msg/DisableBasketSwaps"
	Msg_BasketTokenMint_FullMethodName        = "/kira.basket.Msg/BasketTokenMint"
	Msg_BasketTokenBurn_FullMethodName        = "/kira.basket.Msg/BasketTokenBurn"
	Msg_BasketTokenSwap_FullMethodName        = "/kira.basket.Msg/BasketTokenSwap"
	Msg_BasketClaimRewards_FullMethodName     = "/kira.basket.Msg/BasketClaimRewards"
)

// MsgClient is the client API for Msg service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MsgClient interface {
	// DisableBasketDeposits - emergency function & permission to disable one or all deposits of one or all token in the basket
	DisableBasketDeposits(ctx context.Context, in *MsgDisableBasketDeposits, opts ...grpc.CallOption) (*MsgDisableBasketDepositsResponse, error)
	// DisableBasketWithdraws - emergency function & permission to disable one or all withdrawals of one or all token in the basket
	DisableBasketWithdraws(ctx context.Context, in *MsgDisableBasketWithdraws, opts ...grpc.CallOption) (*MsgDisableBasketWithdrawsResponse, error)
	// DisableBasketSwaps - emergency function & permission to disable one or all withdrawals of one or all token in the basket
	DisableBasketSwaps(ctx context.Context, in *MsgDisableBasketSwaps, opts ...grpc.CallOption) (*MsgDisableBasketSwapsResponse, error)
	// BasketTokenMint - to mint basket tokens
	BasketTokenMint(ctx context.Context, in *MsgBasketTokenMint, opts ...grpc.CallOption) (*MsgBasketTokenMintResponse, error)
	// BasketTokenBurn - to burn basket tokens and redeem underlying aggregate tokens
	BasketTokenBurn(ctx context.Context, in *MsgBasketTokenBurn, opts ...grpc.CallOption) (*MsgBasketTokenBurnResponse, error)
	// BasketTokenSwap - to swap one or many of the basket tokens for one or many others
	BasketTokenSwap(ctx context.Context, in *MsgBasketTokenSwap, opts ...grpc.CallOption) (*MsgBasketTokenSwapResponse, error)
	// BasketClaimRewards - to force staking derivative `SDB` basket to claim outstanding rewards of one all or many aggregate `V<ID>` tokens
	BasketClaimRewards(ctx context.Context, in *MsgBasketClaimRewards, opts ...grpc.CallOption) (*MsgBasketClaimRewardsResponse, error)
}

type msgClient struct {
	cc grpc.ClientConnInterface
}

func NewMsgClient(cc grpc.ClientConnInterface) MsgClient {
	return &msgClient{cc}
}

func (c *msgClient) DisableBasketDeposits(ctx context.Context, in *MsgDisableBasketDeposits, opts ...grpc.CallOption) (*MsgDisableBasketDepositsResponse, error) {
	out := new(MsgDisableBasketDepositsResponse)
	err := c.cc.Invoke(ctx, Msg_DisableBasketDeposits_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DisableBasketWithdraws(ctx context.Context, in *MsgDisableBasketWithdraws, opts ...grpc.CallOption) (*MsgDisableBasketWithdrawsResponse, error) {
	out := new(MsgDisableBasketWithdrawsResponse)
	err := c.cc.Invoke(ctx, Msg_DisableBasketWithdraws_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) DisableBasketSwaps(ctx context.Context, in *MsgDisableBasketSwaps, opts ...grpc.CallOption) (*MsgDisableBasketSwapsResponse, error) {
	out := new(MsgDisableBasketSwapsResponse)
	err := c.cc.Invoke(ctx, Msg_DisableBasketSwaps_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) BasketTokenMint(ctx context.Context, in *MsgBasketTokenMint, opts ...grpc.CallOption) (*MsgBasketTokenMintResponse, error) {
	out := new(MsgBasketTokenMintResponse)
	err := c.cc.Invoke(ctx, Msg_BasketTokenMint_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) BasketTokenBurn(ctx context.Context, in *MsgBasketTokenBurn, opts ...grpc.CallOption) (*MsgBasketTokenBurnResponse, error) {
	out := new(MsgBasketTokenBurnResponse)
	err := c.cc.Invoke(ctx, Msg_BasketTokenBurn_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) BasketTokenSwap(ctx context.Context, in *MsgBasketTokenSwap, opts ...grpc.CallOption) (*MsgBasketTokenSwapResponse, error) {
	out := new(MsgBasketTokenSwapResponse)
	err := c.cc.Invoke(ctx, Msg_BasketTokenSwap_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) BasketClaimRewards(ctx context.Context, in *MsgBasketClaimRewards, opts ...grpc.CallOption) (*MsgBasketClaimRewardsResponse, error) {
	out := new(MsgBasketClaimRewardsResponse)
	err := c.cc.Invoke(ctx, Msg_BasketClaimRewards_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MsgServer is the server API for Msg service.
// All implementations must embed UnimplementedMsgServer
// for forward compatibility
type MsgServer interface {
	// DisableBasketDeposits - emergency function & permission to disable one or all deposits of one or all token in the basket
	DisableBasketDeposits(context.Context, *MsgDisableBasketDeposits) (*MsgDisableBasketDepositsResponse, error)
	// DisableBasketWithdraws - emergency function & permission to disable one or all withdrawals of one or all token in the basket
	DisableBasketWithdraws(context.Context, *MsgDisableBasketWithdraws) (*MsgDisableBasketWithdrawsResponse, error)
	// DisableBasketSwaps - emergency function & permission to disable one or all withdrawals of one or all token in the basket
	DisableBasketSwaps(context.Context, *MsgDisableBasketSwaps) (*MsgDisableBasketSwapsResponse, error)
	// BasketTokenMint - to mint basket tokens
	BasketTokenMint(context.Context, *MsgBasketTokenMint) (*MsgBasketTokenMintResponse, error)
	// BasketTokenBurn - to burn basket tokens and redeem underlying aggregate tokens
	BasketTokenBurn(context.Context, *MsgBasketTokenBurn) (*MsgBasketTokenBurnResponse, error)
	// BasketTokenSwap - to swap one or many of the basket tokens for one or many others
	BasketTokenSwap(context.Context, *MsgBasketTokenSwap) (*MsgBasketTokenSwapResponse, error)
	// BasketClaimRewards - to force staking derivative `SDB` basket to claim outstanding rewards of one all or many aggregate `V<ID>` tokens
	BasketClaimRewards(context.Context, *MsgBasketClaimRewards) (*MsgBasketClaimRewardsResponse, error)
	mustEmbedUnimplementedMsgServer()
}

// UnimplementedMsgServer must be embedded to have forward compatible implementations.
type UnimplementedMsgServer struct {
}

func (UnimplementedMsgServer) DisableBasketDeposits(context.Context, *MsgDisableBasketDeposits) (*MsgDisableBasketDepositsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableBasketDeposits not implemented")
}
func (UnimplementedMsgServer) DisableBasketWithdraws(context.Context, *MsgDisableBasketWithdraws) (*MsgDisableBasketWithdrawsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableBasketWithdraws not implemented")
}
func (UnimplementedMsgServer) DisableBasketSwaps(context.Context, *MsgDisableBasketSwaps) (*MsgDisableBasketSwapsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableBasketSwaps not implemented")
}
func (UnimplementedMsgServer) BasketTokenMint(context.Context, *MsgBasketTokenMint) (*MsgBasketTokenMintResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BasketTokenMint not implemented")
}
func (UnimplementedMsgServer) BasketTokenBurn(context.Context, *MsgBasketTokenBurn) (*MsgBasketTokenBurnResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BasketTokenBurn not implemented")
}
func (UnimplementedMsgServer) BasketTokenSwap(context.Context, *MsgBasketTokenSwap) (*MsgBasketTokenSwapResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BasketTokenSwap not implemented")
}
func (UnimplementedMsgServer) BasketClaimRewards(context.Context, *MsgBasketClaimRewards) (*MsgBasketClaimRewardsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BasketClaimRewards not implemented")
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

func _Msg_DisableBasketDeposits_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDisableBasketDeposits)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DisableBasketDeposits(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DisableBasketDeposits_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DisableBasketDeposits(ctx, req.(*MsgDisableBasketDeposits))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DisableBasketWithdraws_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDisableBasketWithdraws)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DisableBasketWithdraws(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DisableBasketWithdraws_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DisableBasketWithdraws(ctx, req.(*MsgDisableBasketWithdraws))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_DisableBasketSwaps_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDisableBasketSwaps)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).DisableBasketSwaps(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_DisableBasketSwaps_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).DisableBasketSwaps(ctx, req.(*MsgDisableBasketSwaps))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_BasketTokenMint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgBasketTokenMint)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).BasketTokenMint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_BasketTokenMint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).BasketTokenMint(ctx, req.(*MsgBasketTokenMint))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_BasketTokenBurn_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgBasketTokenBurn)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).BasketTokenBurn(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_BasketTokenBurn_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).BasketTokenBurn(ctx, req.(*MsgBasketTokenBurn))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_BasketTokenSwap_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgBasketTokenSwap)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).BasketTokenSwap(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_BasketTokenSwap_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).BasketTokenSwap(ctx, req.(*MsgBasketTokenSwap))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_BasketClaimRewards_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgBasketClaimRewards)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).BasketClaimRewards(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_BasketClaimRewards_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).BasketClaimRewards(ctx, req.(*MsgBasketClaimRewards))
	}
	return interceptor(ctx, in, info, handler)
}

// Msg_ServiceDesc is the grpc.ServiceDesc for Msg service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Msg_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kira.basket.Msg",
	HandlerType: (*MsgServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DisableBasketDeposits",
			Handler:    _Msg_DisableBasketDeposits_Handler,
		},
		{
			MethodName: "DisableBasketWithdraws",
			Handler:    _Msg_DisableBasketWithdraws_Handler,
		},
		{
			MethodName: "DisableBasketSwaps",
			Handler:    _Msg_DisableBasketSwaps_Handler,
		},
		{
			MethodName: "BasketTokenMint",
			Handler:    _Msg_BasketTokenMint_Handler,
		},
		{
			MethodName: "BasketTokenBurn",
			Handler:    _Msg_BasketTokenBurn_Handler,
		},
		{
			MethodName: "BasketTokenSwap",
			Handler:    _Msg_BasketTokenSwap_Handler,
		},
		{
			MethodName: "BasketClaimRewards",
			Handler:    _Msg_BasketClaimRewards_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kira/basket/tx.proto",
}
