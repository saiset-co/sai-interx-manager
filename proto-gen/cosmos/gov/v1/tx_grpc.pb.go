// Since: cosmos-sdk 0.46

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: cosmos/gov/v1/tx.proto

package v1

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
	Msg_SubmitProposal_FullMethodName    = "/cosmos.gov.v1.Msg/SubmitProposal"
	Msg_ExecLegacyContent_FullMethodName = "/cosmos.gov.v1.Msg/ExecLegacyContent"
	Msg_Vote_FullMethodName              = "/cosmos.gov.v1.Msg/Vote"
	Msg_VoteWeighted_FullMethodName      = "/cosmos.gov.v1.Msg/VoteWeighted"
	Msg_Deposit_FullMethodName           = "/cosmos.gov.v1.Msg/Deposit"
	Msg_UpdateParams_FullMethodName      = "/cosmos.gov.v1.Msg/UpdateParams"
)

// MsgClient is the client API for Msg service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MsgClient interface {
	// SubmitProposal defines a method to create new proposal given the messages.
	SubmitProposal(ctx context.Context, in *MsgSubmitProposal, opts ...grpc.CallOption) (*MsgSubmitProposalResponse, error)
	// ExecLegacyContent defines a Msg to be in included in a MsgSubmitProposal
	// to execute a legacy content-based proposal.
	ExecLegacyContent(ctx context.Context, in *MsgExecLegacyContent, opts ...grpc.CallOption) (*MsgExecLegacyContentResponse, error)
	// Vote defines a method to add a vote on a specific proposal.
	Vote(ctx context.Context, in *MsgVote, opts ...grpc.CallOption) (*MsgVoteResponse, error)
	// VoteWeighted defines a method to add a weighted vote on a specific proposal.
	VoteWeighted(ctx context.Context, in *MsgVoteWeighted, opts ...grpc.CallOption) (*MsgVoteWeightedResponse, error)
	// Deposit defines a method to add deposit on a specific proposal.
	Deposit(ctx context.Context, in *MsgDeposit, opts ...grpc.CallOption) (*MsgDepositResponse, error)
	// UpdateParams defines a governance operation for updating the x/gov module
	// parameters. The authority is defined in the keeper.
	//
	// Since: cosmos-sdk 0.47
	UpdateParams(ctx context.Context, in *MsgUpdateParams, opts ...grpc.CallOption) (*MsgUpdateParamsResponse, error)
}

type msgClient struct {
	cc grpc.ClientConnInterface
}

func NewMsgClient(cc grpc.ClientConnInterface) MsgClient {
	return &msgClient{cc}
}

func (c *msgClient) SubmitProposal(ctx context.Context, in *MsgSubmitProposal, opts ...grpc.CallOption) (*MsgSubmitProposalResponse, error) {
	out := new(MsgSubmitProposalResponse)
	err := c.cc.Invoke(ctx, Msg_SubmitProposal_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) ExecLegacyContent(ctx context.Context, in *MsgExecLegacyContent, opts ...grpc.CallOption) (*MsgExecLegacyContentResponse, error) {
	out := new(MsgExecLegacyContentResponse)
	err := c.cc.Invoke(ctx, Msg_ExecLegacyContent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) Vote(ctx context.Context, in *MsgVote, opts ...grpc.CallOption) (*MsgVoteResponse, error) {
	out := new(MsgVoteResponse)
	err := c.cc.Invoke(ctx, Msg_Vote_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) VoteWeighted(ctx context.Context, in *MsgVoteWeighted, opts ...grpc.CallOption) (*MsgVoteWeightedResponse, error) {
	out := new(MsgVoteWeightedResponse)
	err := c.cc.Invoke(ctx, Msg_VoteWeighted_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) Deposit(ctx context.Context, in *MsgDeposit, opts ...grpc.CallOption) (*MsgDepositResponse, error) {
	out := new(MsgDepositResponse)
	err := c.cc.Invoke(ctx, Msg_Deposit_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *msgClient) UpdateParams(ctx context.Context, in *MsgUpdateParams, opts ...grpc.CallOption) (*MsgUpdateParamsResponse, error) {
	out := new(MsgUpdateParamsResponse)
	err := c.cc.Invoke(ctx, Msg_UpdateParams_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MsgServer is the server API for Msg service.
// All implementations must embed UnimplementedMsgServer
// for forward compatibility
type MsgServer interface {
	// SubmitProposal defines a method to create new proposal given the messages.
	SubmitProposal(context.Context, *MsgSubmitProposal) (*MsgSubmitProposalResponse, error)
	// ExecLegacyContent defines a Msg to be in included in a MsgSubmitProposal
	// to execute a legacy content-based proposal.
	ExecLegacyContent(context.Context, *MsgExecLegacyContent) (*MsgExecLegacyContentResponse, error)
	// Vote defines a method to add a vote on a specific proposal.
	Vote(context.Context, *MsgVote) (*MsgVoteResponse, error)
	// VoteWeighted defines a method to add a weighted vote on a specific proposal.
	VoteWeighted(context.Context, *MsgVoteWeighted) (*MsgVoteWeightedResponse, error)
	// Deposit defines a method to add deposit on a specific proposal.
	Deposit(context.Context, *MsgDeposit) (*MsgDepositResponse, error)
	// UpdateParams defines a governance operation for updating the x/gov module
	// parameters. The authority is defined in the keeper.
	//
	// Since: cosmos-sdk 0.47
	UpdateParams(context.Context, *MsgUpdateParams) (*MsgUpdateParamsResponse, error)
	mustEmbedUnimplementedMsgServer()
}

// UnimplementedMsgServer must be embedded to have forward compatible implementations.
type UnimplementedMsgServer struct {
}

func (UnimplementedMsgServer) SubmitProposal(context.Context, *MsgSubmitProposal) (*MsgSubmitProposalResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitProposal not implemented")
}
func (UnimplementedMsgServer) ExecLegacyContent(context.Context, *MsgExecLegacyContent) (*MsgExecLegacyContentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExecLegacyContent not implemented")
}
func (UnimplementedMsgServer) Vote(context.Context, *MsgVote) (*MsgVoteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Vote not implemented")
}
func (UnimplementedMsgServer) VoteWeighted(context.Context, *MsgVoteWeighted) (*MsgVoteWeightedResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VoteWeighted not implemented")
}
func (UnimplementedMsgServer) Deposit(context.Context, *MsgDeposit) (*MsgDepositResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Deposit not implemented")
}
func (UnimplementedMsgServer) UpdateParams(context.Context, *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateParams not implemented")
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

func _Msg_SubmitProposal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgSubmitProposal)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).SubmitProposal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_SubmitProposal_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).SubmitProposal(ctx, req.(*MsgSubmitProposal))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_ExecLegacyContent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgExecLegacyContent)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).ExecLegacyContent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_ExecLegacyContent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).ExecLegacyContent(ctx, req.(*MsgExecLegacyContent))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_Vote_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgVote)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).Vote(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_Vote_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).Vote(ctx, req.(*MsgVote))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_VoteWeighted_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgVoteWeighted)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).VoteWeighted(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_VoteWeighted_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).VoteWeighted(ctx, req.(*MsgVoteWeighted))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_Deposit_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgDeposit)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).Deposit(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_Deposit_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).Deposit(ctx, req.(*MsgDeposit))
	}
	return interceptor(ctx, in, info, handler)
}

func _Msg_UpdateParams_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgUpdateParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).UpdateParams(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Msg_UpdateParams_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).UpdateParams(ctx, req.(*MsgUpdateParams))
	}
	return interceptor(ctx, in, info, handler)
}

// Msg_ServiceDesc is the grpc.ServiceDesc for Msg service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Msg_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "cosmos.gov.v1.Msg",
	HandlerType: (*MsgServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SubmitProposal",
			Handler:    _Msg_SubmitProposal_Handler,
		},
		{
			MethodName: "ExecLegacyContent",
			Handler:    _Msg_ExecLegacyContent_Handler,
		},
		{
			MethodName: "Vote",
			Handler:    _Msg_Vote_Handler,
		},
		{
			MethodName: "VoteWeighted",
			Handler:    _Msg_VoteWeighted_Handler,
		},
		{
			MethodName: "Deposit",
			Handler:    _Msg_Deposit_Handler,
		},
		{
			MethodName: "UpdateParams",
			Handler:    _Msg_UpdateParams_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cosmos/gov/v1/tx.proto",
}
