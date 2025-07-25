// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: kira/multistaking/query.proto

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
	Query_StakingPools_FullMethodName          = "/kira.multistaking.Query/StakingPools"
	Query_OutstandingRewards_FullMethodName    = "/kira.multistaking.Query/OutstandingRewards"
	Query_Undelegations_FullMethodName         = "/kira.multistaking.Query/Undelegations"
	Query_CompoundInfo_FullMethodName          = "/kira.multistaking.Query/CompoundInfo"
	Query_StakingPoolDelegators_FullMethodName = "/kira.multistaking.Query/StakingPoolDelegators"
)

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type QueryClient interface {
	StakingPools(ctx context.Context, in *QueryStakingPoolsRequest, opts ...grpc.CallOption) (*QueryStakingPoolsResponse, error)
	OutstandingRewards(ctx context.Context, in *QueryOutstandingRewardsRequest, opts ...grpc.CallOption) (*QueryOutstandingRewardsResponse, error)
	Undelegations(ctx context.Context, in *QueryUndelegationsRequest, opts ...grpc.CallOption) (*QueryUndelegationsResponse, error)
	CompoundInfo(ctx context.Context, in *QueryCompoundInfoRequest, opts ...grpc.CallOption) (*QueryCompoundInfoResponse, error)
	StakingPoolDelegators(ctx context.Context, in *QueryStakingPoolDelegatorsRequest, opts ...grpc.CallOption) (*QueryStakingPoolDelegatorsResponse, error)
}

type queryClient struct {
	cc grpc.ClientConnInterface
}

func NewQueryClient(cc grpc.ClientConnInterface) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) StakingPools(ctx context.Context, in *QueryStakingPoolsRequest, opts ...grpc.CallOption) (*QueryStakingPoolsResponse, error) {
	out := new(QueryStakingPoolsResponse)
	err := c.cc.Invoke(ctx, Query_StakingPools_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) OutstandingRewards(ctx context.Context, in *QueryOutstandingRewardsRequest, opts ...grpc.CallOption) (*QueryOutstandingRewardsResponse, error) {
	out := new(QueryOutstandingRewardsResponse)
	err := c.cc.Invoke(ctx, Query_OutstandingRewards_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) Undelegations(ctx context.Context, in *QueryUndelegationsRequest, opts ...grpc.CallOption) (*QueryUndelegationsResponse, error) {
	out := new(QueryUndelegationsResponse)
	err := c.cc.Invoke(ctx, Query_Undelegations_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) CompoundInfo(ctx context.Context, in *QueryCompoundInfoRequest, opts ...grpc.CallOption) (*QueryCompoundInfoResponse, error) {
	out := new(QueryCompoundInfoResponse)
	err := c.cc.Invoke(ctx, Query_CompoundInfo_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) StakingPoolDelegators(ctx context.Context, in *QueryStakingPoolDelegatorsRequest, opts ...grpc.CallOption) (*QueryStakingPoolDelegatorsResponse, error) {
	out := new(QueryStakingPoolDelegatorsResponse)
	err := c.cc.Invoke(ctx, Query_StakingPoolDelegators_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
// All implementations must embed UnimplementedQueryServer
// for forward compatibility
type QueryServer interface {
	StakingPools(context.Context, *QueryStakingPoolsRequest) (*QueryStakingPoolsResponse, error)
	OutstandingRewards(context.Context, *QueryOutstandingRewardsRequest) (*QueryOutstandingRewardsResponse, error)
	Undelegations(context.Context, *QueryUndelegationsRequest) (*QueryUndelegationsResponse, error)
	CompoundInfo(context.Context, *QueryCompoundInfoRequest) (*QueryCompoundInfoResponse, error)
	StakingPoolDelegators(context.Context, *QueryStakingPoolDelegatorsRequest) (*QueryStakingPoolDelegatorsResponse, error)
	mustEmbedUnimplementedQueryServer()
}

// UnimplementedQueryServer must be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (UnimplementedQueryServer) StakingPools(context.Context, *QueryStakingPoolsRequest) (*QueryStakingPoolsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StakingPools not implemented")
}
func (UnimplementedQueryServer) OutstandingRewards(context.Context, *QueryOutstandingRewardsRequest) (*QueryOutstandingRewardsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method OutstandingRewards not implemented")
}
func (UnimplementedQueryServer) Undelegations(context.Context, *QueryUndelegationsRequest) (*QueryUndelegationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Undelegations not implemented")
}
func (UnimplementedQueryServer) CompoundInfo(context.Context, *QueryCompoundInfoRequest) (*QueryCompoundInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CompoundInfo not implemented")
}
func (UnimplementedQueryServer) StakingPoolDelegators(context.Context, *QueryStakingPoolDelegatorsRequest) (*QueryStakingPoolDelegatorsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StakingPoolDelegators not implemented")
}
func (UnimplementedQueryServer) mustEmbedUnimplementedQueryServer() {}

// UnsafeQueryServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to QueryServer will
// result in compilation errors.
type UnsafeQueryServer interface {
	mustEmbedUnimplementedQueryServer()
}

func RegisterQueryServer(s grpc.ServiceRegistrar, srv QueryServer) {
	s.RegisterService(&Query_ServiceDesc, srv)
}

func _Query_StakingPools_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryStakingPoolsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).StakingPools(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_StakingPools_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).StakingPools(ctx, req.(*QueryStakingPoolsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_OutstandingRewards_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryOutstandingRewardsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).OutstandingRewards(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_OutstandingRewards_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).OutstandingRewards(ctx, req.(*QueryOutstandingRewardsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_Undelegations_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryUndelegationsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).Undelegations(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_Undelegations_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).Undelegations(ctx, req.(*QueryUndelegationsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_CompoundInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryCompoundInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).CompoundInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_CompoundInfo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).CompoundInfo(ctx, req.(*QueryCompoundInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_StakingPoolDelegators_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryStakingPoolDelegatorsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).StakingPoolDelegators(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_StakingPoolDelegators_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).StakingPoolDelegators(ctx, req.(*QueryStakingPoolDelegatorsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Query_ServiceDesc is the grpc.ServiceDesc for Query service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Query_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kira.multistaking.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StakingPools",
			Handler:    _Query_StakingPools_Handler,
		},
		{
			MethodName: "OutstandingRewards",
			Handler:    _Query_OutstandingRewards_Handler,
		},
		{
			MethodName: "Undelegations",
			Handler:    _Query_Undelegations_Handler,
		},
		{
			MethodName: "CompoundInfo",
			Handler:    _Query_CompoundInfo_Handler,
		},
		{
			MethodName: "StakingPoolDelegators",
			Handler:    _Query_StakingPoolDelegators_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kira/multistaking/query.proto",
}
