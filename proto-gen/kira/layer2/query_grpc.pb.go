// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: kira/layer2/query.proto

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
	Query_ExecutionRegistrar_FullMethodName = "/kira.layer2.Query/ExecutionRegistrar"
	Query_AllDapps_FullMethodName           = "/kira.layer2.Query/AllDapps"
	Query_TransferDapps_FullMethodName      = "/kira.layer2.Query/TransferDapps"
)

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type QueryClient interface {
	// query info of a specific application by dApp ID or name
	ExecutionRegistrar(ctx context.Context, in *QueryExecutionRegistrarRequest, opts ...grpc.CallOption) (*QueryExecutionRegistrarResponse, error)
	// list IDs of all execution registrars and allow search by
	// executor or verifier kira public key (e.g. list all dApps run by address kiraXXX…YYY)
	AllDapps(ctx context.Context, in *QueryAllDappsRequest, opts ...grpc.CallOption) (*QueryAllDappsResponse, error)
	// query XAMs’ records by either account address, account index, xid or
	// transaction hash in which cross-app transaction was added to the ABR.
	TransferDapps(ctx context.Context, in *QueryTransferDappsRequest, opts ...grpc.CallOption) (*QueryTransferDappsResponse, error)
}

type queryClient struct {
	cc grpc.ClientConnInterface
}

func NewQueryClient(cc grpc.ClientConnInterface) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) ExecutionRegistrar(ctx context.Context, in *QueryExecutionRegistrarRequest, opts ...grpc.CallOption) (*QueryExecutionRegistrarResponse, error) {
	out := new(QueryExecutionRegistrarResponse)
	err := c.cc.Invoke(ctx, Query_ExecutionRegistrar_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) AllDapps(ctx context.Context, in *QueryAllDappsRequest, opts ...grpc.CallOption) (*QueryAllDappsResponse, error) {
	out := new(QueryAllDappsResponse)
	err := c.cc.Invoke(ctx, Query_AllDapps_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) TransferDapps(ctx context.Context, in *QueryTransferDappsRequest, opts ...grpc.CallOption) (*QueryTransferDappsResponse, error) {
	out := new(QueryTransferDappsResponse)
	err := c.cc.Invoke(ctx, Query_TransferDapps_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
// All implementations must embed UnimplementedQueryServer
// for forward compatibility
type QueryServer interface {
	// query info of a specific application by dApp ID or name
	ExecutionRegistrar(context.Context, *QueryExecutionRegistrarRequest) (*QueryExecutionRegistrarResponse, error)
	// list IDs of all execution registrars and allow search by
	// executor or verifier kira public key (e.g. list all dApps run by address kiraXXX…YYY)
	AllDapps(context.Context, *QueryAllDappsRequest) (*QueryAllDappsResponse, error)
	// query XAMs’ records by either account address, account index, xid or
	// transaction hash in which cross-app transaction was added to the ABR.
	TransferDapps(context.Context, *QueryTransferDappsRequest) (*QueryTransferDappsResponse, error)
	mustEmbedUnimplementedQueryServer()
}

// UnimplementedQueryServer must be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (UnimplementedQueryServer) ExecutionRegistrar(context.Context, *QueryExecutionRegistrarRequest) (*QueryExecutionRegistrarResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExecutionRegistrar not implemented")
}
func (UnimplementedQueryServer) AllDapps(context.Context, *QueryAllDappsRequest) (*QueryAllDappsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllDapps not implemented")
}
func (UnimplementedQueryServer) TransferDapps(context.Context, *QueryTransferDappsRequest) (*QueryTransferDappsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TransferDapps not implemented")
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

func _Query_ExecutionRegistrar_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryExecutionRegistrarRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).ExecutionRegistrar(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_ExecutionRegistrar_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).ExecutionRegistrar(ctx, req.(*QueryExecutionRegistrarRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_AllDapps_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryAllDappsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).AllDapps(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_AllDapps_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).AllDapps(ctx, req.(*QueryAllDappsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_TransferDapps_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryTransferDappsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).TransferDapps(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_TransferDapps_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).TransferDapps(ctx, req.(*QueryTransferDappsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Query_ServiceDesc is the grpc.ServiceDesc for Query service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Query_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kira.layer2.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ExecutionRegistrar",
			Handler:    _Query_ExecutionRegistrar_Handler,
		},
		{
			MethodName: "AllDapps",
			Handler:    _Query_AllDapps_Handler,
		},
		{
			MethodName: "TransferDapps",
			Handler:    _Query_TransferDapps_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kira/layer2/query.proto",
}
