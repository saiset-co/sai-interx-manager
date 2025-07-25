// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.19.1
// source: kira/bridge/query.proto

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
	Query_ChangeCosmosEthereumByAddress_FullMethodName = "/kira.bridge.Query/ChangeCosmosEthereumByAddress"
	Query_ChangeEthereumCosmosByAddress_FullMethodName = "/kira.bridge.Query/ChangeEthereumCosmosByAddress"
)

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type QueryClient interface {
	ChangeCosmosEthereumByAddress(ctx context.Context, in *ChangeCosmosEthereumByAddressRequest, opts ...grpc.CallOption) (*ChangeCosmosEthereumByAddressResponse, error)
	ChangeEthereumCosmosByAddress(ctx context.Context, in *ChangeEthereumCosmosByAddressRequest, opts ...grpc.CallOption) (*ChangeEthereumCosmosByAddressResponse, error)
}

type queryClient struct {
	cc grpc.ClientConnInterface
}

func NewQueryClient(cc grpc.ClientConnInterface) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) ChangeCosmosEthereumByAddress(ctx context.Context, in *ChangeCosmosEthereumByAddressRequest, opts ...grpc.CallOption) (*ChangeCosmosEthereumByAddressResponse, error) {
	out := new(ChangeCosmosEthereumByAddressResponse)
	err := c.cc.Invoke(ctx, Query_ChangeCosmosEthereumByAddress_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) ChangeEthereumCosmosByAddress(ctx context.Context, in *ChangeEthereumCosmosByAddressRequest, opts ...grpc.CallOption) (*ChangeEthereumCosmosByAddressResponse, error) {
	out := new(ChangeEthereumCosmosByAddressResponse)
	err := c.cc.Invoke(ctx, Query_ChangeEthereumCosmosByAddress_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
// All implementations must embed UnimplementedQueryServer
// for forward compatibility
type QueryServer interface {
	ChangeCosmosEthereumByAddress(context.Context, *ChangeCosmosEthereumByAddressRequest) (*ChangeCosmosEthereumByAddressResponse, error)
	ChangeEthereumCosmosByAddress(context.Context, *ChangeEthereumCosmosByAddressRequest) (*ChangeEthereumCosmosByAddressResponse, error)
	mustEmbedUnimplementedQueryServer()
}

// UnimplementedQueryServer must be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (UnimplementedQueryServer) ChangeCosmosEthereumByAddress(context.Context, *ChangeCosmosEthereumByAddressRequest) (*ChangeCosmosEthereumByAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangeCosmosEthereumByAddress not implemented")
}
func (UnimplementedQueryServer) ChangeEthereumCosmosByAddress(context.Context, *ChangeEthereumCosmosByAddressRequest) (*ChangeEthereumCosmosByAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChangeEthereumCosmosByAddress not implemented")
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

func _Query_ChangeCosmosEthereumByAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangeCosmosEthereumByAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).ChangeCosmosEthereumByAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_ChangeCosmosEthereumByAddress_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).ChangeCosmosEthereumByAddress(ctx, req.(*ChangeCosmosEthereumByAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_ChangeEthereumCosmosByAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChangeEthereumCosmosByAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).ChangeEthereumCosmosByAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Query_ChangeEthereumCosmosByAddress_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).ChangeEthereumCosmosByAddress(ctx, req.(*ChangeEthereumCosmosByAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Query_ServiceDesc is the grpc.ServiceDesc for Query service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Query_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kira.bridge.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ChangeCosmosEthereumByAddress",
			Handler:    _Query_ChangeCosmosEthereumByAddress_Handler,
		},
		{
			MethodName: "ChangeEthereumCosmosByAddress",
			Handler:    _Query_ChangeEthereumCosmosByAddress_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kira/bridge/query.proto",
}
