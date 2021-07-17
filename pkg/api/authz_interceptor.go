package api

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type AuthzInterceptor struct {
	permissions map[string]map[string]struct{}
}

type AuthzInterceptorOptions struct {
	// Permissions maps from a client certificate common name to a
	// list of allowed endpoints. The endpoints are as described by
	// the grpc.UnaryServerInfo/grpc.StreamServerInfo FullMethod
	// variable.
	Permissions map[string][]string
}

// NewAuthzInterceptor creates an authorization interceptor from the
// argument options.
func NewAuthzInterceptor(opts AuthzInterceptorOptions) *AuthzInterceptor {
	a := &AuthzInterceptor{
		permissions: make(map[string]map[string]struct{}, len(opts.Permissions)),
	}

	for cn, endpoints := range opts.Permissions {
		permissions := make(map[string]struct{}, len(endpoints))
		for _, endpoint := range endpoints {
			permissions[endpoint] = struct{}{}
		}
		a.permissions[cn] = permissions
	}
	return a
}

// Unary returns a grpc.UnaryServerInterceptor responsible for enforcing
// the authorization rules configured for this interceptor.
func (a *AuthzInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := a.authorize(ctx, info.FullMethod); err != nil {
			logrus.WithFields(logrus.Fields{
				"request": req,
				"method":  info.FullMethod,
			}).Debugf("unary authz failed: %v", err)
			return nil, status.Error(codes.PermissionDenied, "")
		}

		return handler(ctx, req)
	}
}

// Stream returns a grpc.StreamServerInterceptor responsible for enforcing
// the authorization rules configured for this interceptor.
func (a *AuthzInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := a.authorize(stream.Context(), info.FullMethod); err != nil {
			logrus.WithFields(logrus.Fields{
				"method": info.FullMethod,
			}).Debugf("stream authz failed: %v", err)
			return status.Error(codes.PermissionDenied, "")
		}

		return handler(srv, stream)
	}
}

// authorize extracts the peer's client certificate from the argument
// context. The common name in the certificate is used as a key to the
// permissions map, and the request is authorized only if the common
// name has been granted permissions for the argument method.
func (a *AuthzInterceptor) authorize(ctx context.Context, method string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("failed to get peer from context")
	}

	if p.AuthInfo == nil {
		return fmt.Errorf("peer has no auth info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return fmt.Errorf("failed to get TLS info from auth info")
	}

	if len(tlsInfo.State.VerifiedChains) < 1 {
		return fmt.Errorf("no verified chains in TLS connection state")
	}

	if len(tlsInfo.State.VerifiedChains[0]) < 1 {
		return fmt.Errorf("failed to find peer TLS certificaates")
	}

	cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	permissions, ok := a.permissions[cn]
	if !ok {
		return fmt.Errorf("CN %q has no permissions", cn)
	}

	if _, ok := permissions[method]; !ok {
		return fmt.Errorf("CN %q is not authorized to access %q", cn, method)
	}

	return nil
}
