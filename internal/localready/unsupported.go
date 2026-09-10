//go:build !darwin && !windows

package localready

import (
	"context"
	"github.com/nats-io/nkeys"
)

type Server struct{}

func Listen(context.Context, string, Identity, nkeys.KeyPair) (*Server, error) {
	return nil, ErrUnavailable
}
func (*Server) MarkReady() error                            { return ErrUnavailable }
func (*Server) Close() error                                { return nil }
func Probe(context.Context, string, Identity, string) error { return ErrUnavailable }
