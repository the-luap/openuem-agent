//go:build !darwin || !cgo

package macservice

import "context"

func openNative(context.Context, string) (*Service, error) { return nil, ErrUnsupported }
