//go:build !darwin

package macbundle

import "context"

func Build(context.Context, Options) (Result, error) { return Result{}, ErrUnsupported }
