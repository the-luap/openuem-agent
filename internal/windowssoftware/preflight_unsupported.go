//go:build !windows

package windowssoftware

import "context"

func preflightNative(context.Context, preflightRequest) error { return ErrPreflight }
func readPreflight(context.Context, preflightRequest) error   { return ErrPreflight }
