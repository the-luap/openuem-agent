package activatecommand

import (
	"context"
	"os"
	"os/signal"
)

func activationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt)
}
