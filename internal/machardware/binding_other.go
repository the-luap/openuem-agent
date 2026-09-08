//go:build !darwin

package machardware

import "github.com/open-uem/nats/enrollment"

func ReadBinding() (*enrollment.MacBindingProof, error) { return nil, nil }
