package machardware

import (
	"errors"
	"github.com/open-uem/nats/enrollment"
	"howett.net/plist"
)

const maxBindingBytes = 16 << 10

var ErrBinding = errors.New("Mac management binding is unavailable")

func parseBinding(data []byte) (*enrollment.MacBindingProof, error) {
	if len(data) == 0 || len(data) > maxBindingBytes {
		return nil, ErrBinding
	}
	var values map[string]any
	format, err := plist.Unmarshal(data, &values)
	if err != nil || (format != plist.XMLFormat && format != plist.BinaryFormat) || len(values) != 3 {
		return nil, ErrBinding
	}
	challenge, ok1 := values["ChallengeID"].(string)
	device, ok2 := values["DeviceID"].(string)
	token, ok3 := values["Token"].(string)
	proof := &enrollment.MacBindingProof{ChallengeID: challenge, DeviceID: device, Token: token}
	if !ok1 || !ok2 || !ok3 || !proof.Valid() {
		return nil, ErrBinding
	}
	return proof, nil
}
