package linuxservice

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/godbus/dbus/v5"
)

const maxManagerMessage = 1 << 20

// godbus 5.2.2 performs header/body alignment outside its decoder's recovery
// boundary. A socket close during those padding bytes can panic its inWorker.
// Admit one bounded complete frame before exposing any bytes to that decoder.
// No socket error can then interrupt a message already handed to the library.
func (t *managerTransport) readFrame(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(t.frame) == 0 {
		var header [16]byte
		if _, err := io.ReadFull(t.UnixConn, header[:]); err != nil {
			return 0, err
		}
		var order binary.ByteOrder
		switch header[0] {
		case 'l':
			order = binary.LittleEndian
		case 'B':
			order = binary.BigEndian
		default:
			return 0, ErrManager
		}
		if header[3] != 1 {
			return 0, ErrManager
		}
		body, fields := uint64(order.Uint32(header[4:8])), uint64(order.Uint32(header[12:16]))
		size := uint64(len(header)) + ((fields + 7) &^ 7) + body
		if size > maxManagerMessage {
			return 0, ErrManager
		}
		frame := make([]byte, int(size))
		copy(frame, header[:])
		if _, err := io.ReadFull(t.UnixConn, frame[len(header):]); err != nil {
			return 0, err
		}
		if !validManagerFrame(frame) {
			return 0, ErrManager
		}
		t.frame = frame
	}
	n := copy(p, t.frame)
	t.frame = t.frame[n:]
	return n, nil
}

// Also reject malformed complete messages before the library reads the stream.
// The local boundary contains only decoding of already bounded peer bytes.
func validManagerFrame(frame []byte) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	reader := bytes.NewReader(frame)
	_, err := dbus.DecodeMessage(reader)
	return err == nil && reader.Len() == 0
}
