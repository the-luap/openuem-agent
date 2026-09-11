//go:build windows && (amd64 || arm64)

package burnbundle

import (
	"context"
	"io"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cabinetOutputHandle = uintptr(4096)

// FDI's allocation/file callbacks have no user-data parameter. A gate binds the
// fixed callbacks to one invocation; callbacks are registered once per process.
var cabinetGate = make(chan struct{}, 1)
var activeCabinet *cabinetDecode
var cabinetDLL = windows.NewLazySystemDLL("cabinet.dll")
var createFDI = cabinetDLL.NewProc("FDICreate")
var copyFDI = cabinetDLL.NewProc("FDICopy")
var destroyFDI = cabinetDLL.NewProc("FDIDestroy")
var cabinetCallbacks = [...]uintptr{
	windows.NewCallbackCDecl(cabinetAlloc), windows.NewCallbackCDecl(cabinetFree),
	windows.NewCallbackCDecl(cabinetOpen), windows.NewCallbackCDecl(cabinetRead),
	windows.NewCallbackCDecl(cabinetWrite), windows.NewCallbackCDecl(cabinetClose),
	windows.NewCallbackCDecl(cabinetSeek), windows.NewCallbackCDecl(cabinetNotify),
}

type cabinetDecode struct {
	ctx                                                context.Context
	reader                                             io.ReaderAt
	size, wanted, readBytes, allocated, allocatedTotal int64
	calls, opened                                      uintptr
	memory                                             map[uintptr]int64
	inputs                                             map[uintptr]int64
	output                                             []byte
	writing, complete, failed                          bool
}

type fdiNotification struct {
	Size                                           int32
	Name, Second, Third                            *byte
	User, Handle                                   uintptr
	Date, Time, Attributes, SetID, Cabinet, Folder uint16
	Error                                          int32
}

// decodeCabinet uses only memory-backed handles. The existing preflight helper
// must provide the hard process deadline when this is integrated into execution;
// cancellation here also stops subsequent native callbacks and gate acquisition.
func decodeCabinet(ctx context.Context, reader io.ReaderAt, size int64, index cabinetIndex) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || size < 36 || size > maxUXSize || index.manifestSize < 1 || index.manifestSize > maxManifestSize {
		return nil, ErrFormat
	}
	select {
	case cabinetGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrFormat
	}
	defer func() { <-cabinetGate }()
	if createFDI.Find() != nil || copyFDI.Find() != nil || destroyFDI.Find() != nil {
		return nil, ErrFormat
	}
	s := &cabinetDecode{ctx: ctx, reader: reader, size: size, wanted: index.manifestSize, memory: make(map[uintptr]int64), inputs: make(map[uintptr]int64)}
	activeCabinet = s
	defer func() {
		for ptr := range s.memory {
			windows.LocalFree(windows.Handle(ptr))
		}
		clear(s.output)
		activeCabinet = nil
	}()
	var errors [3]int32
	var pin runtime.Pinner
	pin.Pin(&errors[0])
	defer pin.Unpin()
	handle, _, _ := createFDI.Call(cabinetCallbacks[0], cabinetCallbacks[1], cabinetCallbacks[2], cabinetCallbacks[3], cabinetCallbacks[4], cabinetCallbacks[5], cabinetCallbacks[6], ^uintptr(0), uintptr(unsafe.Pointer(&errors[0])))
	if handle == 0 {
		return nil, ErrFormat
	}
	name, path := []byte("openuem.cab\x00"), []byte{0}
	result, _, _ := copyFDI.Call(handle, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&path[0])), 0, cabinetCallbacks[7], 0, 0)
	runtime.KeepAlive(name)
	runtime.KeepAlive(path)
	// The close notification intentionally aborts immediately after the manifest.
	// Other members are never extracted, even when the cabinet contains them.
	completed := result == 0 && errors[0] == 11 && errors[2] != 0 && s.complete && !s.failed && ctx.Err() == nil && int64(len(s.output)) == s.wanted
	destroyed, _, _ := destroyFDI.Call(handle)
	if !completed || destroyed == 0 || s.failed || len(s.memory) != 0 || len(s.inputs) != 0 {
		return nil, ErrFormat
	}
	return append([]byte(nil), s.output...), nil
}

func cabinetActive() *cabinetDecode {
	s := activeCabinet
	if s == nil {
		return nil
	}
	s.calls++
	if s.failed || s.ctx.Err() != nil || s.calls > 131072 {
		s.failed = true
		return nil
	}
	return s
}

func cabinetAlloc(count uintptr) uintptr {
	s := cabinetActive()
	if s == nil || count == 0 || count > 16<<20 || len(s.memory) >= 1024 {
		return 0
	}
	length := int64(count)
	if s.allocated+length > 32<<20 || s.allocatedTotal+length > 64<<20 {
		s.failed = true
		return 0
	}
	ptr, err := windows.LocalAlloc(windows.LMEM_FIXED, uint32(count))
	if err != nil || ptr == 0 {
		s.failed = true
		return 0
	}
	s.memory[ptr] = length
	s.allocated += length
	s.allocatedTotal += length
	return ptr
}

func cabinetFree(ptr uintptr) uintptr {
	// Cleanup remains available after cancellation or budget exhaustion.
	s := activeCabinet
	if ptr == 0 || s == nil {
		return 0
	}
	length, ok := s.memory[ptr]
	if !ok {
		s.failed = true
		return 0
	}
	if _, err := windows.LocalFree(windows.Handle(ptr)); err != nil {
		s.failed = true
		return 0
	}
	delete(s.memory, ptr)
	s.allocated -= length
	return 0
}

func nativeName(ptr *byte, want string) bool {
	if ptr == nil {
		return want == ""
	}
	for i := 0; i < len(want); i++ {
		if *(*byte)(unsafe.Add(unsafe.Pointer(ptr), i)) != want[i] {
			return false
		}
	}
	return *(*byte)(unsafe.Add(unsafe.Pointer(ptr), len(want))) == 0
}

func cabinetOpen(name *byte, flags, mode uintptr) uintptr {
	s := cabinetActive()
	if s == nil || !nativeName(name, "openuem.cab") || flags&3 != 0 || flags&0x700 != 0 || s.opened >= 16 {
		return ^uintptr(0)
	}
	s.opened++
	s.inputs[s.opened] = 0
	return s.opened
}

func cabinetRead(handle uintptr, buffer *byte, count uintptr) uintptr {
	s := cabinetActive()
	if s == nil || buffer == nil || count > 1<<20 {
		return ^uintptr(0)
	}
	position, ok := s.inputs[handle]
	if !ok || position < 0 || position > s.size {
		return ^uintptr(0)
	}
	length := min(int64(count), s.size-position)
	s.readBytes += length
	if s.readBytes > 2*maxUXSize {
		s.failed = true
		return ^uintptr(0)
	}
	if length == 0 {
		return 0
	}
	data := unsafe.Slice(buffer, int(length))
	n, err := s.reader.ReadAt(data, position)
	if n != len(data) || err != nil {
		s.failed = true
		return ^uintptr(0)
	}
	s.inputs[handle] += int64(n)
	return uintptr(n)
}

func cabinetWrite(handle uintptr, buffer *byte, count uintptr) uintptr {
	s := cabinetActive()
	if s == nil || handle != cabinetOutputHandle || !s.writing || buffer == nil || count > uintptr(maxManifestSize) || int64(count) > s.wanted-int64(len(s.output)) {
		return ^uintptr(0)
	}
	s.output = append(s.output, unsafe.Slice(buffer, int(count))...)
	return count
}

func cabinetClose(handle uintptr) uintptr {
	s := activeCabinet
	if s == nil {
		return ^uintptr(0)
	}
	if _, ok := s.inputs[handle]; ok {
		delete(s.inputs, handle)
		return 0
	}
	// Only the close-file notification can establish complete manifest output.
	s.failed = true
	return ^uintptr(0)
}

func cabinetSeek(handle, displacement, whence uintptr) uintptr {
	s := cabinetActive()
	if s == nil {
		return ^uintptr(0)
	}
	position, ok := s.inputs[handle]
	if !ok {
		return ^uintptr(0)
	}
	move := int64(int32(uint32(displacement))) // FDI uses a signed Windows LONG.
	switch whence {
	case 0:
		position = move
	case 1:
		position += move
	case 2:
		position = s.size + move
	default:
		return ^uintptr(0)
	}
	if position < 0 || position > s.size {
		return ^uintptr(0)
	}
	s.inputs[handle] = position
	return uintptr(position)
}

func cabinetNotify(kind uintptr, n *fdiNotification) uintptr {
	s := cabinetActive()
	if s == nil || n == nil {
		return ^uintptr(0)
	}
	switch kind {
	case 0: // fdintCABINET_INFO; external and split cabinets were rejected above.
		if n.Cabinet != 0 || !nativeName(n.Name, "") || !nativeName(n.Second, "") {
			s.failed = true
			return ^uintptr(0)
		}
		return 0
	case 2: // fdintCOPY_FILE
		if s.writing || s.complete || !nativeName(n.Name, "0") || int64(n.Size) != s.wanted || n.Attributes&0x40 != 0 {
			s.failed = true
			return ^uintptr(0)
		}
		s.writing = true
		return cabinetOutputHandle
	case 3: // fdintCLOSE_FILE_INFO; deliberately abort without executing anything.
		if !s.writing || n.Handle != cabinetOutputHandle || !nativeName(n.Name, "0") || n.Size != 0 || int64(len(s.output)) != s.wanted {
			s.failed = true
			return ^uintptr(0)
		}
		s.writing, s.complete = false, true
		return 0
	case 5: // fdintENUMERATE
		return 0
	default:
		s.failed = true
		return ^uintptr(0)
	}
}
