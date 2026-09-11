//go:build windows && (amd64 || arm64)

package burnbundle

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestNativeCabinetManifestMemoryOnly(t *testing.T) {
	if unsafe.Sizeof(fdiNotification{}) != 64 || unsafe.Offsetof(fdiNotification{}.Name) != 8 || unsafe.Offsetof(fdiNotification{}.Handle) != 40 || unsafe.Offsetof(fdiNotification{}.Error) != 60 {
		t.Fatal("FDI notification ABI mismatch")
	}
	for _, compressed := range []bool{false, true} {
		for _, reserve := range []bool{false, true} {
			payload := bytes.Repeat([]byte("bounded manifest bytes"), 4000)
			cab := cabinetFixture(t, payload, compressed, reserve)
			index, err := indexCabinet(t.Context(), bytes.NewReader(cab), int64(len(cab)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeCabinet(t.Context(), bytes.NewReader(cab), int64(len(cab)), index)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("compression=%v reserve=%v: native decode %v, bytes=%d", compressed, reserve, err, len(got))
			}
			if activeCabinet != nil {
				t.Fatal("native decode context retained")
			}
		}
	}
}

func TestNativeRegistrationBindsContainerAndXML(t *testing.T) {
	for _, modern := range []bool{false, true} {
		layout, manifest := registrationFixture("amd64", modern, true)
		cab := cabinetFixture(t, manifest, true, true)
		bundle := append(layoutFixture(0x8664)[:2048], cab...)
		put32(bundle, 1584, uint32(len(cab)))
		got, err := ReadRegistration(t.Context(), bytes.NewReader(bundle), int64(len(bundle)))
		if err != nil || got.BundleCode != layout.BundleCode || got.Scope != "machine" || got.RegistryView != "64" || got.Version != "1.2.3.4" {
			t.Fatalf("native metadata binding: %+v %v", got, err)
		}
		bundle[1544] ^= 1
		got, err = ReadRegistration(t.Context(), bytes.NewReader(bundle), int64(len(bundle)))
		if err != ErrFormat || got != (Registration{}) {
			t.Fatal("mismatched bundle code accepted")
		}
	}
}

func TestNativeCabinetRejectsFailureAndIncompleteOutput(t *testing.T) {
	payload := []byte("bounded manifest")
	cab := cabinetFixture(t, payload, true, false)
	index, err := indexCabinet(t.Context(), bytes.NewReader(cab), int64(len(cab)))
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []int64{0, index.manifestSize - 1, index.manifestSize + 1, maxManifestSize + 1} {
		bad := index
		bad.manifestSize = length
		got, err := decodeCabinet(t.Context(), bytes.NewReader(cab), int64(len(cab)), bad)
		if err != ErrFormat || got != nil {
			t.Fatal("mismatched output accepted")
		}
	}
	got, err := decodeCabinet(t.Context(), &faultReader{ReaderAt: bytes.NewReader(cab), fail: 1}, int64(len(cab)), index)
	if err != ErrFormat || got != nil {
		t.Fatal("read failure accepted")
	}
	broken := append([]byte(nil), cab...)
	broken[int(u32(broken[36:]))+8] = 0 // Corrupt the MSZIP CK marker after directory validation.
	got, err = decodeCabinet(t.Context(), bytes.NewReader(broken), int64(len(broken)), index)
	if err != ErrFormat || got != nil {
		t.Fatal("corrupt compression accepted")
	}
	if activeCabinet != nil {
		t.Fatal("failed decode context retained")
	}
}

func TestNativeCabinetSerializedCancellationAndReuse(t *testing.T) {
	payload := []byte("manifest")
	cab := cabinetFixture(t, payload, true, false)
	index, err := indexCabinet(t.Context(), bytes.NewReader(cab), int64(len(cab)))
	if err != nil {
		t.Fatal(err)
	}
	cabinetGate <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	_, err = decodeCabinet(ctx, bytes.NewReader(cab), int64(len(cab)), index)
	cancel()
	<-cabinetGate
	if err != ErrFormat {
		t.Fatal("cancelled gate admission accepted")
	}
	var group sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Go(func() {
			for j := 0; j < 24; j++ {
				got, err := decodeCabinet(t.Context(), bytes.NewReader(cab), int64(len(cab)), index)
				if err != nil {
					results <- err
					return
				}
				if !bytes.Equal(got, payload) {
					results <- ErrFormat
					return
				}
			}
			results <- nil
		})
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("serialized native decoder reuse", err)
		}
	}
	if activeCabinet != nil {
		t.Fatal("native context retained after reuse")
	}
}
