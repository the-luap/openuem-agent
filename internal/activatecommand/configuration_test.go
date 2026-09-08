package activatecommand

import (
	"bytes"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
)

func TestActivationConfigurationPreservesMarkedOperationalChanges(t *testing.T) {
	id := &enrollmentstore.Identity{Response: enrollment.Response{DeviceID: fixtureDeviceID}}
	data := configuration(id)
	if !validConfiguration(data, id) {
		t.Fatal("generated operational INI is invalid")
	}
	changed := bytes.ReplaceAll(data, []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = 60"))
	if !validConfiguration(changed, id) {
		t.Fatal("valid server frequency would be overwritten on retry")
	}
	for _, data := range [][]byte{
		[]byte("[Agent]\nUUID = " + fixtureDeviceID),
		append(configuration(id), []byte("\n[NATS]\nNATSServers = legacy\n")...),
		bytes.ReplaceAll(data, []byte("individual-v1"), []byte("legacy")),
		bytes.Replace(data, []byte("DeviceID = "+fixtureDeviceID), []byte("DeviceID = another-device"), 1),
		bytes.ReplaceAll(data, []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = -1")),
		bytes.ReplaceAll(data, []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = 1441")),
		bytes.ReplaceAll(data, []byte("Enabled = true"), []byte("Enabled = invalid")),
		bytes.ReplaceAll(data, []byte("SFTPDisabled = true"), []byte("SFTPDisabled = false")),
		bytes.ReplaceAll(data, []byte("SFTPPort ="), []byte("SFTPPort = 2022")),
		bytes.ReplaceAll(data, []byte("Debug = false"), []byte("Debug = false\nDebug = true")),
		bytes.ReplaceAll(data, []byte("Debug = false"), []byte("Debug = false\nDebug =")),
		bytes.ReplaceAll(data, []byte("SFTPPort ="), []byte("SFTPPort =\nSFTPPort = 2022")),
		bytes.ReplaceAll(data, []byte("DefaultFrequency = 15"), []byte("DefaultFrequency = %(WingetConfigureFrequency)s")),
		append(configuration(id), 0), []byte(strings.Repeat("x", maxConfiguration+1)),
	} {
		if validConfiguration(data, id) {
			t.Fatal("unowned or malformed configuration was adopted")
		}
	}
}
