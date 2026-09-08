package machardware

import (
	"encoding/base64"
	"encoding/json"
	"howett.net/plist"
	"strings"
	"testing"
)

func TestHardwareParserPreservesRealModelAndDistinctIdentifiers(t *testing.T) {
	for _, number := range []any{8, "8"} {
		data, _ := json.Marshal(map[string]any{"SPHardwareDataType": []any{map[string]any{
			"machine_model": "iMacPro1,1", "serial_number": "ABCD123456", "number_processors": number, "physical_memory": "32 GB",
			"cpu_type": "Intel Xeon", "platform_UUID": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "provisioning_UDID": "00006001-001234567890ABCD",
		}}})
		s, err := Parse(data)
		if err != nil || s.Computer.Model != "iMacPro1,1" || s.Computer.ProcessorCores != 8 || s.Computer.Memory != 32768 || s.Computer.Processor != "Intel Xeon" {
			t.Fatal("hardware parsing changed the device", err)
		}
		h, err := s.Inventory("12345678-1234-4234-8234-123456789abc")
		if err != nil || h.PlatformUUID == h.ProvisioningUDID || h.ProvisioningUDID != "00006001-001234567890ABCD" {
			t.Fatal("hardware identities conflated", err)
		}
	}
	s, err := Parse([]byte(`{"SPHardwareDataType":[{"machine_model":"Mac16,1","chip_type":"Apple M4","number_processors":"unrecognized","physical_memory":"24 GB"}]}`))
	if err != nil || s.Computer.Processor != "Apple M4" || s.Computer.ProcessorCores != 0 || s.Computer.Memory != 24576 {
		t.Fatal("silicon metadata lost", err)
	}
	if _, err := s.Inventory("12345678-1234-4234-8234-123456789abc"); err == nil {
		t.Fatal("missing identifiers became linking evidence")
	}
	for _, input := range []string{"", "null", "{}", `{"SPHardwareDataType":[]}`, `{"SPHardwareDataType":[{},{}]}`, strings.Repeat(" ", MaxHardwareBytes+1)} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatal("invalid hardware document accepted")
		}
	}
	for _, input := range []string{"-1 GB", "18446744073709551615 GB", "unknown", "32 TB"} {
		if memoryMB(input) != 0 {
			t.Fatal("invalid memory accepted")
		}
	}
}

func TestBindingParserAcceptsBinaryAndXMLWithoutCoercionOrSecretErrors(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	valid := map[string]any{"ChallengeID": "12345678-1234-4234-8234-123456789abc", "DeviceID": "12345678-1234-4234-8234-123456789abd", "Token": token}
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		data, err := plist.Marshal(valid, format)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := parseBinding(data)
		if err != nil || proof.Token != token || !proof.Valid() {
			t.Fatal("managed proof did not survive plist parsing", err)
		}
	}
	for _, wrong := range []any{uint64(12), []byte(token), "", token + "=", strings.Repeat("x", maxBindingBytes+1)} {
		valid["Token"] = wrong
		data, err := plist.Marshal(valid, plist.XMLFormat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseBinding(data); err != ErrBinding || strings.Contains(err.Error(), token) {
			t.Fatal("invalid proof accepted or disclosed")
		}
	}
	if _, err := parseBinding([]byte(`{"Token":"` + token + `"}`)); err != ErrBinding {
		t.Fatal("non-plist proof accepted")
	}
}
