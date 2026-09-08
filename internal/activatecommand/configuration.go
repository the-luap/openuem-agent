package activatecommand

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/open-uem/openuem-agent/internal/enrollmentstore"
	"gopkg.in/ini.v1"
)

const maxConfiguration = 32 << 10

func configuration(identity *enrollmentstore.Identity) []byte {
	return []byte("[Enrollment]\nMode = individual-v1\nDeviceID = " + identity.Response.DeviceID + "\n\n" +
		"[Agent]\nUUID = " + identity.Response.DeviceID + "\nEnabled = true\nExecuteTaskEveryXMinutes = 5\nDefaultFrequency = 15\nWingetConfigureFrequency = 30\nDebug = false\nSFTPPort =\nVNCProxyPort =\nSFTPDisabled = true\nRemoteAssistanceDisabled = true\nRestartRequired = false\n")
}

// Adopt only this activation flow's marked, bounded operational INI. Preserve
// valid administrator/server changes on retry; never overwrite a legacy config.
func validConfiguration(data []byte, identity *enrollmentstore.Identity) bool {
	if len(data) == 0 || len(data) > maxConfiguration || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	file, err := ini.LoadSources(ini.LoadOptions{AllowShadows: true}, data)
	if err != nil {
		return false
	}
	// Match the service's last-value-wins parser as well. ValueWithShadows
	// deliberately omits empty values, including conflicting empty duplicates.
	effective, err := ini.Load(data)
	if err != nil {
		return false
	}
	for _, section := range file.Sections() {
		if section.Name() != ini.DefaultSection && section.Name() != "Agent" && section.Name() != "Enrollment" {
			return false
		}
		for _, key := range section.Keys() {
			values := key.ValueWithShadows()
			if len(values) > 1 || (key.Value() == "" && len(values) != 0) || effective.Section(section.Name()).Key(key.Name()).Value() != key.Value() {
				return false
			}
		}
	}
	if len(file.Section(ini.DefaultSection).Keys()) != 0 {
		return false
	}
	enrollment := file.Section("Enrollment")
	if len(enrollment.Keys()) != 2 || enrollment.Key("Mode").String() != "individual-v1" || enrollment.Key("DeviceID").String() != identity.Response.DeviceID {
		return false
	}
	agent := file.Section("Agent")
	if agent.Key("UUID").String() != identity.Response.DeviceID {
		return false
	}
	for _, name := range []string{"Enabled", "Debug", "SFTPDisabled", "RemoteAssistanceDisabled"} {
		key, err := agent.GetKey(name)
		if err != nil {
			return false
		}
		value, err := key.Bool()
		if err != nil || ((name == "SFTPDisabled" || name == "RemoteAssistanceDisabled") && !value) {
			return false
		}
	}
	for _, name := range []string{"ExecuteTaskEveryXMinutes", "DefaultFrequency", "WingetConfigureFrequency"} {
		value, err := strconv.Atoi(agent.Key(name).String())
		if err != nil || value < 1 || value > 1440 {
			return false
		}
	}
	for _, name := range []string{"SFTPPort", "VNCProxyPort"} {
		key, err := agent.GetKey(name)
		if err != nil || key.String() != "" {
			return false
		}
	}
	// The INI parser may interpolate %(...) values. Operational settings must
	// remain literal rather than aliasing another section or identity field.
	for _, section := range file.Sections() {
		for _, key := range section.Keys() {
			if strings.Contains(key.Value(), "%(") {
				return false
			}
		}
	}
	return true
}
