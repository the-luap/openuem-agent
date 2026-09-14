// Package linuxservice defines the installed Linux agent's systemd contract.
// Unit text alone does not authorize installation, activation or readiness.
package linuxservice

import (
	"bytes"
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	UnitName               = "openuem-agent.service"
	UnitPath               = "/etc/systemd/system/" + UnitName
	ConfigurationDirectory = "/etc/openuem-agent"
	LogDirectory           = "/var/log/openuem-agent"
	MaxUnitSize            = 32 << 10
)

var ErrUnit = errors.New("the Linux service definition does not match the authorized installation")

// Spec contains only the already admitted running executable and native identity
// directory. It has no service-name, user, environment or command override.
type Spec struct {
	Executable        string
	IdentityDirectory string
}

func (s Spec) Valid() bool {
	// systemd rejects quotes and backslashes in the executable itself, even
	// when they were correctly escaped in the unit's command line.
	return validPath(s.Executable) && !strings.ContainsAny(s.Executable, "\"'\\") && validPath(s.IdentityDirectory) && s.Executable != s.IdentityDirectory && !strings.HasPrefix(s.Executable, s.IdentityDirectory+"/")
}

func validPath(value string) bool {
	if !path.IsAbs(value) || value == "/" || path.Clean(value) != value || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Render emits one canonical service definition. The ':' execution prefix
// disables environment expansion; doubled '%' retains literal path specifiers.
// All arguments are quoted using systemd's syntax, without a shell intermediary.
func Render(s Spec) ([]byte, error) {
	if !s.Valid() {
		return nil, ErrUnit
	}
	data := []byte("# OpenUEM individual agent service v1\n" +
		"[Unit]\nDescription=OpenUEM individual endpoint agent\nWants=network-online.target\nAfter=network-online.target\n\n" +
		"[Service]\nType=exec\nUser=root\nGroup=root\n" +
		"ExecStart=:" + quote(s.Executable) + " serve -identity-directory " + quote(s.IdentityDirectory) + "\n" +
		"Restart=on-failure\nRestartSec=5s\nTimeoutStopSec=120s\nKillMode=mixed\nUMask=0077\n" +
		"Environment=\"" + serviceEnvironment + "\"\n\n" +
		"[Install]\nWantedBy=multi-user.target\n")
	if len(data) > MaxUnitSize {
		return nil, ErrUnit
	}
	return data, nil
}

func quote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`).Replace(value) + `"`
}

// Matches requires the whole exact definition. A marker comment or a matching
// ExecStart cannot authorize additional directives, drop-ins or a foreign unit.
// Native admission must separately prove ownership and effective manager state.
func Matches(data []byte, s Spec) bool {
	if len(data) == 0 || len(data) > MaxUnitSize {
		return false
	}
	expected, err := Render(s)
	return err == nil && bytes.Equal(data, expected)
}
