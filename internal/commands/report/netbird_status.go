package report

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	nats "github.com/open-uem/nats"
)

func observationText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func observationURL(value string) bool {
	if value == "" {
		return true
	}
	u, err := url.Parse(value)
	return observationText(value, 2048) && err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func netbirdOverview(raw []byte, result *nats.Netbird) error {
	if len(raw) > 1<<20 || !utf8.Valid(raw) || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return ErrNetbirdState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !netbirdJSONValue(d, 0) {
		return ErrNetbirdState
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrNetbirdState
	}
	type endpoint struct {
		URL       string `json:"url"`
		Connected *bool  `json:"connected"`
	}
	var state struct {
		IP         *string   `json:"netbirdIp"`
		Profile    string    `json:"profileName"`
		Management *endpoint `json:"management"`
		Signal     *endpoint `json:"signal"`
		Peers      *struct {
			Total     *int `json:"total"`
			Connected *int `json:"connected"`
		} `json:"peers"`
		SSH struct {
			Enabled bool `json:"enabled"`
		} `json:"sshServer"`
		DNS []struct {
			Servers []string `json:"servers"`
		} `json:"dnsServers"`
	}
	if json.Unmarshal(raw, &state) != nil || state.IP == nil || state.Management == nil || state.Signal == nil || state.Peers == nil || state.Management.Connected == nil || state.Signal.Connected == nil || state.Peers.Total == nil || state.Peers.Connected == nil {
		return ErrNetbirdState
	}
	if *state.IP != "" {
		if _, err := netip.ParseAddr(*state.IP); err != nil {
			if _, err = netip.ParsePrefix(*state.IP); err != nil {
				return ErrNetbirdState
			}
		}
	}
	if !observationText(state.Profile, 256) || !observationURL(state.Management.URL) || !observationURL(state.Signal.URL) || *state.Peers.Total < 0 || *state.Peers.Total > 1000000 || *state.Peers.Connected < 0 || *state.Peers.Connected > *state.Peers.Total || len(state.DNS) > 256 {
		return ErrNetbirdState
	}
	servers := make([]string, 0)
	seen := map[string]bool{}
	for _, group := range state.DNS {
		if len(group.Servers) > 256 {
			return ErrNetbirdState
		}
		for _, server := range group.Servers {
			if server == "" || !observationText(server, 512) {
				return ErrNetbirdState
			}
			if !seen[server] {
				seen[server] = true
				servers = append(servers, server)
			}
			if len(servers) > 256 {
				return ErrNetbirdState
			}
		}
	}
	result.IP = *state.IP
	result.Profile = state.Profile
	result.ManagementURL = state.Management.URL
	result.ManagementConnected = *state.Management.Connected
	result.SignalURL = state.Signal.URL
	result.SignalConnected = *state.Signal.Connected
	result.PeersTotal = *state.Peers.Total
	result.PeersConnected = *state.Peers.Connected
	result.SSHEnabled = state.SSH.Enabled
	result.DNSServers = servers
	return nil
}

// Reject duplicate keys (including case aliases) and excessive nesting before
// projecting known fields. Future nonconflicting fields remain compatible.
func netbirdJSONValue(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok {
				return false
			}
			name = strings.ToLower(name)
			if seen[name] {
				return false
			}
			seen[name] = true
			if !netbirdJSONValue(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !netbirdJSONValue(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
