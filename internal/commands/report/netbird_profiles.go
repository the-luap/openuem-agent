package report

import (
	"strconv"
	"strings"
	"unicode/utf8"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
)

// NetBird 0.52 used a counted list with leading active markers. Current clients
// use tabwriter columns; rune offsets preserve spaces and Unicode in labels.
func netbirdProfiles(raw []byte) ([]nats.NetbirdProfile, string, error) {
	if len(raw) > 256<<10 || !utf8.Valid(raw) {
		return nil, "", ErrNetbirdState
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) == 0 || len(lines) > netbirdstate.MaxProfiles+1 {
		return nil, "", ErrNetbirdState
	}
	header := lines[0]
	profiles := make([]nats.NetbirdProfile, 0, len(lines)-1)
	if strings.HasPrefix(header, "Found ") && strings.HasSuffix(header, " profiles:") {
		countText := strings.TrimSuffix(strings.TrimPrefix(header, "Found "), " profiles:")
		count, err := strconv.Atoi(countText)
		if err != nil || strconv.Itoa(count) != countText || count != len(lines)-1 {
			return nil, "", ErrNetbirdState
		}
		for _, line := range lines[1:] {
			marker, name, ok := strings.Cut(line, " ")
			if !ok || (marker != "✓" && marker != "✗") || !netbirdstate.ValidText(name) {
				return nil, "", ErrNetbirdState
			}
			profiles = append(profiles, nats.NetbirdProfile{Name: name, Active: marker == "✓"})
		}
		return profiles, "legacy", nil
	}
	fields := strings.Fields(header)
	format := "names"
	nameColumn := 0
	if len(fields) == 3 && fields[0] == "ID" && fields[1] == "NAME" && fields[2] == "ACTIVE" {
		format = "ids"
		nameColumn = strings.Index(header, "NAME")
	} else if len(fields) != 2 || fields[0] != "NAME" || fields[1] != "ACTIVE" {
		return nil, "", ErrNetbirdState
	}
	activeColumn := strings.Index(header, "ACTIVE")
	if strings.ContainsAny(header, "\t\r") || activeColumn <= nameColumn+4 {
		return nil, "", ErrNetbirdState
	}
	for _, line := range lines[1:] {
		runes := []rune(line)
		if len(runes) <= nameColumn {
			return nil, "", ErrNetbirdState
		}
		end := min(activeColumn, len(runes))
		name := strings.TrimRight(string(runes[nameColumn:end]), " ")
		marker := ""
		if len(runes) > activeColumn {
			marker = strings.TrimSpace(string(runes[activeColumn:]))
		}
		if marker != "" && marker != "✓" || !netbirdstate.ValidText(name) {
			return nil, "", ErrNetbirdState
		}
		profile := nats.NetbirdProfile{Name: name, Active: marker == "✓"}
		if format == "ids" {
			profile.ID = strings.TrimRight(string(runes[:nameColumn]), " ")
			if !netbirdstate.ValidID(profile.ID) {
				return nil, "", ErrNetbirdState
			}
		}
		profiles = append(profiles, profile)
	}
	return profiles, format, nil
}
