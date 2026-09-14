package netbirdinstall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const ownedRemovalJob = `<plist version="1.0"><dict><key>Label</key><string>netbird</string><key>Program</key><string>/usr/local/bin/netbird</string><key>ProgramArguments</key><array><string>/usr/local/bin/netbird</string><string>service</string><string>run</string><string>--log-level</string><string>info</string></array><key>PID</key><integer>45</integer><key>EnvironmentVariables</key><dict><key>OWNED_SETTING</key><string>owned-private-value</string></dict></dict></plist>`

func ownedRemovalJobReader(data string) removalJobReader {
	return func(context.Context) ([]byte, bool, error) { return []byte(data), true, nil }
}

func TestRemovalLaunchdRequiresExplicitCompleteJobEvidence(t *testing.T) {
	first, err := inspectRemovalLaunchd(t.Context(), true, ownedRemovalJobReader(ownedRemovalJob))
	if err != nil || !first.Loaded || first.PID != 45 || len(first.Configuration) != 64 {
		t.Fatal("loaded service identity missing", err)
	}
	second, err := inspectRemovalLaunchd(t.Context(), true, ownedRemovalJobReader(strings.Replace(ownedRemovalJob, "info", "debug", 1)))
	if err != nil || second.Configuration == first.Configuration {
		t.Fatal("changed loaded arguments lost their identity", err)
	}
	waiting, err := inspectRemovalLaunchd(t.Context(), true, ownedRemovalJobReader(strings.Replace(ownedRemovalJob, "<key>PID</key><integer>45</integer>", "", 1)))
	if err != nil || !waiting.Loaded || waiting.PID != 0 || waiting.Configuration != first.Configuration {
		t.Fatal("loaded nonrunning job became absence", err)
	}
	absent, err := inspectRemovalLaunchd(t.Context(), true, func(context.Context) ([]byte, bool, error) { return nil, false, nil })
	if err != nil || absent != (removalLaunchdEvidence{}) {
		t.Fatal("confirmed unloaded job did not retain absence", err)
	}
	for _, read := range []removalJobReader{
		func(context.Context) ([]byte, bool, error) {
			return nil, false, errors.New("owned private native failure")
		},
		func(context.Context) ([]byte, bool, error) { return []byte(ownedRemovalJob), false, nil },
		func(context.Context) ([]byte, bool, error) { return nil, true, nil },
	} {
		if _, err := inspectRemovalLaunchd(t.Context(), true, read); err != errRemovalProcesses {
			t.Fatal("incomplete native query became job absence", err)
		}
	}
}

func TestRemovalLaunchdRejectsForeignOrAmbiguousLoadedService(t *testing.T) {
	for _, change := range []struct{ old, new string }{
		{"<string>netbird</string>", "<string>other</string>"},
		{"<key>Program</key><string>/usr/local/bin/netbird</string>", "<key>Program</key><string>/bin/sh</string>"},
		{"<string>service</string>", "<string>up</string>"},
		{"<string>run</string>", "<string>uninstall</string>"},
		{"<integer>45</integer>", "<integer>0</integer>"},
		{"<integer>45</integer>", "<integer>1</integer>"},
		{"<integer>45</integer>", "<integer>045</integer>"},
		{"<integer>45</integer>", "<string>45</string>"},
		{"<integer>45</integer>", "<integer>2147483648</integer>"},
		{"<key>PID</key>", "<key>UserName</key><string>nobody</string><key>PID</key>"},
		{"<key>PID</key>", "<key>RootDirectory</key><string>/foreign</string><key>PID</key>"},
		{"<key>PID</key>", "<key>WorkingDirectory</key><string>/foreign</string><key>PID</key>"},
		{"<key>PID</key>", "<key>Unknown</key><true/><key>PID</key>"},
		{"<key>PID</key>", "<key>PID</key><integer>45</integer><key>PID</key>"},
		{"<key>OWNED_SETTING</key>", "<key>OWNED_SETTING</key><string>duplicate</string><key>OWNED_SETTING</key>"},
		{"owned-private-value", strings.Repeat("x", 4097)},
	} {
		data := strings.Replace(ownedRemovalJob, change.old, change.new, 1)
		if result, err := inspectRemovalLaunchd(t.Context(), true, ownedRemovalJobReader(data)); err != errRemovalProcesses || result != (removalLaunchdEvidence{}) {
			t.Fatal("foreign or ambiguous loaded job accepted", change.old, err)
		}
	}
	if _, err := inspectRemovalLaunchd(t.Context(), false, ownedRemovalJobReader(ownedRemovalJob)); err != errRemovalProcesses {
		t.Fatal("missing alias supplied loaded service ownership")
	}
}

func FuzzRemovalLaunchdOwnership(f *testing.F) {
	f.Add(ownedRemovalJob)
	f.Add(`<plist version="1.0"><dict/></plist>`)
	f.Fuzz(func(t *testing.T, data string) {
		result, err := inspectRemovalLaunchd(t.Context(), true, ownedRemovalJobReader(data))
		if err == nil && (!result.Loaded || len(result.Configuration) != 64) {
			t.Fatal("present native response yielded incomplete job identity")
		}
	})
}
