package report

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
)

const ownedNetbirdStatus = `{"netbirdIp":"100.64.0.10/16","profileName":"office","management":{"url":"https://management.example.test","connected":true},"signal":{"url":"https://signal.example.test","connected":false},"peers":{"total":4,"connected":2},"sshServer":{"enabled":true},"dnsServers":[{"servers":["192.0.2.53:53","[2001:db8::53]:53"]},{"servers":["192.0.2.53:53"]}],"futureField":{"value":1}}`

func profileTable(ids bool, profiles []nats.NetbirdProfile) []byte {
	var out bytes.Buffer
	w := tabwriter.NewWriter(&out, 0, 0, 2, ' ', 0)
	if ids {
		fmt.Fprintln(w, "ID\tNAME\tACTIVE")
	} else {
		fmt.Fprintln(w, "NAME\tACTIVE")
	}
	for _, p := range profiles {
		marker := ""
		if p.Active {
			marker = "✓"
		}
		if ids {
			fmt.Fprintf(w, "%s\t%s\t%s\n", p.ID, p.Name, marker)
		} else {
			fmt.Fprintf(w, "%s\t%s\n", p.Name, marker)
		}
	}
	w.Flush()
	return out.Bytes()
}

func TestNetbirdProfilesPreserveHandlesAndLabels(t *testing.T) {
	want := []nats.NetbirdProfile{{ID: "default", Name: "office, with spaces", Active: true}, {ID: "a1b2c3d4", Name: "duplicate label"}, {ID: "b1b2c3d4", Name: "duplicate label"}, {ID: "c1b2c3d4", Name: "München 東京 ✓"}}
	for _, ids := range []bool{false, true} {
		got, format, err := netbirdProfiles(profileTable(ids, want))
		if err != nil || len(got) != len(want) {
			t.Fatal("table parsing failed", err)
		}
		for i := range got {
			if got[i].Name != want[i].Name || got[i].Active != want[i].Active || ids && got[i].ID != want[i].ID {
				t.Fatal("display label, identity or active state changed")
			}
		}
		if ids {
			if format != "ids" || netbirdstate.Validate(got) != nil {
				t.Fatal("IDs became duplicate names")
			}
		} else if format != "names" {
			t.Fatal(format)
		}
	}
	legacy := []byte("Found 2 profiles:\r\n✓ office, with spaces\r\n✗ home 東京\r\n")
	got, format, err := netbirdProfiles(legacy)
	if err != nil || format != "legacy" || len(got) != 2 || got[0].Name != "office, with spaces" || got[1].Name != "home 東京" || !got[0].Active {
		t.Fatal("legacy profile names were split")
	}
	for _, raw := range [][]byte{[]byte("Found 0 profiles:\n"), profileTable(false, nil), profileTable(true, nil)} {
		got, _, err := netbirdProfiles(raw)
		if err != nil || len(got) != 0 {
			t.Fatal("empty profile list was fabricated")
		}
	}
}

func TestNetbirdProfilesRejectMalformedOutput(t *testing.T) {
	for _, raw := range []string{"", "Found 2 profiles:\n✓ only one\n", "Found -1 profiles:\n", "Found 01 profiles:\n✓ office\n", "Found 1 profiles:\n? office\n", "Found 1 profiles:\n✓ \n", "Found 1 profiles:\n✓ office\x00\n", "NAME  ACTIVE\nvalue mystery\n", "ID  NAME  ACTIVE\n../ x     ✓\n", strings.Repeat("x", 256<<10+1), "NAME\tACTIVE\nname\t✓\n"} {
		if _, _, err := netbirdProfiles([]byte(raw)); err == nil {
			t.Fatalf("malformed profile output accepted: %q", raw[:min(60, len(raw))])
		}
	}
	profiles := make([]nats.NetbirdProfile, 257)
	for i := range profiles {
		profiles[i] = nats.NetbirdProfile{Name: fmt.Sprint(i)}
	}
	if _, _, err := netbirdProfiles(profileTable(false, profiles)); err == nil {
		t.Fatal("unbounded profile count accepted")
	}
}

func TestNetbirdCollectionRetainsContextAndReportsObservedState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	options := []nats.NetbirdProfile{{ID: "default", Name: "office", Active: true}, {ID: "1234abcd", Name: "office"}, {ID: "abcd1234", Name: "home, lab"}}
	var calls []string
	output := func(got context.Context, exe string, args, env []string, limit int) ([]byte, error) {
		if got != ctx || exe != "/owned/netbird" || !reflect.DeepEqual(env, []string{"LC_ALL=C", "LANG=C"}) {
			t.Fatal("collector changed identity inputs or context")
		}
		command := strings.Join(args, " ")
		calls = append(calls, command)
		switch command {
		case "version":
			if limit != 4096 {
				t.Fatal(limit)
			}
			return []byte("0.70.0\n"), nil
		case "service status":
			return []byte("NetBird service status: Running\n"), nil
		case "status --json":
			if limit != 1<<20 {
				t.Fatal(limit)
			}
			return []byte(ownedNetbirdStatus), nil
		case "profile list":
			return profileTable(false, options), nil
		case "profile list --show-id":
			return profileTable(true, options), nil
		default:
			t.Fatal("unexpected command")
			return nil, nil
		}
	}
	got, err := collectNetbird(ctx, "/owned/netbird", output)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Installed || got.IP != "100.64.0.10/16" || got.PeersTotal != 4 || got.PeersConnected != 2 || !got.SSHEnabled || got.SignalConnected || !got.ManagementConnected || len(got.DNSServers) != 2 || !reflect.DeepEqual(got.ProfileDetails, options) || !reflect.DeepEqual(got.Profiles, []string{"default", "1234abcd", "abcd1234"}) {
		t.Fatal("observed NetBird state was lost")
	}
	if !reflect.DeepEqual(calls, []string{"version", "service status", "status --json", "profile list", "profile list --show-id"}) {
		t.Fatal(calls)
	}
}

func TestNetbirdCollectionStopsWithoutPublishingPartialState(t *testing.T) {
	for _, failAt := range []int{1, 2, 3, 4, 5} {
		calls := 0
		got, err := collectNetbird(context.Background(), "/owned/netbird", func(_ context.Context, _ string, args, env []string, limit int) ([]byte, error) {
			calls++
			if calls == failAt {
				return []byte("private partial output"), errors.New("private failure")
			}
			switch calls {
			case 1:
				return []byte("0.70.0"), nil
			case 2:
				return []byte("NetBird service status: Running"), nil
			case 3:
				return []byte(ownedNetbirdStatus), nil
			case 4:
				return profileTable(false, nil), nil
			}
			return nil, nil
		})
		if got != nil || !errors.Is(err, ErrNetbirdState) || calls != failAt {
			t.Fatal("partial observation escaped or a failed read was retried")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	got, err := collectNetbird(ctx, "/owned/netbird", func(_ context.Context, _ string, args, env []string, limit int) ([]byte, error) {
		calls++
		cancel()
		return []byte("0.70.0"), nil
	})
	if got != nil || err != ErrNetbirdState || calls != 1 {
		t.Fatal("canceled observation continued")
	}
	calls = 0
	got, err = collectNetbird(context.Background(), "/owned/netbird", func(_ context.Context, _ string, args, env []string, limit int) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("0.70.0"), nil
		}
		return []byte("Netbird service status: Stopped"), nil
	})
	if err != nil || calls != 2 || got.ServiceStatus != "netbird.service_stopped" || got.ManagementConnected || len(got.Profiles) != 0 {
		t.Fatal("stopped daemon was queried or given fabricated state")
	}
	for _, service := range []string{"Not running", "NetBird service status: Unknown", "NetBird service status: Running\nNetBird service status: Stopped"} {
		calls = 0
		got, err = collectNetbird(context.Background(), "/owned/netbird", func(_ context.Context, _ string, args, env []string, limit int) ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte("0.70.0"), nil
			}
			return []byte(service), nil
		})
		if got != nil || err != ErrNetbirdState {
			t.Fatal("unknown service state became a confirmed status")
		}
	}
}

func TestNetbirdExecutablePresenceDistinguishesFailure(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if present, err := netbirdPresent(missing); present || err != nil {
		t.Fatal("missing binary was not reported absent")
	}
	if _, err := netbirdPresent(dir); err == nil {
		t.Fatal("directory became an installed binary")
	}
	if err := os.WriteFile(missing, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if present, err := netbirdPresent(missing); !present || err != nil {
		t.Fatal("regular binary was not detected")
	}
}

func TestNetbirdOverviewRejectsAmbiguousOrMalformedState(t *testing.T) {
	for _, raw := range []string{"null", "[]", "{}", ownedNetbirdStatus + "{}", strings.Replace(ownedNetbirdStatus, `"connected":true`, `"connected":true,"connected":false`, 1), strings.Replace(ownedNetbirdStatus, `"connected":true`, `"connected":null`, 1), strings.Replace(ownedNetbirdStatus, `"total":4`, `"total":-1`, 1), strings.Replace(ownedNetbirdStatus, `"connected":2`, `"connected":5`, 1), strings.Replace(ownedNetbirdStatus, "100.64.0.10/16", "not-an-ip", 1), strings.Replace(ownedNetbirdStatus, "https://management.example.test", "https://user:secret@management.example.test", 1), strings.Replace(ownedNetbirdStatus, `"value":1`, `"value":`+strings.Repeat("[", 33)+"0"+strings.Repeat("]", 33), 1), string([]byte{'{', 0xff, '}'}), strings.Repeat(" ", 1<<20+1)} {
		result := &nats.Netbird{Version: "unchanged"}
		if err := netbirdOverview([]byte(raw), result); err != ErrNetbirdState || !reflect.DeepEqual(result, &nats.Netbird{Version: "unchanged"}) {
			t.Fatal("invalid state was accepted or partially applied")
		}
	}
}

func TestNetbirdFailedObservationCannotBecomeUninstalled(t *testing.T) {
	for _, failure := range []struct {
		data *nats.Netbird
		err  error
	}{{nil, nil}, {&nats.Netbird{Installed: true}, errors.New("private error")}, {&nats.Netbird{Error: "private daemon output"}, nil}} {
		report := &Report{}
		if report.netbirdObservation(failure.data, failure.err) != ErrNetbirdState || report.Netbird.Error != ErrNetbirdState.Error() {
			t.Fatal("failed inventory collection became a confirmed absent installation")
		}
	}
	report := &Report{}
	if report.netbirdObservation(&nats.Netbird{}, nil) != nil || report.Netbird.Error != "" || report.Netbird.Installed {
		t.Fatal("confirmed missing executable was rejected")
	}
}
