//go:build linux || darwin

package runtime

import (
	"strings"
	"testing"
)

func TestCommandSessionIdentitySelection(t *testing.T) {
	for _, tc := range []struct {
		platform, output, want string
		fail                   bool
	}{
		{"linux", "alice seat0 2026-09-13\n", "alice", false},
		{"linux", "alice tty2 2026-09-13 (:0)\n", "alice", false},
		{"linux", "gdm seat0 2026-09-13\n", "", false},
		{"linux", "sddm :0 2026-09-13\n", "", false},
		{"linux", "alice pts/1 2026-09-13 (remote)\n", "", false},
		{"linux", "alice seat0 2026-09-13\nalice :0 2026-09-13\n", "alice", false},
		{"linux", "alice seat0 2026-09-13\nbob :0 2026-09-13\n", "", true},
		{"darwin", "alice console Sep 13 09:00\n", "alice", false},
		{"darwin", "alice ttys001 Sep 13 09:00\n", "", false},
		{"darwin", "alice console Sep 13 09:00\nbob console Sep 13 09:00\n", "", true},
		{"darwin", "", "", false},
	} {
		got, err := sessionUsername(tc.output, tc.platform)
		if (err != nil) != tc.fail || got != tc.want {
			t.Fatalf("identity selection mismatch for %s", tc.platform)
		}
	}
	output := &sessionOutput{}
	for i := 0; i < 8; i++ {
		output.Write([]byte(strings.Repeat("x", 16384)))
	}
	if !output.overflow || output.text.Len() > 64<<10 {
		t.Fatal("session discovery output is unbounded")
	}
}
