// Package macbundle assembles the macOS app layout used by ServiceManagement.
// Assembly is an offline build step; it does not sign, install or register it.
package macbundle

import (
	"bytes"
	"debug/macho"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/open-uem/openuem-agent/internal/nativepath"
)

const (
	BundleName           = "OpenUEM Agent.app"
	InstallationPath     = "/Applications/" + BundleName
	BundleIdentifier     = "org.openuem.agent"
	DaemonLabel          = "org.openuem.agent.daemon"
	ExecutableRelative   = "Contents/MacOS/openuem-agent"
	DaemonRelative       = "Contents/Library/LaunchDaemons/" + DaemonLabel + ".plist"
	IdentityDirectory    = "/Library/OpenUEMAgent/identity"
	MinimumSystemVersion = "13.0"
)

var (
	ErrOptions     = errors.New("provide a native agent, private output directory, release version, build number and architecture; use -help for usage")
	ErrUnsupported = errors.New("macOS bundle assembly must run on macOS")
	ErrSource      = errors.New("the agent source is unavailable, changed, or is not a matching single-architecture Mach-O executable")
	ErrOutput      = errors.New("the private output directory is unavailable or changed")
	ErrExists      = errors.New("the destination app bundle already exists; select a separate output directory")
	ErrBuild       = errors.New("the draft app bundle could not be assembled")
	ErrDurability  = errors.New("the draft app bundle was published, but output synchronization failed")
	ErrMetadata    = errors.New("the installed app metadata does not match the supported service layout")
)

type Options struct {
	Agent, Output, Version, Architecture string
	Build                                int
}

// Publication does not authorize release distribution. Final bundle signing can
// change executable bytes, so no pre-signing agent hash is exported here.
type Result struct {
	Published              bool   `json:"published"`
	Path                   string `json:"path"`
	Version                string `json:"version"`
	Build                  int    `json:"build"`
	Architecture           string `json:"architecture"`
	RequiresReleaseSigning bool   `json:"requires_release_signing"`
}

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

func validOptions(o Options) bool {
	return nativepath.Valid(o.Agent) && nativepath.Valid(o.Output) && versionPattern.MatchString(o.Version) &&
		o.Build >= 1 && o.Build <= 9999 && (o.Architecture == "amd64" || o.Architecture == "arm64")
}

func infoPlist(o Options) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>%s</string>
<key>CFBundleName</key><string>OpenUEM Agent</string>
<key>CFBundleDisplayName</key><string>OpenUEM Agent</string>
<key>CFBundleExecutable</key><string>openuem-agent</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleShortVersionString</key><string>%s</string>
<key>CFBundleVersion</key><string>%s</string>
<key>LSMinimumSystemVersion</key><string>%s</string>
<key>LSBackgroundOnly</key><true/>
</dict></plist>
`, BundleIdentifier, o.Version, strconv.Itoa(o.Build), MinimumSystemVersion))
}

func daemonPlist() []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>BundleProgram</key><string>%s</string>
<key>ProgramArguments</key><array>
<string>openuem-agent</string><string>serve</string>
<string>-identity-directory</string><string>%s</string>
</array>
<key>UserName</key><string>root</string>
<key>GroupName</key><string>wheel</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>30</integer>
<key>ExitTimeOut</key><integer>30</integer>
<key>Umask</key><integer>63</integer>
</dict></plist>
`, DaemonLabel, ExecutableRelative, IdentityDirectory))
}

// This checks the container, target and entry-point load command. It cannot
// prove what an executable does; release signing and native policy are separate.
func verifyMachO(reader io.ReaderAt, architecture string) error {
	file, err := macho.NewFile(reader)
	if err != nil {
		return ErrSource
	}
	defer file.Close()
	want := macho.CpuAmd64
	if architecture == "arm64" {
		want = macho.CpuArm64
	} else if architecture != "amd64" {
		return ErrSource
	}
	if file.Magic != macho.Magic64 || file.Cpu != want || file.Type != macho.TypeExec {
		return ErrSource
	}
	entryPoints, deploymentTargets := 0, 0
	for _, command := range file.Loads {
		raw := command.Raw()
		if len(raw) < 8 {
			return ErrSource
		}
		kind := file.ByteOrder.Uint32(raw)
		switch kind {
		case 0x80000028: // LC_MAIN
			if len(raw) != 24 {
				return ErrSource
			}
			entryPoints++
		case 5: // LC_UNIXTHREAD (used by the Go linker).
			if len(raw) < 16 {
				return ErrSource
			}
			entryPoints++
		case 0x32: // LC_BUILD_VERSION: platform, minos, sdk, ntools.
			if len(raw) < 24 || file.ByteOrder.Uint32(raw[8:]) != 1 || uint64(file.ByteOrder.Uint32(raw[20:]))*8+24 != uint64(len(raw)) {
				return ErrSource
			}
			if !compatibleMinimum(file.ByteOrder.Uint32(raw[12:])) {
				return ErrSource
			}
			deploymentTargets++
		case 0x24: // LC_VERSION_MIN_MACOSX (older native executables).
			if len(raw) != 16 || !compatibleMinimum(file.ByteOrder.Uint32(raw[8:])) {
				return ErrSource
			}
			deploymentTargets++
		case 0x25, 0x2f, 0x30: // iOS, tvOS and watchOS minimum version commands.
			return ErrSource
		}
	}
	if entryPoints == 1 && deploymentTargets == 1 {
		return nil
	}
	return ErrSource
}

// loader.h encodes X.Y.Z as xxxx.yy.zz. The app declares macOS 13.0; never
// hide a newer binary deployment target behind that older property-list value.
func compatibleMinimum(version uint32) bool { return version >= 10<<16 && version <= 13<<16 }

func layout(o Options) map[string][]byte {
	return map[string][]byte{"Contents/Info.plist": infoPlist(o), DaemonRelative: daemonPlist()}
}

// ValidateMetadata accepts exactly the builder's property lists. Version/build
// may vary by release; service identity, arguments, account and launch policy
// cannot. Reconstructing and comparing the complete document also rejects
// duplicate keys, aliases, extra fields and alternate XML interpretations.
func ValidateMetadata(info, daemon []byte) error {
	if len(info) == 0 || len(info) > 32<<10 || !bytes.Equal(daemon, daemonPlist()) {
		return ErrMetadata
	}
	var document struct {
		Strings []string `xml:"dict>string"`
	}
	if xml.Unmarshal(info, &document) != nil || len(document.Strings) != 9 {
		return ErrMetadata
	}
	version, buildText := document.Strings[6], document.Strings[7]
	build, err := strconv.Atoi(buildText)
	if err != nil || strconv.Itoa(build) != buildText || build < 1 || build > 9999 || !versionPattern.MatchString(version) || !bytes.Equal(info, infoPlist(Options{Version: version, Build: build})) {
		return ErrMetadata
	}
	return nil
}
