package netbirdinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// This binds loaded job ownership, not transient launchd counters or an on-disk
// plist. Absence requires a successful enumeration of the explicit system domain.
type removalLaunchdEvidence struct {
	Loaded        bool
	PID           uint32
	Configuration string
}

type removalJobReader func(context.Context) ([]byte, bool, error)

func inspectRemovalLaunchd(ctx context.Context, cliPresent bool, read removalJobReader) (removalLaunchdEvidence, error) {
	if ctx == nil || ctx.Err() != nil || read == nil {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	data, present, err := read(ctx)
	defer clear(data)
	if err != nil || ctx.Err() != nil || !present && len(data) != 0 {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	if !present {
		return removalLaunchdEvidence{}, nil
	}
	values, err := nativePlist(bytes.NewReader(data), 64<<10)
	if err != nil {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	label, ok := plistString(values, "Label")
	if !ok || label != "netbird" {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	program, ok := plistString(values, "Program")
	if !ok || !removalJobProgram(program, cliPresent) {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	args := values["ProgramArguments"]
	if args == nil || args.name != "array" || len(args.children) < 3 || len(args.children) > 64 {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	arguments := make([]string, len(args.children))
	for i, value := range args.children {
		if value.name != "string" || len(value.text) > 4096 || strings.ContainsAny(value.text, "\x00\r\n") {
			return removalLaunchdEvidence{}, errRemovalProcesses
		}
		arguments[i] = value.text
	}
	if !removalJobProgram(arguments[0], cliPresent) || arguments[1] != "service" || arguments[2] != "run" {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	// Only these stable ownership fields are copied by the native adapter.
	for key := range values {
		switch key {
		case "Label", "Program", "ProgramArguments", "PID", "EnvironmentVariables", "UserName", "RootDirectory", "WorkingDirectory":
		default:
			return removalLaunchdEvidence{}, errRemovalProcesses
		}
	}
	settings := struct {
		Program               string
		Arguments             []string
		Environment           map[string]string
		User, Root, Directory string
	}{Program: program, Arguments: arguments, Environment: make(map[string]string), User: "root", Root: "/", Directory: "/"}
	for key, target := range map[string]*string{"UserName": &settings.User, "RootDirectory": &settings.Root, "WorkingDirectory": &settings.Directory} {
		if values[key] != nil {
			value, ok := plistString(values, key)
			if !ok || value != *target {
				return removalLaunchdEvidence{}, errRemovalProcesses
			}
		}
	}
	if values["EnvironmentVariables"] != nil {
		env, err := plistDictionary(values["EnvironmentVariables"])
		if err != nil || len(env) > 64 {
			return removalLaunchdEvidence{}, errRemovalProcesses
		}
		for key, item := range env {
			if len(key) > 256 || strings.ContainsAny(key, "=\x00\r\n") || item.name != "string" || len(item.text) > 4096 || strings.ContainsRune(item.text, 0) {
				return removalLaunchdEvidence{}, errRemovalProcesses
			}
			settings.Environment[key] = item.text
		}
	}
	var pid uint64
	if value := values["PID"]; value != nil {
		if value.name != "integer" {
			return removalLaunchdEvidence{}, errRemovalProcesses
		}
		pid, err = strconv.ParseUint(value.text, 10, 31)
		if err != nil || pid <= 1 || strconv.FormatUint(pid, 10) != value.text {
			return removalLaunchdEvidence{}, errRemovalProcesses
		}
	}
	encoded, err := json.Marshal(settings)
	if err != nil || ctx.Err() != nil {
		return removalLaunchdEvidence{}, errRemovalProcesses
	}
	hash := sha256.Sum256(append([]byte("openuem/netbird/removal-job/v1\x00"), encoded...))
	clear(encoded)
	return removalLaunchdEvidence{true, uint32(pid), hex.EncodeToString(hash[:])}, nil
}

func removalJobProgram(path string, cliPresent bool) bool {
	return path == removalCLIExecutable || cliPresent && path == "/usr/local/bin/netbird"
}
