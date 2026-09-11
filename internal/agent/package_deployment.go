package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
)

var errPackageRequest = errors.New("package request does not match this device and operation")

// Legacy package subjects remain unavailable to individually enrolled agents.
// Their broker permissions and approved command protocol are separate boundaries.
func (a *Agent) subscribePackage(operation string) error {
	if a.individual != nil || a.ctx == nil || a.ctx.Err() != nil || a.NATSConnection == nil {
		return errors.New("legacy package subscription is unavailable")
	}
	_, err := a.NATSConnection.Subscribe("agent."+operation+"package."+a.Config.UUID,
		a.packageHandler(operation, a.executePackage, a.SendDeployResult, SaveDeploymentNotACK, func() {
			if r := a.RunReport(); r != nil {
				if err := a.SendReport(r); err != nil {
					log.Printf("[ERROR]: package inventory report could not be sent: %v", err)
				}
			}
		}))
	return err
}

type packageExecutor func(string, openuem.DeployAction) (string, string, error)

func (a *Agent) packageHandler(operation string, execute packageExecutor, send func(*openuem.DeployAction) error, persist func(openuem.DeployAction) error, report func()) nats.MsgHandler {
	return func(msg *nats.Msg) {
		a.admitPackageTask(func() {
			if a.individual != nil || a.ctx == nil || a.ctx.Err() != nil || msg == nil || msg.Subject != "agent."+operation+"package."+a.Config.UUID {
				return
			}
			action, err := decodePackageRequest(msg.Data, a.Config.UUID, operation)
			if err != nil {
				log.Print("[ERROR]: invalid package request rejected")
				return
			}
			_, stderr, executionErr := execute(operation, action)
			action.When = time.Now().UTC()
			action.Failed = executionErr != nil
			action.Info = ""
			if executionErr != nil {
				action.Info = stderr
				if action.Info == "" {
					action.Info = "Package command failed; verify device state before retrying"
				}
			}
			if err := send(&action); err != nil {
				log.Print("[ERROR]: package result could not be acknowledged")
				if err := persist(action); err != nil {
					log.Print("[ERROR]: package result could not be saved for acknowledgement")
				}
			}
			if executionErr == nil && a.ctx.Err() == nil {
				report()
			}
		})
	}
}

func decodePackageRequest(data []byte, device, operation string) (openuem.DeployAction, error) {
	var action openuem.DeployAction
	if device == "" || len(data) == 0 || len(data) > 8<<10 || !utf8.Valid(data) || (operation != "install" && operation != "update" && operation != "uninstall") {
		return action, errPackageRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return action, errPackageRequest
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return action, errPackageRequest
		}
		switch key {
		case "agentid", "action", "when", "packageid", "packagename", "packageversion", "packagebranch", "packagebrewtype", "packageverified", "repository", "info", "failed":
		default:
			return action, errPackageRequest
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return action, errPackageRequest
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return action, errPackageRequest
	}
	if json.Unmarshal(data, &action) != nil || action.AgentId != device || action.Action != operation || strings.TrimSpace(action.PackageId) == "" {
		return openuem.DeployAction{}, errPackageRequest
	}
	// Result fields are produced locally and never copied from an incoming task.
	action.When, action.Info, action.Failed = time.Time{}, "", false
	return action, nil
}
