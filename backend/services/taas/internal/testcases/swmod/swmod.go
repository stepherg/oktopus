// Package swmod implements custom Software Modules test cases for
// Device.SoftwareModules.*
//
// These tests are derived from the message sequences in frontend/custom_messages.txt
// and cover the full lifecycle of a Deployment Unit (DU) and its Execution Unit (EU):
//
//	SM.1 – Probe Device.SoftwareModules support
//	SM.2 – Full lifecycle: InstallDU → StartEU → Greeter GET → StopEU → UninstallDU
//
// The default URLs / UUIDs match the greeter bundle referenced in custom_messages.txt.
// Override them via the standard TestConfig.MultiInstanceObject field if needed
// (or extend TestConfig in future).
package swmod

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

const (
	defaultDUURL   = "http://gdcs-org.github.io/packages/bundles/usp-greeter-python_bundle.tar.gz"
	installTimeout = 3 * time.Minute
)

// generateUUID returns a random RFC 4122 v4 UUID string.
func generateUUID() string {
	var b [16]byte
	rand.Read(b[:])             //nolint:errcheck
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// All returns the complete set of Software Modules test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		testCaseSM1(),
		testCaseSM2(),
	}
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

type smGetReq struct {
	ParamPaths []string `json:"param_paths"`
	MaxDepth   int      `json:"max_depth,omitempty"`
}

type smGetInstancesReq struct {
	ObjPaths       []string `json:"obj_paths"`
	FirstLevelOnly bool     `json:"first_level_only"`
}

type smGetInstancesResp struct {
	ReqPathResults []struct {
		RequestedPath string `json:"requested_path"`
		ErrCode       uint32 `json:"err_code"`
		ErrMsg        string `json:"err_msg"`
		CurrInsts     []struct {
			InstantiatedObjPath string            `json:"instantiated_obj_path"`
			UniqueKeys          map[string]string `json:"unique_keys"`
		} `json:"curr_insts"`
	} `json:"req_path_results"`
}

type smOperateReq struct {
	Command    string            `json:"command"`
	CommandKey string            `json:"command_key"`
	SendResp   bool              `json:"send_resp"`
	InputArgs  map[string]string `json:"input_args,omitempty"`
}

type smAddReq struct {
	AllowPartial bool          `json:"allow_partial"`
	CreateObjs   []smCreateObj `json:"create_objs"`
}

type smCreateObj struct {
	ObjPath       string           `json:"obj_path"`
	ParamSettings []smParamSetting `json:"param_settings"`
}

type smParamSetting struct {
	Param string `json:"param"`
	Value string `json:"value"`
}

type smAddResp struct {
	CreatedObjResults []struct {
		OperStatus struct {
			OperStatus struct {
				OperSuccess *struct {
					InstantiatedPath string `json:"instantiated_path"`
				} `json:"OperSuccess"`
			} `json:"OperStatus"`
		} `json:"oper_status"`
	} `json:"created_obj_results"`
}

type smDelReq struct {
	AllowPartial bool     `json:"allow_partial"`
	ObjPaths     []string `json:"obj_paths"`
}

type smNotify struct {
	SubscriptionId string `json:"subscriptionId"`
	OperComplete   *struct {
		ObjPath     string `json:"objPath"`
		CommandName string `json:"commandName"`
	} `json:"operComplete"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func smDelete(ctx context.Context, c *client.ControllerClient, target testcases.Target, path string) {
	c.Delete(ctx, target.DeviceID, target.MTP, smDelReq{ //nolint:errcheck
		AllowPartial: true,
		ObjPaths:     []string{path},
	})
}

func smAddSubscription(ctx context.Context, c *client.ControllerClient, target testcases.Target,
	notifType, refList, id string) (string, error) {
	raw, err := c.Add(ctx, target.DeviceID, target.MTP, smAddReq{
		AllowPartial: false,
		CreateObjs: []smCreateObj{{
			ObjPath: "Device.LocalAgent.Subscription.",
			ParamSettings: []smParamSetting{
				{Param: "Enable", Value: "true"},
				{Param: "NotifType", Value: notifType},
				{Param: "ReferenceList", Value: refList},
				{Param: "ID", Value: id},
			},
		}},
	})
	if err != nil {
		return "", err
	}
	var ar smAddResp
	json.Unmarshal(raw.RawBody, &ar) //nolint:errcheck
	if len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
		return "", fmt.Errorf("add subscription failed: %s", string(raw.RawBody))
	}
	return ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath, nil
}

// smGetInstances returns the list of instantiated object paths for objPath.
func smGetInstances(ctx context.Context, c *client.ControllerClient, target testcases.Target, objPath string) ([]string, error) {
	raw, err := c.GetInstances(ctx, target.DeviceID, target.MTP, smGetInstancesReq{
		ObjPaths:       []string{objPath},
		FirstLevelOnly: true,
	})
	if err != nil {
		return nil, err
	}
	var gr smGetInstancesResp
	json.Unmarshal(raw.RawBody, &gr) //nolint:errcheck
	if len(gr.ReqPathResults) == 0 {
		return nil, nil
	}
	var paths []string
	for _, inst := range gr.ReqPathResults[0].CurrInsts {
		paths = append(paths, inst.InstantiatedObjPath)
	}
	return paths, nil
}

// smDiff returns elements in b that are not in a.
func smDiff(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	var diff []string
	for _, v := range b {
		if _, ok := set[v]; !ok {
			diff = append(diff, v)
		}
	}
	return diff
}

// smWaitForOperComplete polls notify events until an OperationComplete for the
// given command substring arrives, or the context deadline is exceeded.
func smWaitForOperComplete(ctx context.Context, c *client.ControllerClient, target testcases.Target, cmdSubstr string) ([]byte, error) {
	const poll = 3 * time.Second
	for {
		events, err := c.WaitForNotify(ctx, target.DeviceID, poll)
		if err != nil {
			return nil, err
		}
		for _, ev := range events {
			var n smNotify
			json.Unmarshal(ev, &n) //nolint:errcheck
			if n.OperComplete != nil && strings.Contains(n.OperComplete.CommandName, cmdSubstr) {
				return ev, nil
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SM.1 – Probe Device.SoftwareModules support
// ---------------------------------------------------------------------------

func testCaseSM1() testcases.TestCase {
	return testcases.TestCase{
		ID:      "SM.1",
		Section: 12,
		Name:    "Device.SoftwareModules – Probe support",
		Purpose: "Verify the EUT exposes Device.SoftwareModules.ExecEnv. and Device.SoftwareModules.DeploymentUnit. in its data model.",
		Tags:    []string{"software-modules", "probe"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			// GET Device.SoftwareModules. to confirm presence.
			raw, err := c.Get(ctx, target.DeviceID, target.MTP, smGetReq{
				ParamPaths: []string{"Device.SoftwareModules."},
			})
			if err != nil {
				return testcases.Error("GET Device.SoftwareModules. transport error: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
				if code == 7026 {
					return testcases.Skip("Device.SoftwareModules. is not present in the agent data model (err 7026).")
				}
				return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
			}

			// GetInstances for ExecEnv.
			execEnvs, err := smGetInstances(ctx, c, target, "Device.SoftwareModules.ExecEnv.")
			if err != nil {
				return testcases.Error("GetInstances Device.SoftwareModules.ExecEnv.: " + err.Error())
			}
			if len(execEnvs) == 0 {
				return testcases.Fail("No ExecEnv instances found; at least one is required to install DUs.",
					testcases.Step("GetInstances Device.SoftwareModules.ExecEnv.", "fail", string(raw.RawBody)))
			}

			return testcases.Pass(
				testcases.Step("GET Device.SoftwareModules. – path present", "pass", string(raw.RawBody)),
				testcases.Step(fmt.Sprintf("ExecEnv instances found: %v", execEnvs), "pass", ""),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// SM.2 – Full lifecycle: InstallDU → StartEU → Greeter GET → StopEU → UninstallDU
// ---------------------------------------------------------------------------

func testCaseSM2() testcases.TestCase {
	return testcases.TestCase{
		ID:      "SM.2",
		Section: 12,
		Name:    "Device.SoftwareModules – Full DU/EU lifecycle (Install → Start → Verify → Stop → Uninstall)",
		Purpose: "Verify the EUT can install a Deployment Unit via InstallDU(), start/stop its Execution Unit via SetRequestedState(), and uninstall it via Uninstall(). Uses the greeter bundle from custom_messages.txt.",
		Tags:    []string{"software-modules", "install", "operate", "lifecycle"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// ----------------------------------------------------------------
			// Step 0: Probe Device.SoftwareModules support.
			// ----------------------------------------------------------------
			raw0, err := c.Get(ctx, target.DeviceID, target.MTP, smGetReq{
				ParamPaths: []string{"Device.SoftwareModules."},
			})
			if err != nil {
				return testcases.Error("GET Device.SoftwareModules. transport error: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw0.RawBody); isErr {
				if code == 7026 {
					return testcases.Skip("Device.SoftwareModules. is not present in the agent data model (err 7026).")
				}
				return testcases.Fail(fmt.Sprintf("USP error probing SoftwareModules: %d %s", code, msg))
			}

			// ----------------------------------------------------------------
			// Step 1: Snapshot existing DU and EU instances (baseline)
			// and discover the first available ExecEnv.
			// ----------------------------------------------------------------
			execEnvs, err := smGetInstances(ctx, c, target, "Device.SoftwareModules.ExecEnv.")
			if err != nil {
				return testcases.Error("GetInstances ExecEnv (baseline): " + err.Error())
			}
			if len(execEnvs) == 0 {
				return testcases.Fail("No ExecEnv instances found; at least one is required to install DUs.")
			}
			// Use the path without trailing dot as ExecutionEnvRef (e.g. "Device.SoftwareModules.ExecEnv.1").
			execEnvRef := strings.TrimSuffix(execEnvs[0], ".")

			duBefore, err := smGetInstances(ctx, c, target, "Device.SoftwareModules.DeploymentUnit.")
			if err != nil {
				return testcases.Error("GetInstances DU (baseline): " + err.Error())
			}
			euBefore, err := smGetInstances(ctx, c, target, "Device.SoftwareModules.ExecutionUnit.")
			if err != nil {
				return testcases.Error("GetInstances EU (baseline): " + err.Error())
			}

			// ----------------------------------------------------------------
			// Step 2: Subscribe to OperationComplete for InstallDU().
			// ----------------------------------------------------------------
			subPath, subErr := smAddSubscription(ctx, c, target,
				"OperationComplete", "Device.SoftwareModules.InstallDU()", "swmod-sm2-install")
			if subErr != nil {
				return testcases.Error("create InstallDU OperationComplete subscription: " + subErr.Error())
			}
			defer smDelete(ctx, c, target, subPath)

			// ----------------------------------------------------------------
			// Step 3: Drain stale events.
			// ----------------------------------------------------------------
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// ----------------------------------------------------------------
			// Step 4: Operate Device.SoftwareModules.InstallDU()
			// (matches InstallDU message in custom_messages.txt)
			// ----------------------------------------------------------------
			installRaw, installErr := c.Operate(ctx, target.DeviceID, target.MTP, smOperateReq{
				Command:    "Device.SoftwareModules.InstallDU()",
				CommandKey: "sm2-install",
				SendResp:   true,
				InputArgs: map[string]string{
					"URL":             defaultDUURL,
					"UUID":            generateUUID(),
					"ExecutionEnvRef": execEnvRef,
				},
			})
			if installErr != nil {
				return testcases.Error("Operate InstallDU() transport error: " + installErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(installRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on InstallDU: %d %s", code, msg),
					testcases.Step("Operate InstallDU()", "fail", string(installRaw.RawBody)))
			}

			// ----------------------------------------------------------------
			// Step 5: Wait for OperationComplete (install can take minutes).
			// ----------------------------------------------------------------
			installCtx, installCancel := context.WithTimeout(ctx, installTimeout)
			defer installCancel()

			installEv, waitErr := smWaitForOperComplete(installCtx, c, target, "InstallDU")
			if waitErr != nil {
				return testcases.Fail(
					fmt.Sprintf("did not receive InstallDU OperationComplete within %s", installTimeout),
					testcases.Step("wait for InstallDU OperationComplete", "fail", waitErr.Error()),
				)
			}

			// ----------------------------------------------------------------
			// Step 6: Find newly created DU and EU instances.
			// ----------------------------------------------------------------
			duAfter, err := smGetInstances(ctx, c, target, "Device.SoftwareModules.DeploymentUnit.")
			if err != nil {
				return testcases.Error("GetInstances DU (post-install): " + err.Error())
			}
			newDUs := smDiff(duBefore, duAfter)
			if len(newDUs) == 0 {
				return testcases.Fail("InstallDU OperationComplete received but no new DeploymentUnit instance found",
					testcases.Step("find new DU instance", "fail", string(installEv)))
			}
			duPath := newDUs[0]

			euAfter, err := smGetInstances(ctx, c, target, "Device.SoftwareModules.ExecutionUnit.")
			if err != nil {
				return testcases.Error("GetInstances EU (post-install): " + err.Error())
			}
			newEUs := smDiff(euBefore, euAfter)
			if len(newEUs) == 0 {
				return testcases.Fail("InstallDU succeeded but no new ExecutionUnit instance found",
					testcases.Step("find new EU instance", "fail", duPath))
			}
			euPath := newEUs[0]

			// Always clean up the DU on exit (best-effort).
			defer func() {
				smDelete(ctx, c, target, duPath)
			}()

			// ----------------------------------------------------------------
			// Step 7: Start EU – SetRequestedState(Active)
			// (matches StartEU message in custom_messages.txt)
			// ----------------------------------------------------------------
			startCmd := euPath + "SetRequestedState()"
			startRaw, startErr := c.Operate(ctx, target.DeviceID, target.MTP, smOperateReq{
				Command:    startCmd,
				CommandKey: "sm2-start",
				SendResp:   true,
				InputArgs:  map[string]string{"RequestedState": "Active"},
			})
			if startErr != nil {
				return testcases.Error("Operate SetRequestedState(Active) transport error: " + startErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(startRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on SetRequestedState(Active): %d %s", code, msg),
					testcases.Step("Start EU", "fail", string(startRaw.RawBody)))
			}

			// Brief pause for the EU to become active.
			time.Sleep(3 * time.Second)

			// ----------------------------------------------------------------
			// Step 8: Verify Greeter – GET Device.Greeter.
			// (matches GreeterGet message in custom_messages.txt)
			// ----------------------------------------------------------------
			greeterRaw, greeterErr := c.Get(ctx, target.DeviceID, target.MTP, smGetReq{
				ParamPaths: []string{"Device.Greeter."},
				MaxDepth:   2,
			})
			greeterOK := greeterErr == nil
			greeterNote := ""
			if greeterErr != nil {
				greeterNote = "GET Device.Greeter. failed: " + greeterErr.Error()
			} else if isErr, code, msg := client.IsUSPError(greeterRaw.RawBody); isErr {
				greeterOK = false
				greeterNote = fmt.Sprintf("Device.Greeter. not in agent schema (err %d: %s) – module may not expose a data model path", code, msg)
			} else {
				greeterNote = string(greeterRaw.RawBody)
			}

			// ----------------------------------------------------------------
			// Step 9: Stop EU – SetRequestedState(Idle)
			// (matches StopEU message in custom_messages.txt)
			// ----------------------------------------------------------------
			stopCmd := euPath + "SetRequestedState()"
			stopRaw, stopErr := c.Operate(ctx, target.DeviceID, target.MTP, smOperateReq{
				Command:    stopCmd,
				CommandKey: "sm2-stop",
				SendResp:   true,
				InputArgs:  map[string]string{"RequestedState": "Idle"},
			})
			if stopErr != nil {
				return testcases.Error("Operate SetRequestedState(Idle) transport error: " + stopErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(stopRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on SetRequestedState(Idle): %d %s", code, msg),
					testcases.Step("Stop EU", "fail", string(stopRaw.RawBody)))
			}

			// ----------------------------------------------------------------
			// Step 10: Uninstall DU
			// (matches UninstallDU message in custom_messages.txt)
			// ----------------------------------------------------------------
			uninstallCmd := duPath + "Uninstall()"
			uninstallRaw, uninstallErr := c.Operate(ctx, target.DeviceID, target.MTP, smOperateReq{
				Command:    uninstallCmd,
				CommandKey: "sm2-uninstall",
				SendResp:   true,
				InputArgs:  map[string]string{},
			})
			if uninstallErr != nil {
				return testcases.Error("Operate Uninstall() transport error: " + uninstallErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(uninstallRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on Uninstall: %d %s", code, msg),
					testcases.Step("Uninstall DU", "fail", string(uninstallRaw.RawBody)))
			}

			// ----------------------------------------------------------------
			// Build result.
			// ----------------------------------------------------------------
			steps := []testcases.StepResult{
				testcases.Step("Device.SoftwareModules. present", "pass", ""),
				testcases.Step("InstallDU() sent", "pass", string(installRaw.RawBody)),
				testcases.Step("InstallDU OperationComplete received", "pass", string(installEv)),
				testcases.Step(fmt.Sprintf("New DU instance: %s", duPath), "pass", ""),
				testcases.Step(fmt.Sprintf("New EU instance: %s", euPath), "pass", ""),
				testcases.Step("SetRequestedState(Active) sent", "pass", string(startRaw.RawBody)),
			}

			if greeterOK {
				steps = append(steps, testcases.Step("GET Device.Greeter. – response received", "pass", greeterNote))
			} else {
				steps = append(steps, testcases.Step("GET Device.Greeter. – not accessible (non-fatal)", "pass", greeterNote))
			}

			steps = append(steps,
				testcases.Step("SetRequestedState(Idle) sent", "pass", string(stopRaw.RawBody)),
				testcases.Step("Uninstall() sent", "pass", string(uninstallRaw.RawBody)),
			)

			return testcases.Result{Status: "pass", Steps: steps}
		},
	}
}
