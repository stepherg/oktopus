// Package section9 implements TP-469 Section 9 – Functionality Test Cases.
//
// Most tests in this section require infrastructure not available through the
// controller REST API (firmware images, a file server, alternate certificates,
// a secondary controller). Those tests are registered with Disabled:true and
// return testcases.Skip so they are visible in the test catalogue but not
// counted as failures.
//
// The following tests are fully implemented:
//   - 9.11 Use of the Timer! Event (Device.ScheduleTimer())
//
// The following tests are implemented but disabled because they reboot the
// device, which disrupts the test session:
//   - 9.10 Use of the Boot! event and BootParameters
package section9

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// All returns the complete set of Section 9 test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		testCase9_1(),
		testCase9_2(),
		testCase9_3(),
		testCase9_4(),
		testCase9_5(),
		testCase9_6(),
		testCase9_7(),
		testCase9_8(),
		testCase9_9(),
		testCase9_10(),
		testCase9_11(),
	}
}

// ---------------------------------------------------------------------------
// Shared request / response types
// ---------------------------------------------------------------------------

type s9AddReq struct {
	AllowPartial bool          `json:"allow_partial"`
	CreateObjs   []s9CreateObj `json:"create_objs"`
}

type s9CreateObj struct {
	ObjPath       string           `json:"obj_path"`
	ParamSettings []s9ParamSetting `json:"param_settings"`
}

type s9ParamSetting struct {
	Param    string `json:"param"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type s9AddResp struct {
	CreatedObjResults []struct {
		RequestedPath string `json:"requested_path"`
		OperStatus    struct {
			OperStatus struct {
				OperSuccess *struct {
					InstantiatedPath string `json:"instantiated_path"`
				} `json:"OperSuccess"`
			} `json:"OperStatus"`
		} `json:"oper_status"`
	} `json:"created_obj_results"`
}

type s9DelReq struct {
	AllowPartial bool     `json:"allow_partial"`
	ObjPaths     []string `json:"obj_paths"`
}

type s9OperateReq struct {
	Command    string            `json:"command"`
	CommandKey string            `json:"command_key"`
	SendResp   bool              `json:"send_resp"`
	InputArgs  map[string]string `json:"input_args,omitempty"`
}

type s9OperateResp struct {
	OperationResults []struct {
		ExecutedCommand string `json:"executed_command"`
		OperStatus      struct {
			ReqObjPath    string `json:"req_obj_path"`
			ReqObjSuccess *struct {
				OutputArgs map[string]string `json:"output_args"`
			} `json:"req_obj_success"`
			ReqObjFailure *struct {
				ErrCode uint32 `json:"err_code"`
				ErrMsg  string `json:"err_msg"`
			} `json:"req_obj_failure"`
		} `json:"oper_status"`
	} `json:"operation_results"`
}

// s9NotifyOperComplete is the protojson shape of an OperationComplete notify.
type s9NotifyOperComplete struct {
	SubscriptionId string `json:"subscriptionId"`
	OperComplete   *struct {
		ObjPath     string `json:"objPath"`
		CommandName string `json:"commandName"`
	} `json:"operComplete"`
	// Boot! event
	Event *struct {
		ObjPath   string            `json:"objPath"`
		EventName string            `json:"eventName"`
		Params    map[string]string `json:"params"`
	} `json:"event"`
}

// s9AddSubscription creates a Subscription object and returns its instantiated path.
func s9AddSubscription(ctx context.Context, c *client.ControllerClient, target testcases.Target,
	notifType, refList, id string) (string, *client.USPResponse, error) {
	raw, err := c.Add(ctx, target.DeviceID, target.MTP, s9AddReq{
		AllowPartial: false,
		CreateObjs: []s9CreateObj{{
			ObjPath: "Device.LocalAgent.Subscription.",
			ParamSettings: []s9ParamSetting{
				{Param: "Enable", Value: "true"},
				{Param: "NotifType", Value: notifType},
				{Param: "ReferenceList", Value: refList},
				{Param: "ID", Value: id},
			},
		}},
	})
	if err != nil {
		return "", nil, err
	}
	var ar s9AddResp
	json.Unmarshal(raw.RawBody, &ar) //nolint:errcheck
	if len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
		return "", raw, fmt.Errorf("add subscription failed: %s", string(raw.RawBody))
	}
	return ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath, raw, nil
}

// s9Delete deletes a path (best-effort; errors are silently ignored).
func s9Delete(ctx context.Context, c *client.ControllerClient, target testcases.Target, path string) {
	c.Delete(ctx, target.DeviceID, target.MTP, s9DelReq{ //nolint:errcheck
		AllowPartial: true,
		ObjPaths:     []string{path},
	})
}

// ---------------------------------------------------------------------------
// 9.1 – Use of the Timer! Event (DEPRECATED by 9.11)
// ---------------------------------------------------------------------------

func testCase9_1() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.1",
		Section:  9,
		Name:     "Use of the Timer! Event (DEPRECATED)",
		Purpose:  "Verify the ScheduleTimer() operation on the Controller object triggers a Timer! event. Deprecated; replaced by 9.11.",
		Tags:     []string{"functionality", "timer", "operate", "deprecated"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip("Test 9.1 is deprecated by test 9.11. Run 9.11 instead.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.2 – Use of Device.LocalAgent.AddCertificate()
// ---------------------------------------------------------------------------

func testCase9_2() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.2",
		Section:  9,
		Name:     "Use of Device.LocalAgent.AddCertificate()",
		Purpose:  "Verify the AddCertificate() operation on the EUT functions correctly.",
		Tags:     []string{"functionality", "certificate", "operate"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.2 requires an alternate certificate not yet seen by the EUT, " +
					"and reconfiguring the Controller to use the new certificate mid-test. " +
					"This cannot be automated via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.3 – Upgraded the Agent's Firmware – Autoactivate enabled
// ---------------------------------------------------------------------------

func testCase9_3() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.3",
		Section:  9,
		Name:     "Upgraded the Agent's Firmware – Autoactivate enabled",
		Purpose:  "Verify the EUT can download firmware and automatically activate it using the AutoActivate parameter.",
		Tags:     []string{"functionality", "firmware", "operate"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.3 requires a firmware download URL, a TransferComplete! subscription, " +
					"a Boot! subscription, and an OperationComplete subscription for Download(). " +
					"A reachable firmware file server and an inactive FirmwareImage slot are also needed. " +
					"These cannot be provided via the controller REST API alone.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.4 – Upgrading the Agent's Firmware – Using TimeWindow, Immediate
// ---------------------------------------------------------------------------

func testCase9_4() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.4",
		Section:  9,
		Name:     "Upgrading the Agent's Firmware – Using TimeWindow, Immediate",
		Purpose:  "Verify the EUT can activate a firmware image when a TimeWindow object is used with Immediately mode.",
		Tags:     []string{"functionality", "firmware", "operate", "timewindow"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.4 requires an inactive FirmwareImage slot with firmware already loaded, " +
					"a Boot! subscription, and an OperationComplete subscription for Activate(). " +
					"These prerequisites cannot be provisioned via the controller REST API alone.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.5 – Upgrading the Agent's Firmware – Using TimeWindow, AnyTime
// ---------------------------------------------------------------------------

func testCase9_5() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.5",
		Section:  9,
		Name:     "Upgrading the Agent's Firmware – Using TimeWindow, AnyTime",
		Purpose:  "Verify the EUT can activate a firmware image when a TimeWindow instance is used with the AnyTime mode.",
		Tags:     []string{"functionality", "firmware", "operate", "timewindow"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.5 requires an inactive FirmwareImage slot with firmware already loaded, " +
					"a Boot! subscription, and an OperationComplete subscription for Activate(). " +
					"These prerequisites cannot be provisioned via the controller REST API alone.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.6 – Upgrading the Agent's Firmware – Validated Firmware
// ---------------------------------------------------------------------------

func testCase9_6() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.6",
		Section:  9,
		Name:     "Upgrading the Agent's Firmware – Validated Firmware",
		Purpose:  "Verify the EUT can validate the integrity of downloaded firmware (invalid checksum → ValidationFailed).",
		Tags:     []string{"functionality", "firmware", "operate", "checksum"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.6 requires a firmware download URL, a deliberately invalid checksum, " +
					"and a TransferComplete! subscription. " +
					"A reachable firmware file server is needed. " +
					"These cannot be provided via the controller REST API alone.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.7 – Upgrading the Agent's Firmware – Download to Active Bank
// ---------------------------------------------------------------------------

func testCase9_7() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.7",
		Section:  9,
		Name:     "Upgrading the Agent's Firmware – Download to Active Bank",
		Purpose:  "Verify the EUT is capable of downloading and installing firmware to the active bank.",
		Tags:     []string{"functionality", "firmware", "operate"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.7 requires a firmware download URL targeting the active FirmwareImage slot, " +
					"a TransferComplete! subscription, and a Boot! subscription. " +
					"A reachable firmware file server is needed. " +
					"These cannot be provided via the controller REST API alone.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.8 – Upgrading the Agent's Firmware – Cancelling a request using Cancel()
// ---------------------------------------------------------------------------

func testCase9_8() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.8",
		Section:  9,
		Name:     "Upgrading the Agent's Firmware – Cancelling a request using the Cancel() command",
		Purpose:  "Verify the EUT can correctly cancel a Download()/Activate() operation using Device.LocalAgent.Request.{i}.Cancel().",
		Tags:     []string{"functionality", "firmware", "operate", "cancel"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.8 requires an inactive FirmwareImage slot with firmware, " +
					"a Boot! subscription, and the Device.LocalAgent.Request.{i}.Cancel() operation. " +
					"These prerequisites cannot be provisioned via the controller REST API alone.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.9 – Adding a New Controller – OnBoardRequest
// ---------------------------------------------------------------------------

func testCase9_9() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.9",
		Section:  9,
		Name:     "Adding a New Controller – OnBoardRequest",
		Purpose:  "Verify the EUT can manually add a new Controller and send a SendOnBoardRequest() notification to it.",
		Tags:     []string{"functionality", "controller", "onboard"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 9.9 requires a secondary Controller endpoint that can receive " +
					"an OnBoardRequest Notify and send back a NotifyResponse. " +
					"A valid role instance and certificate instance are also required. " +
					"This multi-controller scenario cannot be automated via the single controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 9.10 – Use of the Boot! event and BootParameters
// (Disabled – reboots the device which severs the test session)
// ---------------------------------------------------------------------------

func testCase9_10() testcases.TestCase {
	return testcases.TestCase{
		ID:       "9.10",
		Section:  9,
		Name:     "Use of the Boot! event and BootParameters",
		Purpose:  "Verify the EUT correctly triggers the Boot! event and includes configured BootParameters in the ParameterMap.",
		Tags:     []string{"functionality", "boot", "reboot", "subscription"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 1: Create a Boot! subscription.
			bootSubPath, bootAddRaw, err := s9AddSubscription(ctx, c, target, "Event", "Device.Boot!", "boot-9-10")
			if err != nil {
				return testcases.Error("setup: create Boot! subscription failed: " + string(bootAddRaw.RawBody))
			}
			defer s9Delete(ctx, c, target, bootSubPath)

			// Step 2: Create a BootParameter for Device.DeviceInfo.BootFirmwareImage.
			bootParamRaw, addErr := c.Add(ctx, target.DeviceID, target.MTP, s9AddReq{
				AllowPartial: false,
				CreateObjs: []s9CreateObj{{
					ObjPath: "Device.LocalAgent.Controller.1.BootParameter.",
					ParamSettings: []s9ParamSetting{
						{Param: "Enable", Value: "true"},
						{Param: "ParameterName", Value: "Device.DeviceInfo.BootFirmwareImage"},
					},
				}},
			})
			if addErr != nil {
				return testcases.Error("setup: create BootParameter failed: " + addErr.Error())
			}
			var bootParamResp s9AddResp
			json.Unmarshal(bootParamRaw.RawBody, &bootParamResp) //nolint:errcheck
			if len(bootParamResp.CreatedObjResults) > 0 && bootParamResp.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess != nil {
				bpPath := bootParamResp.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath
				defer s9Delete(ctx, c, target, bpPath)
			}
			if isErr, code, msg := client.IsUSPError(bootParamRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error creating BootParameter: %d %s", code, msg))
			}

			// Step 3: Drain stale events.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// Step 4: Send Operate Device.Reboot().
			rebootRaw, rebootErr := c.Operate(ctx, target.DeviceID, target.MTP, s9OperateReq{
				Command:    "Device.Reboot()",
				CommandKey: "tp469-9-10",
				SendResp:   true,
			})
			if rebootErr != nil {
				return testcases.Error("Operate Device.Reboot() failed: " + rebootErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(rebootRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on Reboot: %d %s", code, msg))
			}

			// Step 5: Wait for Boot! notify (device may take up to 3 minutes to reboot).
			waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			defer cancel()

			const poll = 2 * time.Second
			for {
				events, waitErr := c.WaitForNotify(waitCtx, target.DeviceID, poll)
				if waitErr != nil {
					return testcases.Fail("did not receive Boot! event within 3 minutes",
						testcases.Step("wait for Boot! notify", "fail", waitErr.Error()))
				}
				for _, ev := range events {
					var n s9NotifyOperComplete
					json.Unmarshal(ev, &n) //nolint:errcheck
					if n.Event != nil && strings.Contains(n.Event.EventName, "Boot!") {
						// Step 6: Verify the ParameterMap includes BootFirmwareImage.
						if _, ok := n.Event.Params["Device.DeviceInfo.BootFirmwareImage"]; ok {
							return testcases.Pass(
								testcases.Step("Boot! event received after reboot", "pass", string(ev)),
								testcases.Step("BootFirmwareImage present in ParameterMap", "pass", ""),
							)
						}
						return testcases.Fail("Boot! event received but Device.DeviceInfo.BootFirmwareImage missing from ParameterMap",
							testcases.Step("BootFirmwareImage in ParameterMap", "fail", string(ev)))
					}
				}
			}
		},
	}
}

// ---------------------------------------------------------------------------
// 9.11 – Use of the Timer! Event
// (Conditional Mandatory: supports Device.ScheduleTimer() command)
// ---------------------------------------------------------------------------

func testCase9_11() testcases.TestCase {
	return testcases.TestCase{
		ID:      "9.11",
		Section: 9,
		Name:    "Use of the Timer! Event",
		Purpose: "Verify the Timer! event can be configured and the EUT correctly triggers the event via Device.ScheduleTimer().",
		Tags:    []string{"functionality", "timer", "operate", "notify"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 1: Create an OperationComplete subscription for Device.ScheduleTimer().
			subPath, subAddRaw, err := s9AddSubscription(ctx, c, target,
				"OperationComplete", "Device.ScheduleTimer()", "timer-9-11")
			if err != nil {
				return testcases.Error("setup: create OperationComplete subscription failed: " + string(subAddRaw.RawBody))
			}
			defer s9Delete(ctx, c, target, subPath)

			// Step 2: Drain stale events.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// Step 3: Send Operate Device.ScheduleTimer() with DelaySeconds=60.
			operRaw, operErr := c.Operate(ctx, target.DeviceID, target.MTP, s9OperateReq{
				Command:    "Device.ScheduleTimer()",
				CommandKey: "tp469-9-11",
				SendResp:   true,
				InputArgs:  map[string]string{"DelaySeconds": "60"},
			})
			if operErr != nil {
				return testcases.Error("Operate Device.ScheduleTimer() transport error: " + operErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(operRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on ScheduleTimer Operate: %d %s", code, msg))
			}

			// Step 4: Verify the OperateResponse has ScheduleTimer() in executed_command.
			var operResp s9OperateResp
			json.Unmarshal(operRaw.RawBody, &operResp) //nolint:errcheck
			if len(operResp.OperationResults) == 0 {
				return testcases.Fail("OperateResponse has no operation_results",
					testcases.Step("executed_command check", "fail", string(operRaw.RawBody)))
			}
			execCmd := operResp.OperationResults[0].ExecutedCommand
			if !strings.Contains(execCmd, "ScheduleTimer") {
				return testcases.Fail(fmt.Sprintf("executed_command %q does not contain ScheduleTimer()", execCmd),
					testcases.Step("executed_command check", "fail", string(operRaw.RawBody)))
			}

			// Step 5: Wait for OperationComplete Notify (timer fires after ~60s; allow 90s).
			waitCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()

			for {
				events, waitErr := c.WaitForNotify(waitCtx, target.DeviceID, 500*time.Millisecond)
				if waitErr != nil {
					return testcases.Fail("no OperationComplete Notify received within 90 seconds",
						testcases.Step("wait for OperationComplete notify", "fail", waitErr.Error()))
				}
				for _, ev := range events {
					var n s9NotifyOperComplete
					json.Unmarshal(ev, &n) //nolint:errcheck
					if n.OperComplete != nil && strings.Contains(n.OperComplete.CommandName, "ScheduleTimer") {
						return testcases.Pass(
							testcases.Step("OperateResponse received with ScheduleTimer() in executed_command", "pass", execCmd),
							testcases.Step("OperationComplete Notify received with ScheduleTimer()", "pass", string(ev)),
						)
					}
				}
			}
		},
	}
}
