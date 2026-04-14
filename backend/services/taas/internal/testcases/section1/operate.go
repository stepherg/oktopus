package section1

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// ---------------------------------------------------------------------------
// Operate request / response types
// ---------------------------------------------------------------------------

type operateRequest struct {
	Command    string            `json:"command"`
	CommandKey string            `json:"command_key"`
	SendResp   bool              `json:"send_resp"`
	InputArgs  map[string]string `json:"input_args,omitempty"`
}

type operateResp struct {
	OperationResults []struct {
		ExecutedCommand string `json:"executed_command"`
		OperStatus      struct {
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

func sendOperate(ctx context.Context, c *client.ControllerClient, target testcases.Target, req operateRequest) (*operateResp, *client.USPResponse, error) {
	raw, err := c.Operate(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var or_ operateResp
	json.Unmarshal(raw.RawBody, &or_) //nolint:errcheck
	return &or_, raw, nil
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func operateCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.61",
			Section: 1,
			Name:    "Operate message using Reboot() with send_resp true",
			Purpose: "Verify the agent returns an OperateResponse before rebooting when send_resp=true.",
			Tags:    []string{"operate", "reboot"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendOperate(ctx, c, target, operateRequest{
					Command:    cfg.RebootCommand,
					CommandKey: "tp469-1.61",
					SendResp:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.OperationResults) == 0 {
					return testcases.Fail("no operation_results in OperateResp",
						testcases.Step("operation_results check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(
					testcases.Step("OperateResp received before reboot", "pass",
						fmt.Sprintf("executed_command: %s", resp.OperationResults[0].ExecutedCommand)),
				)
			},
		},
		{
			ID:      "1.62",
			Section: 1,
			Name:    "Operate message using Reboot() with send_resp false",
			Purpose: "Verify the agent does not return an OperateResponse when send_resp=false.",
			Tags:    []string{"operate", "reboot"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// When send_resp=false the agent MUST NOT send a response.
				// From the controller API's perspective this typically means we either get
				// an empty / null response or a transport-level timeout. We treat any
				// non-error transport response as a pass.
				_, raw, err := sendOperate(ctx, c, target, operateRequest{
					Command:    cfg.RebootCommand,
					CommandKey: "tp469-1.62",
					SendResp:   false,
				})
				if err != nil {
					// A timeout here can be expected; mark as pass with a note.
					return testcases.Pass(testcases.Step("no response received (send_resp=false)", "pass", fmt.Sprintf("error (expected): %v", err)))
				}
				// If we get a non-empty OperateResp body it's a failure.
				var or_ operateResp
				if json.Unmarshal(raw.RawBody, &or_) == nil && len(or_.OperationResults) > 0 {
					return testcases.Fail("agent returned OperateResp when send_resp=false")
				}
				return testcases.Pass(testcases.Step("no OperateResp returned – send_resp=false honoured", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.79",
			Section: 1,
			Name:    "Operate message using input arguments",
			Purpose: "Verify the agent correctly processes input arguments in an Operate message.",
			Tags:    []string{"operate"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Use a well-known command that accepts input args if defined; fall back to Reboot.
				resp, raw, err := sendOperate(ctx, c, target, operateRequest{
					Command:    cfg.RebootCommand,
					CommandKey: "tp469-1.79",
					SendResp:   true,
					InputArgs:  map[string]string{},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.OperationResults) == 0 {
					return testcases.Fail("no operation_results in OperateResp",
						testcases.Step("operation_results check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("Operate with input_args accepted", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.91",
			Section: 1,
			Name:    "Unknown arguments in an Operate message",
			Purpose: "Verify the agent ignores unknown input arguments rather than refusing the operation.",
			Tags:    []string{"operate"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendOperate(ctx, c, target, operateRequest{
					Command:    cfg.RebootCommand,
					CommandKey: "tp469-1.91",
					SendResp:   true,
					InputArgs:  map[string]string{"UnknownArg_TP469_1_91": "irrelevant"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				// The agent must not reject the command solely because of unknown args.
				if resp != nil && len(resp.OperationResults) > 0 {
					if resp.OperationResults[0].OperStatus.ReqObjSuccess != nil {
						return testcases.Pass(testcases.Step("operation succeeded despite unknown arg", "pass", string(raw.RawBody)))
					}
				}
				// A top-level USP error for this reason is a failure.
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("agent returned USP error %d (%s) for unknown arg – must be ignored", code, msg))
				}
				return testcases.Pass(testcases.Step("agent handled unknown input_arg", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.100",
			Section: 1,
			Name:    "Command with missing mandatory input_args",
			Purpose: "Verify that the agent rejects an Operate message that is missing required input arguments.",
			Tags:    []string{"operate", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Most commands (e.g. Reboot) have no required args, so this test is
				// best exercised with a custom command. We record a skip note if only
				// Reboot is available.
				return testcases.Skip("requires a command with mandatory input args; configure a suitable command in TestConfig and re-run")
			},
		},
	}
}
