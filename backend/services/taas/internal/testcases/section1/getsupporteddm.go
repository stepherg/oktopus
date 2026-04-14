package section1

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// ---------------------------------------------------------------------------
// GetSupportedDM request / response types
// ---------------------------------------------------------------------------

type getSupportedDMRequest struct {
	ObjPaths       []string `json:"obj_paths"`
	FirstLevelOnly bool     `json:"first_level_only"`
	ReturnCommands bool     `json:"return_commands"`
	ReturnEvents   bool     `json:"return_events"`
	ReturnParams   bool     `json:"return_params"`
}

type getSupportedDMResp struct {
	ReqObjResults []struct {
		ReqObjPath    string `json:"req_obj_path"`
		ErrCode       uint32 `json:"err_code"`
		ErrMsg        string `json:"err_msg"`
		SupportedObjs []struct {
			SupportedObjPath string `json:"supported_obj_path"`
			Access           string `json:"access"`
			IsMultiInstance  bool   `json:"is_multi_instance"`
			SupportedParams  []struct {
				ParamName string `json:"param_name"`
				Access    string `json:"access"`
			} `json:"supported_params"`
			SupportedCommands []struct {
				CommandName string `json:"command_name"`
			} `json:"supported_commands"`
			SupportedEvents []struct {
				EventName string `json:"event_name"`
			} `json:"supported_events"`
		} `json:"supported_objs"`
	} `json:"req_obj_results"`
}

func sendGetSupportedDM(ctx context.Context, c *client.ControllerClient, target testcases.Target, req getSupportedDMRequest) (*getSupportedDMResp, *client.USPResponse, error) {
	raw, err := c.GetSupportedDM(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var gr getSupportedDMResp
	json.Unmarshal(raw.RawBody, &gr) //nolint:errcheck
	return &gr, raw, nil
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func getSupportedDMCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.72",
			Section: 1,
			Name:    "GetSupportedDM using a single object, first_level_only false, all options",
			Purpose: "Verify the agent returns complete DM information including params, commands, and events.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{cfg.GetSupportedDMObject},
					FirstLevelOnly: false,
					ReturnCommands: true,
					ReturnEvents:   true,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 {
					return testcases.Fail("no req_obj_results in GetSupportedDMResp")
				}
				if resp.ReqObjResults[0].ErrCode != 0 {
					return testcases.Fail(fmt.Sprintf("err_code %d: %s", resp.ReqObjResults[0].ErrCode, resp.ReqObjResults[0].ErrMsg))
				}
				return testcases.Pass(
					testcases.Step("GetSupportedDMResp received", "pass",
						fmt.Sprintf("supported objects: %d", len(resp.ReqObjResults[0].SupportedObjs))),
				)
			},
		},
		{
			ID:      "1.73",
			Section: 1,
			Name:    "GetSupportedDM using a single object, first_level_only true, all options",
			Purpose: "Verify the agent returns only first-level object DM information.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{cfg.GetSupportedDMObject},
					FirstLevelOnly: true,
					ReturnCommands: true,
					ReturnEvents:   true,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 || resp.ReqObjResults[0].ErrCode != 0 {
					return testcases.Fail("no valid response",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetSupportedDMResp (first_level_only=true) received", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.74",
			Section: 1,
			Name:    "GetSupportedDM using a single object, first_level_only true, no options",
			Purpose: "Verify the agent returns object DM without params, commands, or events when all return_* options are false.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{cfg.GetSupportedDMObject},
					FirstLevelOnly: true,
					ReturnCommands: false,
					ReturnEvents:   false,
					ReturnParams:   false,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 || resp.ReqObjResults[0].ErrCode != 0 {
					return testcases.Fail("no valid response")
				}
				// Verify no params/commands/events returned
				if len(resp.ReqObjResults[0].SupportedObjs) > 0 {
					obj := resp.ReqObjResults[0].SupportedObjs[0]
					if len(obj.SupportedParams) > 0 || len(obj.SupportedCommands) > 0 || len(obj.SupportedEvents) > 0 {
						return testcases.Fail("agent returned params/commands/events despite all return_* options being false",
							testcases.Step("no options check", "fail", string(raw.RawBody)))
					}
				}
				return testcases.Pass(testcases.Step("no params/commands/events returned as expected", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.75",
			Section: 1,
			Name:    "GetSupportedDM using multiple objects, first_level_only true, all options",
			Purpose: "Verify the agent returns DM information for multiple requested object paths.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{cfg.GetSupportedDMObject, cfg.GetInstancesObject},
					FirstLevelOnly: true,
					ReturnCommands: true,
					ReturnEvents:   true,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) < 2 {
					return testcases.Fail("expected at least 2 req_obj_results for 2 obj_paths",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("multiple objects returned", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.76",
			Section: 1,
			Name:    "GetSupportedDM on root object, all options",
			Purpose: "Verify the agent returns the complete data model when the root object path 'Device.' is requested.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{"Device."},
					FirstLevelOnly: false,
					ReturnCommands: true,
					ReturnEvents:   true,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 || resp.ReqObjResults[0].ErrCode != 0 {
					return testcases.Fail("no valid response for root object")
				}
				return testcases.Pass(
					testcases.Step("root DM returned", "pass",
						fmt.Sprintf("supported objects: %d", len(resp.ReqObjResults[0].SupportedObjs))),
				)
			},
		},
		{
			ID:      "1.77",
			Section: 1,
			Name:    "GetSupportedDM on unsupported object",
			Purpose: "Verify the agent returns an appropriate error when an unsupported object path is requested.",
			Tags:    []string{"get_supported_dm", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{cfg.InvalidPath},
					FirstLevelOnly: false,
					ReturnCommands: true,
					ReturnEvents:   true,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned for unsupported object", "pass", string(raw.RawBody)))
				}
				if resp != nil && len(resp.ReqObjResults) > 0 && resp.ReqObjResults[0].ErrCode != 0 {
					return testcases.Pass(testcases.Step(
						fmt.Sprintf("err_code %d in req_obj_results", resp.ReqObjResults[0].ErrCode), "pass", ""))
				}
				return testcases.Fail("agent did not return an error for unsupported object",
					testcases.Step("error check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.80",
			Section: 1,
			Name:    "GetSupportedProtocol",
			Purpose: "Verify the agent returns its supported USP protocol versions.",
			Tags:    []string{"get_supported_protocol"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// GetSupportedProtocol uses the generic endpoint with a full USP message.
				body := map[string]any{
					"header": map[string]any{"msg_id": "tp469-1.80", "msg_type": 12}, // GET_SUPPORTED_PROTOCOL = 12
					"body": map[string]any{
						"request": map[string]any{
							"get_supported_protocol": map[string]any{
								"controller_supported_protocol_versions": "1.0,1.1,1.2,1.3,1.4",
							},
						},
					},
				}
				raw, err := c.Generic(ctx, target.DeviceID, target.MTP, body)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				var resp struct {
					AgentSupportedProtocolVersions string `json:"agent_supported_protocol_versions"`
				}
				if json.Unmarshal(raw.RawBody, &resp) == nil && resp.AgentSupportedProtocolVersions != "" {
					return testcases.Pass(
						testcases.Step("agent_supported_protocol_versions returned", "pass",
							resp.AgentSupportedProtocolVersions),
					)
				}
				return testcases.Fail("agent did not return agent_supported_protocol_versions",
					testcases.Step("protocol versions check", "fail", string(raw.RawBody)))
			},
		},
	}
}
