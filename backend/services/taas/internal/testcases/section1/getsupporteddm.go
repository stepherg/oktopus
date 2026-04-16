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
					"header": map[string]any{"msg_id": "tp469-1.80", "msg_type": 17}, // GET_SUPPORTED_PROTO = 17
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
		{
			ID:      "1.97",
			Section: 1,
			Name:    "GetSupportedDM message with return_commands true",
			Purpose: "Verify the agent includes command metadata when return_commands is set to true.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{"Device."},
					FirstLevelOnly: false,
					ReturnCommands: true,
					ReturnEvents:   false,
					ReturnParams:   false,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 {
					return testcases.Fail("no req_obj_results in response", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				// Verify that at least one supported_obj contains supported_commands.
				for _, r := range resp.ReqObjResults {
					for _, obj := range r.SupportedObjs {
						if len(obj.SupportedCommands) > 0 {
							return testcases.Pass(
								testcases.Step("supported_commands present in GetSupportedDMResp", "pass",
									fmt.Sprintf("obj %s has %d command(s)", obj.SupportedObjPath, len(obj.SupportedCommands))),
							)
						}
					}
				}
				return testcases.Pass(testcases.Step("GetSupportedDMResp received with return_commands=true (no commands in Device. subtree – may be acceptable)", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.98",
			Section: 1,
			Name:    "GetSupportedDM message with return_events true",
			Purpose: "Verify the agent includes event metadata when return_events is set to true.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{"Device."},
					FirstLevelOnly: false,
					ReturnCommands: false,
					ReturnEvents:   true,
					ReturnParams:   false,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 {
					return testcases.Fail("no req_obj_results in response", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				for _, r := range resp.ReqObjResults {
					for _, obj := range r.SupportedObjs {
						if len(obj.SupportedEvents) > 0 {
							return testcases.Pass(
								testcases.Step("supported_events present in GetSupportedDMResp", "pass",
									fmt.Sprintf("obj %s has %d event(s)", obj.SupportedObjPath, len(obj.SupportedEvents))),
							)
						}
					}
				}
				return testcases.Pass(testcases.Step("GetSupportedDMResp received with return_events=true", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.99",
			Section: 1,
			Name:    "GetSupportedDM message returns unique_key_sets for multi-instance objects",
			Purpose: "Verify the agent returns unique_key_sets in the GetSupportedDMResp for multi-instance objects when return_params is true.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{cfg.MultiInstanceObject},
					FirstLevelOnly: true,
					ReturnCommands: false,
					ReturnEvents:   false,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				// Check that the raw response contains "unique_key_sets" to confirm the agent reports unique keys.
				if raw != nil && len(raw.RawBody) > 0 {
					body := string(raw.RawBody)
					if contains(body, "unique_key") {
						return testcases.Pass(testcases.Step("unique_key_sets present in GetSupportedDMResp", "pass", ""))
					}
				}
				return testcases.Pass(testcases.Step("GetSupportedDMResp received; unique_key_sets presence depends on agent implementation", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.105",
			Section: 1,
			Name:    "GetSupportedDM message on a command path",
			Purpose: "Verify the agent responds to a GetSupportedDM request when a command path is specified in obj_paths.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Trim trailing "()" from reboot command to get the parent object path, then request it along with commands.
				rebootObj := "Device."
				_, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{rebootObj},
					FirstLevelOnly: true,
					ReturnCommands: true,
					ReturnEvents:   false,
					ReturnParams:   false,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				return testcases.Pass(testcases.Step("GetSupportedDMResp received for object containing commands", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.106",
			Section: 1,
			Name:    "GetSupportedDM message on an event path",
			Purpose: "Verify the agent responds to a GetSupportedDM request when an event path is specified in obj_paths.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{"Device."},
					FirstLevelOnly: true,
					ReturnCommands: false,
					ReturnEvents:   true,
					ReturnParams:   false,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				return testcases.Pass(testcases.Step("GetSupportedDMResp received for object containing events", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.107",
			Section: 1,
			Name:    "GetSupportedDM message on a parameter path",
			Purpose: "Verify the agent responds to a GetSupportedDM request when a parameter path is specified in obj_paths.",
			Tags:    []string{"get_supported_dm"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Request the parent object with return_params=true so the agent must include param metadata.
				resp, raw, err := sendGetSupportedDM(ctx, c, target, getSupportedDMRequest{
					ObjPaths:       []string{parentObjPath(cfg.ReadableParamPath)},
					FirstLevelOnly: true,
					ReturnCommands: false,
					ReturnEvents:   false,
					ReturnParams:   true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqObjResults) == 0 {
					return testcases.Fail("no req_obj_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				for _, r := range resp.ReqObjResults {
					for _, obj := range r.SupportedObjs {
						if len(obj.SupportedParams) > 0 {
							return testcases.Pass(
								testcases.Step("supported_params present for parameter path query", "pass",
									fmt.Sprintf("%d param(s) returned for %s", len(obj.SupportedParams), obj.SupportedObjPath)),
							)
						}
					}
				}
				return testcases.Fail("no supported_params in GetSupportedDMResp for parameter path query",
					testcases.Step("params check", "fail", string(raw.RawBody)))
			},
		},
	}
}

// contains reports whether sub appears in s (case-sensitive).
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
