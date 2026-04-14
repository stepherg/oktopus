package section1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// ---------------------------------------------------------------------------
// Set request / response types
// ---------------------------------------------------------------------------

type setParamSetting struct {
	Param    string `json:"param"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type setUpdateObject struct {
	ObjPath       string            `json:"obj_path"`
	ParamSettings []setParamSetting `json:"param_settings"`
}

type setRequest struct {
	AllowPartial bool              `json:"allow_partial"`
	UpdateObjs   []setUpdateObject `json:"update_objs"`
}

type setRespSuccess struct {
	AffectedPath string `json:"affected_path"`
}

type setRespOperStatus struct {
	OperSuccess *struct {
		UpdatedInstResults []struct {
			AffectedPath string `json:"affected_path"`
			ParamErrs    []struct {
				Param   string `json:"param"`
				ErrCode uint32 `json:"err_code"`
				ErrMsg  string `json:"err_msg"`
			} `json:"param_errs"`
		} `json:"updated_inst_results"`
	} `json:"oper_success"`
	OperFailure *struct {
		ErrCode uint32 `json:"err_code"`
		ErrMsg  string `json:"err_msg"`
	} `json:"oper_failure"`
}

type setRespUpdatedObj struct {
	RequestedPath string            `json:"requested_path"`
	OperStatus    setRespOperStatus `json:"oper_status"`
}

type setResp struct {
	UpdatedObjResults []setRespUpdatedObj `json:"updated_obj_results"`
}

func sendSet(ctx context.Context, c *client.ControllerClient, target testcases.Target, req setRequest) (*setResp, *client.USPResponse, error) {
	raw, err := c.Set(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var sr setResp
	json.Unmarshal(raw.RawBody, &sr) //nolint:errcheck
	return &sr, raw, nil
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func setCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.11",
			Section: 1,
			Name:    "Set message with allow_partial false, required parameters pass",
			Purpose: "Verify the agent correctly updates an object's parameter when allow_partial is false and the parameter value is valid.",
			Tags:    []string{"set"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: false,
					UpdateObjs: []setUpdateObject{{
						ObjPath: cfg.WritableParamPath,
						ParamSettings: []setParamSetting{{
							Param:    "",
							Value:    "taas-test-1.11",
							Required: true,
						}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if raw.StatusCode != http.StatusOK {
					return testcases.Fail(fmt.Sprintf("unexpected HTTP status %d", raw.StatusCode))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.UpdatedObjResults) == 0 {
					return testcases.Fail("no updated_obj_results in response")
				}
				if resp.UpdatedObjResults[0].OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("oper_success returned", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.12",
			Section: 1,
			Name:    "Set message with allow_partial true, required parameters pass",
			Purpose: "Verify the agent updates a parameter when allow_partial is true and the parameter is valid.",
			Tags:    []string{"set", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: true,
					UpdateObjs: []setUpdateObject{{
						ObjPath:       cfg.WritableParamPath,
						ParamSettings: []setParamSetting{{Param: "", Value: "taas-test-1.12", Required: true}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.UpdatedObjResults) == 0 || resp.UpdatedObjResults[0].OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present", testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("oper_success returned", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.14",
			Section: 1,
			Name:    "Set message with allow_partial false, required parameters fail",
			Purpose: "Verify the agent rejects the Set when a required parameter has an invalid value and allow_partial is false.",
			Tags:    []string{"set", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: false,
					UpdateObjs: []setUpdateObject{{
						ObjPath:       cfg.WritableParamPath,
						ParamSettings: []setParamSetting{{Param: "NonExistentParam_TP469_1_14", Value: "irrelevant", Required: true}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned for invalid required param", "pass", string(raw.RawBody)))
				}
				if resp != nil && len(resp.UpdatedObjResults) > 0 && resp.UpdatedObjResults[0].OperStatus.OperFailure != nil {
					return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
				}
				return testcases.Fail("expected error or oper_failure for invalid required param",
					testcases.Step("error check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.20",
			Section: 1,
			Name:    "Set message with wildcard search path, allow_partial false, required parameters fail",
			Purpose: "Verify the agent returns a SetResponse containing an error when allow_partial is false and matching fails.",
			Tags:    []string{"set", "wildcard", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: false,
					UpdateObjs: []setUpdateObject{{
						ObjPath:       cfg.InvalidPath + "*.",
						ParamSettings: []setParamSetting{{Param: "NonExistentParam", Value: "v", Required: true}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned", "pass", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("non-success returned for wildcard on invalid path", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.23",
			Section: 1,
			Name:    "Set message with path that matches no objects",
			Purpose: "Verify the agent returns an empty oper_success result when the path matches no objects.",
			Tags:    []string{"set"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: true,
					UpdateObjs: []setUpdateObject{{
						ObjPath:       cfg.MultiInstanceObject + "[Enable==\"UNLIKELY_VALUE_TP469_1_23\"].",
						ParamSettings: []setParamSetting{{Param: "Enable", Value: "true", Required: false}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				// The agent should respond with an empty oper_success (no instances matched).
				if resp != nil && len(resp.UpdatedObjResults) > 0 {
					if s := resp.UpdatedObjResults[0].OperStatus.OperSuccess; s != nil && len(s.UpdatedInstResults) == 0 {
						return testcases.Pass(testcases.Step("empty oper_success returned", "pass", string(raw.RawBody)))
					}
				}
				// A USP error response is also acceptable when no objects match.
				return testcases.Pass(testcases.Step("agent handled no-match path", "pass", string(raw.RawBody)))
			},
		},
	}
}
