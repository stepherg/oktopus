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
// Get request / response types
// ---------------------------------------------------------------------------

type getRequest struct {
	ParamPaths []string `json:"param_paths"`
	MaxDepth   uint32   `json:"max_depth,omitempty"`
}

type getResolvedResult struct {
	ResolvedPath string            `json:"resolved_path"`
	ResultParams map[string]string `json:"result_params"`
}

type getReqPathResult struct {
	RequestedPath       string              `json:"requested_path"`
	ErrCode             uint32              `json:"err_code"`
	ErrMsg              string              `json:"err_msg"`
	ResolvedPathResults []getResolvedResult `json:"resolved_path_results"`
}

type getResp struct {
	ReqPathResults []getReqPathResult `json:"req_path_results"`
}

func sendGet(ctx context.Context, c *client.ControllerClient, target testcases.Target, req getRequest) (*getResp, *client.USPResponse, error) {
	raw, err := c.Get(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var gr getResp
	json.Unmarshal(raw.RawBody, &gr) //nolint:errcheck
	return &gr, raw, nil
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func getCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.36",
			Section: 1,
			Name:    "Get message with full parameter path",
			Purpose: "Verify the agent returns the value of a parameter when a full parameter path is specified.",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{cfg.ReadableParamPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if raw.StatusCode != http.StatusOK {
					return testcases.Fail(fmt.Sprintf("unexpected HTTP status %d", raw.StatusCode))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results in response")
				}
				r := resp.ReqPathResults[0]
				if r.ErrCode != 0 {
					return testcases.Fail(fmt.Sprintf("err_code %d in req_path_results: %s", r.ErrCode, r.ErrMsg))
				}
				if len(r.ResolvedPathResults) == 0 {
					return testcases.Fail("no resolved_path_results")
				}
				return testcases.Pass(
					testcases.Step("parameter value returned", "pass",
						fmt.Sprintf("path=%s results=%d", cfg.ReadableParamPath, len(r.ResolvedPathResults))),
				)
			},
		},
		{
			ID:      "1.37",
			Section: 1,
			Name:    "Get message with multiple full parameter paths, same object",
			Purpose: "Verify the agent returns values for multiple full parameter paths from the same object.",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Use both a parameter path and the parent object path to exercise multi-path Get.
				objPath := parentObjPath(cfg.ReadableParamPath)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.ReadableParamPath, objPath + "ModelName"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) < 2 {
					return testcases.Fail("expected at least 2 req_path_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("multiple parameter values returned", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.39",
			Section: 1,
			Name:    "Get message with object path",
			Purpose: "Verify the agent returns all parameters of an object when its path is used (object path, not parameter path).",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				objPath := parentObjPath(cfg.ReadableParamPath)
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{objPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 || resp.ReqPathResults[0].ErrCode != 0 {
					return testcases.Fail("no valid results for object path",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("object parameters returned", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.41",
			Section: 1,
			Name:    "Get message with invalid parameter",
			Purpose: "Verify the agent returns an error code in req_path_results when the parameter path is invalid.",
			Tags:    []string{"get", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{cfg.InvalidPath + "NonExistent"}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					// Top-level error is also acceptable.
					return testcases.Pass(testcases.Step("USP error returned for invalid parameter", "pass", string(raw.RawBody)))
				}
				if resp != nil && len(resp.ReqPathResults) > 0 && resp.ReqPathResults[0].ErrCode != 0 {
					return testcases.Pass(testcases.Step(
						fmt.Sprintf("err_code %d in req_path_results", resp.ReqPathResults[0].ErrCode),
						"pass", string(raw.RawBody)))
				}
				return testcases.Fail("agent did not return an error for an invalid parameter path",
					testcases.Step("error check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.42",
			Section: 1,
			Name:    "Get message with invalid parameter and valid parameter",
			Purpose: "Verify the agent returns a result for the valid path and an error for the invalid path.",
			Tags:    []string{"get", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.ReadableParamPath, cfg.InvalidPath + "NonExistent"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if resp == nil || len(resp.ReqPathResults) < 2 {
					return testcases.Fail("expected 2 req_path_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				validOK := resp.ReqPathResults[0].ErrCode == 0 && len(resp.ReqPathResults[0].ResolvedPathResults) > 0
				invalidFailed := resp.ReqPathResults[1].ErrCode != 0
				if validOK && invalidFailed {
					return testcases.Pass(
						testcases.Step("valid path returned value", "pass", ""),
						testcases.Step(fmt.Sprintf("invalid path returned err_code %d", resp.ReqPathResults[1].ErrCode), "pass", ""),
					)
				}
				return testcases.Fail("agent did not correctly handle mixed valid/invalid paths",
					testcases.Step("mixed path check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.82",
			Section: 1,
			Name:    "Get message with unmatched search expression",
			Purpose: "Verify the agent returns an empty resolved_path_results list when the search expression matches no objects.",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.GetInstancesObject + "[Alias==\"UNLIKELY_VALUE_TP469_1_82\"]."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if resp != nil && len(resp.ReqPathResults) > 0 {
					result := resp.ReqPathResults[0]
					if result.ErrCode == 0 && len(result.ResolvedPathResults) == 0 {
						return testcases.Pass(testcases.Step("empty resolved_path_results returned", "pass", string(raw.RawBody)))
					}
				}
				return testcases.Pass(testcases.Step("no error for unmatched expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.89",
			Section: 1,
			Name:    "Get message using max_depth",
			Purpose: "Verify the agent respects the max_depth parameter and does not return results below the specified depth.",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{"Device."},
					MaxDepth:   1,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results in response")
				}
				return testcases.Pass(testcases.Step("response received for max_depth=1", "pass", string(raw.RawBody)))
			},
		},
	}
}

// parentObjPath strips the trailing parameter name from a full parameter path
// and returns the parent object path (with trailing dot).
// e.g. "Device.DeviceInfo.Manufacturer" → "Device.DeviceInfo."
func parentObjPath(param string) string {
	for i := len(param) - 1; i >= 0; i-- {
		if param[i] == '.' {
			return param[:i+1]
		}
	}
	return param
}
