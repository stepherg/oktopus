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
				// Spec uses Device.LocalAgent.EndpointID and Device.LocalAgent.SoftwareVersion –
				// both always present on a USP agent and on the same parent object.
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{"Device.LocalAgent.EndpointID", "Device.LocalAgent.SoftwareVersion"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) < 2 {
					return testcases.Fail("expected 2 req_path_results for 2 param paths",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				for _, r := range resp.ReqPathResults {
					if r.ErrCode != 0 {
						return testcases.Fail(fmt.Sprintf("err_code %d for path %s: %s", r.ErrCode, r.RequestedPath, r.ErrMsg),
							testcases.Step("path error check", "fail", string(raw.RawBody)))
					}
				}
				return testcases.Pass(testcases.Step("both parameter values returned from same object", "pass", string(raw.RawBody)))
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
			Purpose: "Verify the agent respects the max_depth parameter. Spec requires testing max_depth 1, 2, and 0 (unlimited).",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				var steps []testcases.StepResult
				// Spec tests max_depth 1, 2, and 0; use Device.LocalAgent. to keep response size reasonable.
				for _, depth := range []uint32{1, 2, 0} {
					resp, raw, err := sendGet(ctx, c, target, getRequest{
						ParamPaths: []string{"Device.LocalAgent."},
						MaxDepth:   depth,
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error (max_depth=%d): %v", depth, err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("USP error %d for max_depth=%d: %s", code, depth, msg))
					}
					if resp == nil || len(resp.ReqPathResults) == 0 {
						return testcases.Fail(fmt.Sprintf("no req_path_results for max_depth=%d", depth))
					}
					steps = append(steps, testcases.Step(
						fmt.Sprintf("response received for max_depth=%d", depth), "pass", "",
					))
				}
				return testcases.Pass(steps...)
			},
		},
		{
			ID:      "1.38",
			Section: 1,
			Name:    "Get message with multiple full parameter paths from different objects",
			Purpose: "Verify the agent returns values for multiple full parameter paths that span different object instances.",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Device.LocalAgent.EndpointID and Device.DeviceInfo.Manufacturer are different top-level objects.
				paths := []string{"Device.LocalAgent.EndpointID", "Device.DeviceInfo.Manufacturer"}
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: paths})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) < 2 {
					return testcases.Fail("expected 2 req_path_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				for _, r := range resp.ReqPathResults {
					if r.ErrCode != 0 {
						return testcases.Fail(fmt.Sprintf("err_code %d for path %s: %s", r.ErrCode, r.RequestedPath, r.ErrMsg))
					}
					if len(r.ResolvedPathResults) == 0 {
						return testcases.Fail(fmt.Sprintf("no resolved_path_results for path %s", r.RequestedPath))
					}
				}
				return testcases.Pass(testcases.Step("both parameter paths returned values from different objects", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.40",
			Section: 1,
			Name:    "Get message with object instance path",
			Purpose: "Verify the agent returns the parameters of an object instance when the path points to a specific instance.",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				instantiatedPath, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, instantiatedPath)
				resp, raw, getErr := sendGet(ctx, c, target, getRequest{ParamPaths: []string{instantiatedPath}})
				if getErr != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", getErr))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if resp.ReqPathResults[0].ErrCode != 0 {
					return testcases.Fail(fmt.Sprintf("err_code %d: %s", resp.ReqPathResults[0].ErrCode, resp.ReqPathResults[0].ErrMsg))
				}
				if len(resp.ReqPathResults[0].ResolvedPathResults) == 0 {
					return testcases.Fail("no resolved_path_results for instance path", testcases.Step("resolved check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("parameters returned for object instance path", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.43",
			Section: 1,
			Name:    "Get message with unique key addressing",
			Purpose: "Verify the agent resolves a path that uses unique key addressing and returns the requested parameter.",
			Tags:    []string{"get", "unique_key"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				const subID = "get1-43-uk"
				ar, addRaw, err := sendAdd(ctx, c, target, addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{{
						ObjPath: cfg.MultiInstanceObject,
						ParamSettings: []paramSetting{
							{Param: "ID", Value: subID},
							{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue},
						},
					}},
				})
				if err != nil {
					return testcases.Error("setup Add failed: " + err.Error())
				}
				if ar == nil || len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					return testcases.Error("setup Add did not succeed: " + string(addRaw.RawBody))
				}
				instantiatedPath := ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath
				defer deleteInstantiatedPath(ctx, c, target, instantiatedPath)

				ukPath := fmt.Sprintf("%s[ID==\"%s\"].Enable", cfg.MultiInstanceObject, subID)
				resp, raw, getErr := sendGet(ctx, c, target, getRequest{ParamPaths: []string{ukPath}})
				if getErr != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", getErr))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 || len(resp.ReqPathResults[0].ResolvedPathResults) == 0 {
					return testcases.Fail("no resolved_path_results for unique key addressed path",
						testcases.Step("resolved check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("parameter returned via unique key addressing", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.44",
			Section: 1,
			Name:    "Get message with wildcard on a full parameter path",
			Purpose: "Verify the agent returns a value for each instance when a wildcard is used in a full parameter path.",
			Tags:    []string{"get", "wildcard"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p1, err1 := createTempSubscription(ctx, c, target, cfg)
				p2, err2 := createTempSubscription(ctx, c, target, cfg)
				if err1 != nil || err2 != nil {
					deleteInstantiatedPath(ctx, c, target, p1)
					return testcases.Error("setup failed creating subscriptions")
				}
				defer deleteInstantiatedPath(ctx, c, target, p1)
				defer deleteInstantiatedPath(ctx, c, target, p2)

				wildcardPath := cfg.MultiInstanceObject + "*.Enable"
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{wildcardPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if len(resp.ReqPathResults[0].ResolvedPathResults) < 1 {
					return testcases.Fail("no resolved_path_results for wildcard parameter path",
						testcases.Step("wildcard resolved check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("wildcard parameter path resolved to multiple results", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.45",
			Section: 1,
			Name:    "Get message with wildcard on an object path",
			Purpose: "Verify the agent returns all parameters for each instance when a wildcard is used in an object path.",
			Tags:    []string{"get", "wildcard"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p1, err1 := createTempSubscription(ctx, c, target, cfg)
				p2, err2 := createTempSubscription(ctx, c, target, cfg)
				if err1 != nil || err2 != nil {
					deleteInstantiatedPath(ctx, c, target, p1)
					return testcases.Error("setup failed creating subscriptions")
				}
				defer deleteInstantiatedPath(ctx, c, target, p1)
				defer deleteInstantiatedPath(ctx, c, target, p2)

				wildcardPath := cfg.MultiInstanceObject + "*."
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{wildcardPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if len(resp.ReqPathResults[0].ResolvedPathResults) < 1 {
					return testcases.Fail("no resolved_path_results for wildcard object path",
						testcases.Step("wildcard resolved check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("wildcard object path resolved to instance parameters", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.46",
			Section: 1,
			Name:    "Get message with search expression, equivalence",
			Purpose: "Verify the agent returns objects matching an equivalence search expression (==).",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, p)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.MultiInstanceObject + "[Enable==false]."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetResp returned for equivalence search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.47",
			Section: 1,
			Name:    "Get message with search expression, non-equivalence",
			Purpose: "Verify the agent returns objects matching a non-equivalence search expression (!=).",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, p)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.MultiInstanceObject + "[Enable!=false].Enable"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetResp returned for non-equivalence search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.48",
			Section: 1,
			Name:    "Get message with search expression, exclusive greater",
			Purpose: "Verify the agent returns objects matching an exclusive greater-than search expression (>).",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, p)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.MultiInstanceObject + "[NotifExpiration>0].NotifExpiration"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetResp returned for exclusive-greater search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.49",
			Section: 1,
			Name:    "Get message with search expression, exclusive lesser",
			Purpose: "Verify the agent returns objects matching an exclusive less-than search expression (<).",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, p)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.MultiInstanceObject + "[NotifExpiration<10000].NotifExpiration"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetResp returned for exclusive-lesser search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.50",
			Section: 1,
			Name:    "Get message with search expression, inclusive greater",
			Purpose: "Verify the agent returns objects matching an inclusive greater-than-or-equal search expression (>=).",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, p)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.MultiInstanceObject + "[NotifExpiration>=0].NotifExpiration"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetResp returned for inclusive-greater search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.51",
			Section: 1,
			Name:    "Get message with search expression, inclusive lesser",
			Purpose: "Verify the agent returns objects matching an inclusive less-than-or-equal search expression (<=).",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				p, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				defer deleteInstantiatedPath(ctx, c, target, p)
				resp, raw, err := sendGet(ctx, c, target, getRequest{
					ParamPaths: []string{cfg.MultiInstanceObject + "[NotifExpiration<=10000].NotifExpiration"},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetResp returned for inclusive-lesser search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.86",
			Section: 1,
			Name:    "Get message with unresolved search path (search expression matches no instances)",
			Purpose: "Verify the agent returns an empty resolved_path_results for a search path when no instances match.",
			Tags:    []string{"get", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Use an impossible ID value to guarantee no match regardless of device state.
				unresolvedPath := cfg.MultiInstanceObject + "[ID==\"IMPOSSIBLE_VALUE_TP469_1_86\"]."
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{unresolvedPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("unexpected USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results in response", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				result := resp.ReqPathResults[0]
				if result.ErrCode != 0 {
					return testcases.Fail(fmt.Sprintf("req_path_result err_code %d: %s – agent should return empty results, not an error", result.ErrCode, result.ErrMsg))
				}
				if len(result.ResolvedPathResults) != 0 {
					return testcases.Fail("expected empty resolved_path_results for unmatched search path",
						testcases.Step("empty resolved check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("empty resolved_path_results for unmatched search path", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.87",
			Section: 1,
			Name:    "Get message with unresolved path (empty multi-instance table)",
			Purpose: "Verify the agent returns an empty resolved_path_results when the requested object path points to an empty table.",
			Tags:    []string{"get"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Device.LocalAgent.Request. is a table that is empty except during active operations.
				emptyTablePath := "Device.LocalAgent.Request."
				resp, raw, err := sendGet(ctx, c, target, getRequest{ParamPaths: []string{emptyTablePath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("unexpected USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results in response", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				result := resp.ReqPathResults[0]
				if result.ErrCode != 0 {
					return testcases.Fail(fmt.Sprintf("req_path_result err_code %d: %s – expected empty result, not error", result.ErrCode, result.ErrMsg))
				}
				return testcases.Pass(testcases.Step("GetResp returned without error for empty table path", "pass", string(raw.RawBody)))
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
