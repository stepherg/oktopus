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
// Request / response types mirroring the USP proto json tags.
// ---------------------------------------------------------------------------

type paramSetting struct {
	Param    string `json:"param"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type createObject struct {
	ObjPath      string         `json:"obj_path"`
	ParamSettings []paramSetting `json:"param_settings"`
}

type addRequest struct {
	AllowPartial bool           `json:"allow_partial"`
	CreateObjs   []createObject `json:"create_objs"`
}

type addRespOperSuccess struct {
	InstantiatedPath string            `json:"instantiated_path"`
	UniqueKeys       map[string]string `json:"unique_keys"`
}

type addRespOperFailure struct {
	ErrCode uint32 `json:"err_code"`
	ErrMsg  string `json:"err_msg"`
}

type addRespOperStatus struct {
	OperSuccess *addRespOperSuccess `json:"oper_success"`
	OperFailure *addRespOperFailure `json:"oper_failure"`
}

type addRespCreatedObj struct {
	RequestedPath string            `json:"requested_path"`
	OperStatus    addRespOperStatus `json:"oper_status"`
}

type addResp struct {
	CreatedObjResults []addRespCreatedObj `json:"created_obj_results"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sendAdd(ctx context.Context, c *client.ControllerClient, target testcases.Target, req addRequest) (*addResp, *client.USPResponse, error) {
	resp, err := c.Add(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var ar addResp
	if err := json.Unmarshal(resp.RawBody, &ar); err != nil {
		return nil, resp, nil // could be an error response
	}
	return &ar, resp, nil
}

// deleteInstantiatedPath is a clean-up helper used at the end of Add tests to
// remove the object created during the test so the device stays tidy.
func deleteInstantiatedPath(ctx context.Context, c *client.ControllerClient, target testcases.Target, path string) {
	type delReq struct {
		AllowPartial bool     `json:"allow_partial"`
		ObjPaths     []string `json:"obj_paths"`
	}
	c.Delete(ctx, target.DeviceID, target.MTP, delReq{AllowPartial: true, ObjPaths: []string{path}}) //nolint:errcheck
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func addCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.1",
			Section: 1,
			Name:    "Add message with allow_partial false, single object, required parameters succeed",
			Purpose: "Verify the agent correctly creates an object when all required parameters are provided.",
			Tags:    []string{"add"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{{
						ObjPath: cfg.MultiInstanceObject,
						ParamSettings: []paramSetting{{
							Param:    cfg.RequiredParam,
							Value:    cfg.RequiredParamValue,
							Required: true,
						}},
					}},
				}
				resp, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if raw.StatusCode != http.StatusOK {
					return testcases.Fail(fmt.Sprintf("unexpected HTTP status %d", raw.StatusCode),
						testcases.Step("HTTP status check", "fail", string(raw.RawBody)))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg),
						testcases.Step("USP error check", "fail", string(raw.RawBody)))
				}
				if resp == nil || len(resp.CreatedObjResults) == 0 {
					return testcases.Fail("no created_obj_results in response",
						testcases.Step("response body check", "fail", string(raw.RawBody)))
				}
				res := resp.CreatedObjResults[0]
				if res.OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				if res.OperStatus.OperSuccess.InstantiatedPath == "" {
					return testcases.Fail("instantiated_path is empty",
						testcases.Step("instantiated_path check", "fail", string(raw.RawBody)))
				}
				// Clean up the created instance.
				deleteInstantiatedPath(ctx, c, target, res.OperStatus.OperSuccess.InstantiatedPath)
				return testcases.Pass(
					testcases.Step("HTTP status check", "pass", "200 OK"),
					testcases.Step("oper_success check", "pass", "instantiated_path: "+res.OperStatus.OperSuccess.InstantiatedPath),
				)
			},
		},
		{
			ID:      "1.2",
			Section: 1,
			Name:    "Add message with allow_partial true, single object, required parameters succeed",
			Purpose: "Verify the agent creates an object when allow_partial is true and all required parameters are valid.",
			Tags:    []string{"add", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: true,
					CreateObjs: []createObject{{
						ObjPath: cfg.MultiInstanceObject,
						ParamSettings: []paramSetting{{
							Param:    cfg.RequiredParam,
							Value:    cfg.RequiredParamValue,
							Required: true,
						}},
					}},
				}
				resp, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if raw.StatusCode != http.StatusOK {
					return testcases.Fail(fmt.Sprintf("unexpected HTTP status %d", raw.StatusCode))
				}
				if resp == nil || len(resp.CreatedObjResults) == 0 {
					return testcases.Fail("no created_obj_results in response")
				}
				if resp.CreatedObjResults[0].OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present")
				}
				path := resp.CreatedObjResults[0].OperStatus.OperSuccess.InstantiatedPath
				deleteInstantiatedPath(ctx, c, target, path)
				return testcases.Pass(
					testcases.Step("oper_success check", "pass", "instantiated_path: "+path),
				)
			},
		},
		{
			ID:      "1.3",
			Section: 1,
			Name:    "Add message with allow_partial false, single object, required parameters fail",
			Purpose: "Verify the agent rejects the creation when a required parameter has an invalid value and allow_partial is false.",
			Tags:    []string{"add", "allow_partial", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{{
						ObjPath: cfg.MultiInstanceObject,
						ParamSettings: []paramSetting{{
							Param:    cfg.RequiredParam,
							Value:    "INTENTIONALLY_INVALID_VALUE_TP469_1_3",
							Required: true,
						}},
					}},
				}
				resp, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				// The agent must return a USP error or oper_failure – it must NOT return oper_success.
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("error returned on invalid required param", "pass", string(raw.RawBody)))
				}
				if resp != nil && len(resp.CreatedObjResults) > 0 {
					if resp.CreatedObjResults[0].OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
					}
					if resp.CreatedObjResults[0].OperStatus.OperSuccess != nil {
						// Clean up and fail.
						deleteInstantiatedPath(ctx, c, target, resp.CreatedObjResults[0].OperStatus.OperSuccess.InstantiatedPath)
						return testcases.Fail("agent returned oper_success for invalid required parameter",
							testcases.Step("oper_failure check", "fail", string(raw.RawBody)))
					}
				}
				return testcases.Pass(testcases.Step("agent rejected creation", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.4",
			Section: 1,
			Name:    "Add message with allow_partial false, single invalid object",
			Purpose: "Verify the agent returns an error when the obj_path is not a valid supported object.",
			Tags:    []string{"add", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{{
						ObjPath: cfg.InvalidPath,
					}},
				}
				_, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step(fmt.Sprintf("USP error %d returned for invalid obj_path", code), "pass", string(raw.RawBody)))
				}
				// Could also be oper_failure inside created_obj_results.
				var ar addResp
				if json.Unmarshal(raw.RawBody, &ar) == nil && len(ar.CreatedObjResults) > 0 {
					if ar.CreatedObjResults[0].OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned for invalid obj_path", "pass", string(raw.RawBody)))
					}
				}
				return testcases.Fail("agent did not return an error for an invalid object path",
					testcases.Step("error check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.5",
			Section: 1,
			Name:    "Add message with allow_partial false, multiple objects",
			Purpose: "Verify the agent can create multiple objects in a single Add request.",
			Tags:    []string{"add"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{
						{ObjPath: cfg.MultiInstanceObject, ParamSettings: []paramSetting{{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue, Required: true}}},
						{ObjPath: cfg.MultiInstanceObject, ParamSettings: []paramSetting{{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue, Required: true}}},
					},
				}
				resp, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.CreatedObjResults) < 2 {
					return testcases.Fail("expected 2 created_obj_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				for _, r := range resp.CreatedObjResults {
					if r.OperStatus.OperSuccess == nil {
						return testcases.Fail("at least one object was not created successfully")
					}
					deleteInstantiatedPath(ctx, c, target, r.OperStatus.OperSuccess.InstantiatedPath)
				}
				return testcases.Pass(testcases.Step("both objects created", "pass", ""))
			},
		},
		{
			ID:      "1.7",
			Section: 1,
			Name:    "Add message with allow_partial false, multiple objects, required parameters fail in single object",
			Purpose: "Verify that when allow_partial is false and one object fails, the entire Add request is rejected.",
			Tags:    []string{"add", "allow_partial", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{
						{ObjPath: cfg.MultiInstanceObject, ParamSettings: []paramSetting{{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue, Required: true}}},
						{ObjPath: cfg.MultiInstanceObject, ParamSettings: []paramSetting{{Param: cfg.RequiredParam, Value: "INVALID_TP469_1_7", Required: true}}},
					},
				}
				resp, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				// With allow_partial=false both must fail.
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned – entire request rejected", "pass", string(raw.RawBody)))
				}
				if resp != nil {
					for _, r := range resp.CreatedObjResults {
						if r.OperStatus.OperSuccess != nil {
							deleteInstantiatedPath(ctx, c, target, r.OperStatus.OperSuccess.InstantiatedPath)
							return testcases.Fail("agent created an object despite allow_partial=false and one invalid required param",
								testcases.Step("oper_success check", "fail", string(raw.RawBody)))
						}
					}
				}
				return testcases.Pass(testcases.Step("no objects created – request correctly rejected", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.8",
			Section: 1,
			Name:    "Add message with allow_partial true, required parameters fail, invalid type, single object",
			Purpose: "Verify that when allow_partial is true and required parameters fail, the agent returns oper_failure with an appropriate error code.",
			Tags:    []string{"add", "allow_partial", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				req := addRequest{
					AllowPartial: true,
					CreateObjs: []createObject{{
						ObjPath: cfg.MultiInstanceObject,
						ParamSettings: []paramSetting{{
							Param:    cfg.RequiredParam,
							Value:    "INVALID_TP469_1_8",
							Required: true,
						}},
					}},
				}
				resp, raw, err := sendAdd(ctx, c, target, req)
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if resp != nil && len(resp.CreatedObjResults) > 0 {
					r := resp.CreatedObjResults[0]
					if r.OperStatus.OperFailure != nil && r.OperStatus.OperFailure.ErrCode != 0 {
						return testcases.Pass(testcases.Step(
							fmt.Sprintf("oper_failure with err_code %d", r.OperStatus.OperFailure.ErrCode),
							"pass", string(raw.RawBody)))
					}
					if r.OperStatus.OperSuccess != nil {
						deleteInstantiatedPath(ctx, c, target, r.OperStatus.OperSuccess.InstantiatedPath)
						return testcases.Fail("agent returned oper_success for invalid required parameter with allow_partial=true")
					}
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned", "pass", string(raw.RawBody)))
				}
				return testcases.Fail("expected oper_failure but got unexpected response",
					testcases.Step("oper_failure check", "fail", string(raw.RawBody)))
			},
		},
	}
}
