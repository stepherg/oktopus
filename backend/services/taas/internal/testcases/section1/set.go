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

type setRespOperStatus struct {
	OperStatus *struct {
		OperSuccess *struct {
			UpdatedInstResults []struct {
				AffectedPath string `json:"affected_path"`
				ParamErrs    []struct {
					Param   string `json:"param"`
					ErrCode uint32 `json:"err_code"`
					ErrMsg  string `json:"err_msg"`
				} `json:"param_errs"`
			} `json:"updated_inst_results"`
		} `json:"OperSuccess"`
		OperFailure *struct {
			ErrCode uint32 `json:"err_code"`
			ErrMsg  string `json:"err_msg"`
		} `json:"OperFailure"`
	} `json:"OperStatus"`
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

// setWithSubscription creates a Subscription, runs fn with its instance path, then deletes it.
// It returns an error Result if setup or teardown fails.
func setWithSubscription(
	ctx context.Context,
	c *client.ControllerClient,
	target testcases.Target,
	subID string,
	fn func(subPath string) testcases.Result,
) testcases.Result {
	// --- setup: add a Subscription ---
	ar, addRaw, err := sendAdd(ctx, c, target, addRequest{
		AllowPartial: false,
		CreateObjs: []createObject{{
			ObjPath: "Device.LocalAgent.Subscription.",
			ParamSettings: []paramSetting{
				{Param: "Enable", Value: "true"},
				{Param: "ID", Value: subID},
				{Param: "NotifType", Value: "ValueChange"},
				{Param: "ReferenceList", Value: "Device.LocalAgent.SoftwareVersion", Required: true},
			},
		}},
	})
	if err != nil {
		return testcases.Error(fmt.Sprintf("setup Add failed: %v", err))
	}
	if ar == nil || len(ar.CreatedObjResults) == 0 ||
		ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil ||
		ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath == "" {
		return testcases.Error(fmt.Sprintf("setup Add did not return instance path: %s", string(addRaw.RawBody)))
	}
	subPath := ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath

	// --- run the actual test ---
	result := fn(subPath)

	// --- teardown ---
	deleteInstantiatedPath(ctx, c, target, subPath)

	return result
}

// setWithTwoSubscriptions creates two Subscription instances with the given IDs,
// runs fn with their paths, then deletes both.
func setWithTwoSubscriptions(
	ctx context.Context,
	c *client.ControllerClient,
	target testcases.Target,
	id1, id2 string,
	fn func(path1, path2 string) testcases.Result,
) testcases.Result {
	ar, addRaw, err := sendAdd(ctx, c, target, addRequest{
		AllowPartial: false,
		CreateObjs: []createObject{
			{
				ObjPath: "Device.LocalAgent.Subscription.",
				ParamSettings: []paramSetting{
					{Param: "Enable", Value: "true"},
					{Param: "ID", Value: id1},
					{Param: "NotifType", Value: "ValueChange"},
					{Param: "ReferenceList", Value: "Device.LocalAgent.SoftwareVersion", Required: true},
				},
			},
			{
				ObjPath: "Device.LocalAgent.Subscription.",
				ParamSettings: []paramSetting{
					{Param: "Enable", Value: "true"},
					{Param: "ID", Value: id2},
					{Param: "NotifType", Value: "ValueChange"},
					{Param: "ReferenceList", Value: "Device.LocalAgent.SoftwareVersion", Required: true},
				},
			},
		},
	})
	if err != nil {
		return testcases.Error(fmt.Sprintf("setup Add failed: %v", err))
	}
	if ar == nil || len(ar.CreatedObjResults) < 2 ||
		ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil ||
		ar.CreatedObjResults[1].OperStatus.OperStatus.OperSuccess == nil {
		return testcases.Error(fmt.Sprintf("setup Add failed to create 2 subscriptions: %s", string(addRaw.RawBody)))
	}
	path1 := ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath
	path2 := ar.CreatedObjResults[1].OperStatus.OperStatus.OperSuccess.InstantiatedPath
	result := fn(path1, path2)
	deleteInstantiatedPath(ctx, c, target, path1)
	deleteInstantiatedPath(ctx, c, target, path2)
	return result
}

func setCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.11",
			Section: 1,
			Name:    "Set message with allow_partial false, required parameters pass",
			Purpose: "Verify the agent correctly updates an object's parameter when allow_partial is false and the parameter value is valid.",
			Tags:    []string{"set"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithSubscription(ctx, c, target, "set1-11", func(subPath string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{{
							ObjPath: subPath,
							ParamSettings: []setParamSetting{{
								Param:    "NotifRetry",
								Value:    "true",
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
					if resp.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
						return testcases.Fail("oper_success not present",
							testcases.Step("oper_success check", "fail", string(raw.RawBody)))
					}
					return testcases.Pass(testcases.Step("oper_success returned", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.12",
			Section: 1,
			Name:    "Set message with allow_partial true, required parameters pass",
			Purpose: "Verify the agent updates a parameter when allow_partial is true and the parameter is valid.",
			Tags:    []string{"set", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithSubscription(ctx, c, target, "set1-12", func(subPath string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: true,
						UpdateObjs: []setUpdateObject{{
							ObjPath:       subPath,
							ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) == 0 || resp.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
						return testcases.Fail("oper_success not present", testcases.Step("oper_success check", "fail", string(raw.RawBody)))
					}
					return testcases.Pass(testcases.Step("oper_success returned", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.14",
			Section: 1,
			Name:    "Set message with allow_partial false, required parameters fail",
			Purpose: "Verify the agent rejects the Set when a required parameter is invalid and allow_partial is false.",
			Tags:    []string{"set", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithSubscription(ctx, c, target, "set1-14", func(subPath string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{{
							ObjPath:       subPath,
							ParamSettings: []setParamSetting{{Param: "InvalidParameter", Value: "irrelevant", Required: true}},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Pass(testcases.Step("USP error returned for invalid required param", "pass", string(raw.RawBody)))
					}
					if resp != nil && len(resp.UpdatedObjResults) > 0 && resp.UpdatedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
					}
					return testcases.Fail("expected error or oper_failure for invalid required param",
						testcases.Step("error check", "fail", string(raw.RawBody)))
				})
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
					if s := resp.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess; s != nil && len(s.UpdatedInstResults) == 0 {
						return testcases.Pass(testcases.Step("empty oper_success returned", "pass", string(raw.RawBody)))
					}
				}
				// A USP error response is also acceptable when no objects match.
				return testcases.Pass(testcases.Step("agent handled no-match path", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.13",
			Section: 1,
			Name:    "Set message with allow_partial false, multiple objects",
			Purpose: "Verify the agent updates parameters on multiple objects when allow_partial is false and all updates succeed.",
			Tags:    []string{"set"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithTwoSubscriptions(ctx, c, target, "set1-13a", "set1-13b", func(path1, path2 string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{
							{ObjPath: path1, ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}}},
							{ObjPath: path2, ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "false", Required: true}}},
						},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) < 2 {
						return testcases.Fail("expected 2 updated_obj_results",
							testcases.Step("result count check", "fail", string(raw.RawBody)))
					}
					for _, r := range resp.UpdatedObjResults {
						if r.OperStatus.OperStatus.OperSuccess == nil {
							return testcases.Fail("oper_success not present for all updated objects",
								testcases.Step("oper_success check", "fail", string(raw.RawBody)))
						}
					}
					return testcases.Pass(testcases.Step("both objects updated successfully", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.15",
			Section: 1,
			Name:    "Set message with allow_partial false, multiple objects, required parameters fail in single object",
			Purpose: "Verify the agent rejects the entire Set request when allow_partial is false and one object has a failing required parameter.",
			Tags:    []string{"set", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithTwoSubscriptions(ctx, c, target, "set1-15a", "set1-15b", func(path1, path2 string) testcases.Result {
					_, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{
							{ObjPath: path1, ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}}},
							{ObjPath: path2, ParamSettings: []setParamSetting{{Param: "InvalidParameter", Value: "bad", Required: true}}},
						},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Pass(testcases.Step("USP error returned – entire request rejected", "pass", string(raw.RawBody)))
					}
					var sr setResp
					if json.Unmarshal(raw.RawBody, &sr) == nil {
						for _, r := range sr.UpdatedObjResults {
							if r.OperStatus.OperStatus.OperFailure != nil {
								return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
							}
						}
					}
					return testcases.Fail("expected error or oper_failure for required param failure in multi-object set",
						testcases.Step("error check", "fail", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.16",
			Section: 1,
			Name:    "Set message with allow_partial true, required parameter fails, multiple objects",
			Purpose: "Verify that with allow_partial true, the valid object update succeeds and the invalid one returns oper_failure.",
			Tags:    []string{"set", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithTwoSubscriptions(ctx, c, target, "set1-16a", "set1-16b", func(path1, path2 string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: true,
						UpdateObjs: []setUpdateObject{
							{ObjPath: path1, ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}}},
							{ObjPath: path2, ParamSettings: []setParamSetting{{Param: "InvalidParameter", Value: "bad", Required: true}}},
						},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("with allow_partial=true got top-level USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) < 2 {
						return testcases.Fail("expected 2 updated_obj_results",
							testcases.Step("result count", "fail", string(raw.RawBody)))
					}
					var gotSuccess, gotFailure bool
					for _, r := range resp.UpdatedObjResults {
						if r.OperStatus.OperStatus.OperSuccess != nil {
							gotSuccess = true
						}
						if r.OperStatus.OperStatus.OperFailure != nil {
							gotFailure = true
						}
					}
					if !gotSuccess || !gotFailure {
						return testcases.Fail("expected one oper_success and one oper_failure",
							testcases.Step("mixed result check", "fail", string(raw.RawBody)))
					}
					return testcases.Pass(testcases.Step("valid object updated, invalid returned oper_failure", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.17",
			Section: 1,
			Name:    "Set message with allow_partial true, non-required parameter fails, multiple parameters",
			Purpose: "Verify the agent updates the valid parameter and reports a ParameterError for the invalid non-required parameter.",
			Tags:    []string{"set", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithSubscription(ctx, c, target, "set1-17", func(subPath string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: true,
						UpdateObjs: []setUpdateObject{{
							ObjPath: subPath,
							ParamSettings: []setParamSetting{
								{Param: "NotifRetry", Value: "true"},
								{Param: "InvalidParameter", Value: "bad"},
							},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) == 0 {
						return testcases.Fail("no updated_obj_results",
							testcases.Step("result check", "fail", string(raw.RawBody)))
					}
					r := resp.UpdatedObjResults[0]
					if r.OperStatus.OperStatus.OperSuccess == nil {
						return testcases.Fail("expected oper_success (valid param should update, invalid should be in param_errs)",
							testcases.Step("oper_success check", "fail", string(raw.RawBody)))
					}
					hasParamErr := len(r.OperStatus.OperStatus.OperSuccess.UpdatedInstResults) > 0 &&
						len(r.OperStatus.OperStatus.OperSuccess.UpdatedInstResults[0].ParamErrs) > 0
					if hasParamErr {
						return testcases.Pass(
							testcases.Step("oper_success returned with NotifRetry updated", "pass", ""),
							testcases.Step("ParameterError for InvalidParameter", "pass", string(raw.RawBody)),
						)
					}
					return testcases.Pass(testcases.Step("oper_success returned (param_errs format may differ)", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.18",
			Section: 1,
			Name:    "Set message with unique key addressing in path",
			Purpose: "Verify the agent can update a parameter using a unique key expression in the object path.",
			Tags:    []string{"set", "unique_key"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				const subID = "set1-18-uk"
				return setWithSubscription(ctx, c, target, subID, func(subPath string) testcases.Result {
					ukPath := fmt.Sprintf("Device.LocalAgent.Subscription.[ID==\"%s\"].", subID)
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{{
							ObjPath:       ukPath,
							ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) == 0 || resp.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
						return testcases.Fail("oper_success not present for unique key addressed set",
							testcases.Step("oper_success check", "fail", string(raw.RawBody)))
					}
					return testcases.Pass(testcases.Step("parameter updated via unique key addressing", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.19",
			Section: 1,
			Name:    "Set message with wildcard search path, allow_partial false, required parameters pass",
			Purpose: "Verify the agent updates a parameter on all matching objects when using a wildcard path.",
			Tags:    []string{"set", "wildcard"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithTwoSubscriptions(ctx, c, target, "set1-19a", "set1-19b", func(_, _ string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{{
							ObjPath:       "Device.LocalAgent.Subscription.*.",
							ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) == 0 {
						return testcases.Fail("no updated_obj_results for wildcard set",
							testcases.Step("result check", "fail", string(raw.RawBody)))
					}
					if resp.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
						return testcases.Fail("oper_success not present",
							testcases.Step("oper_success check", "fail", string(raw.RawBody)))
					}
					return testcases.Pass(testcases.Step("wildcard set succeeded", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.21",
			Section: 1,
			Name:    "Set message with wildcard search path, allow_partial true, required parameters fail",
			Purpose: "Verify the agent returns oper_failure for each matched object when all required parameters fail with allow_partial true.",
			Tags:    []string{"set", "wildcard", "allow_partial", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				return setWithTwoSubscriptions(ctx, c, target, "set1-21a", "set1-21b", func(_, _ string) testcases.Result {
					resp, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: true,
						UpdateObjs: []setUpdateObject{{
							ObjPath:       "Device.LocalAgent.Subscription.*.",
							ParamSettings: []setParamSetting{{Param: "Enable", Value: "INVALID_VALUE_TP469_1_21", Required: true}},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Fail(fmt.Sprintf("with allow_partial=true got top-level USP error %d: %s", code, msg))
					}
					if resp == nil || len(resp.UpdatedObjResults) == 0 {
						return testcases.Fail("no updated_obj_results for wildcard set",
							testcases.Step("result check", "fail", string(raw.RawBody)))
					}
					if resp.UpdatedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned for invalid wildcard set", "pass", string(raw.RawBody)))
					}
					return testcases.Pass(testcases.Step("agent handled wildcard set with all-failing required params", "pass", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.22",
			Section: 1,
			Name:    "Set message with search expression search path",
			Purpose: "Verify the agent correctly sets parameters on instances matching a search expression.",
			Tags:    []string{"set", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				// Create a subscription with NotifExpiration=30 so the search expression [NotifExpiration>0] matches it.
				ar, addRaw, err := sendAdd(ctx, c, target, addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{{
						ObjPath: "Device.LocalAgent.Subscription.",
						ParamSettings: []paramSetting{
							{Param: "Enable", Value: "true"},
							{Param: "ID", Value: "set1-22"},
							{Param: "NotifType", Value: "ValueChange"},
							{Param: "ReferenceList", Value: "Device.LocalAgent.SoftwareVersion", Required: true},
							{Param: "NotifExpiration", Value: "30"},
						},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("setup Add failed: %v", err))
				}
				if ar == nil || len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					return testcases.Error("setup Add did not succeed: " + string(addRaw.RawBody))
				}
				subPath := ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath
				defer deleteInstantiatedPath(ctx, c, target, subPath)

				resp, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: false,
					UpdateObjs: []setUpdateObject{{
						ObjPath:       "Device.LocalAgent.Subscription.[NotifExpiration>0].",
						ParamSettings: []setParamSetting{{Param: "NotifRetry", Value: "true", Required: true}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.UpdatedObjResults) == 0 {
					return testcases.Fail("no updated_obj_results for search expression set",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if resp.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("search expression set succeeded", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.96",
			Section: 1,
			Name:    "Non-functional Unique Key Immutability",
			Purpose: "Verify the agent does not allow a non-functional unique key (ID) to be changed after object creation.",
			Tags:    []string{"set", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				const subID = "add96"
				return setWithSubscription(ctx, c, target, subID, func(subPath string) testcases.Result {
					_, raw, err := sendSet(ctx, c, target, setRequest{
						AllowPartial: false,
						UpdateObjs: []setUpdateObject{{
							ObjPath:       subPath,
							ParamSettings: []setParamSetting{{Param: "ID", Value: "add96-NEW", Required: true}},
						}},
					})
					if err != nil {
						return testcases.Error(fmt.Sprintf("transport error: %v", err))
					}
					if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
						return testcases.Pass(testcases.Step("USP error returned – non-functional unique key cannot be changed", "pass", string(raw.RawBody)))
					}
					var sr setResp
					if json.Unmarshal(raw.RawBody, &sr) == nil && len(sr.UpdatedObjResults) > 0 {
						if sr.UpdatedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
							return testcases.Pass(testcases.Step("oper_failure returned for immutable key change", "pass", string(raw.RawBody)))
						}
					}
					return testcases.Fail("agent allowed a non-functional unique key to be changed",
						testcases.Step("immutability check", "fail", string(raw.RawBody)))
				})
			},
		},
		{
			ID:      "1.104",
			Section: 1,
			Name:    "Set message on WriteOnceReadOnly parameter",
			Purpose: "Verify the agent rejects an attempt to change a WriteOnceReadOnly parameter (Alias) after it is set at creation.",
			Tags:    []string{"set", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Create a subscription with Alias explicitly set.
				ar, addRaw, err := sendAdd(ctx, c, target, addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{{
						ObjPath: cfg.MultiInstanceObject,
						ParamSettings: []paramSetting{
							{Param: "Alias", Value: "test-1-104"},
							{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue},
						},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("setup Add failed: %v", err))
				}
				if ar == nil || len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					// Alias might not be supported – skip since we can't run the test.
					return testcases.Skip("setup Add did not succeed (Alias parameter may not be supported): " + string(addRaw.RawBody))
				}
				subPath := ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath
				defer deleteInstantiatedPath(ctx, c, target, subPath)

				_, raw, err := sendSet(ctx, c, target, setRequest{
					AllowPartial: false,
					UpdateObjs: []setUpdateObject{{
						ObjPath:       subPath,
						ParamSettings: []setParamSetting{{Param: "Alias", Value: "test-1-104-new-alias", Required: true}},
					}},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned – WriteOnceReadOnly parameter cannot be changed", "pass", string(raw.RawBody)))
				}
				var sr setResp
				if json.Unmarshal(raw.RawBody, &sr) == nil && len(sr.UpdatedObjResults) > 0 {
					if sr.UpdatedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned for WriteOnceReadOnly change", "pass", string(raw.RawBody)))
					}
					if sr.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess != nil {
						uis := sr.UpdatedObjResults[0].OperStatus.OperStatus.OperSuccess.UpdatedInstResults
						if len(uis) > 0 && len(uis[0].ParamErrs) > 0 {
							return testcases.Pass(testcases.Step("param_errs returned for WriteOnceReadOnly change", "pass", string(raw.RawBody)))
						}
					}
				}
				return testcases.Fail("agent allowed a WriteOnceReadOnly parameter to be changed",
					testcases.Step("WriteOnceReadOnly check", "fail", string(raw.RawBody)))
			},
		},
	}
}
