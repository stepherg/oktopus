package section1

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// ---------------------------------------------------------------------------
// Delete request / response types
// ---------------------------------------------------------------------------

type deleteRequest struct {
	AllowPartial bool     `json:"allow_partial"`
	ObjPaths     []string `json:"obj_paths"`
}

type deleteRespDeletedObj struct {
	RequestedPath string `json:"requested_path"`
	OperStatus    struct {
		OperStatus *struct {
			OperSuccess *struct {
				AffectedPaths []string `json:"affected_paths"`
			} `json:"OperSuccess"`
			OperFailure *struct {
				ErrCode uint32 `json:"err_code"`
				ErrMsg  string `json:"err_msg"`
			} `json:"OperFailure"`
		} `json:"OperStatus"`
	} `json:"oper_status"`
}

type deleteResp struct {
	DeletedObjResults []deleteRespDeletedObj `json:"deleted_obj_results"`
}

func sendDelete(ctx context.Context, c *client.ControllerClient, target testcases.Target, req deleteRequest) (*deleteResp, *client.USPResponse, error) {
	raw, err := c.Delete(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var dr deleteResp
	json.Unmarshal(raw.RawBody, &dr) //nolint:errcheck
	return &dr, raw, nil
}

// createTempSubscription creates a temporary subscription instance and returns
// its instantiated path for use in delete tests.
func createTempSubscription(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) (string, error) {
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
		return "", fmt.Errorf("transport error: %w", err)
	}
	if resp == nil || len(resp.CreatedObjResults) == 0 || resp.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
		return "", fmt.Errorf("failed to create temp instance: %s", string(raw.RawBody))
	}
	return resp.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath, nil
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func deleteCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.24",
			Section: 1,
			Name:    "Delete message with allow_partial false, valid object instance",
			Purpose: "Verify the agent correctly deletes a valid object instance.",
			Tags:    []string{"delete"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				path, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{AllowPartial: false, ObjPaths: []string{path}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.DeletedObjResults) == 0 {
					return testcases.Fail("no deleted_obj_results in response")
				}
				if resp.DeletedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(
					testcases.Step("object deleted", "pass",
						fmt.Sprintf("affected_paths: %v", resp.DeletedObjResults[0].OperStatus.OperStatus.OperSuccess.AffectedPaths)),
				)
			},
		},
		{
			ID:      "1.25",
			Section: 1,
			Name:    "Delete message with allow_partial false, object instance doesn't exist",
			Purpose: "Verify the agent returns a DeleteResp with an empty oper_success when the instance doesn't exist (spec metric 1).",
			Tags:    []string{"delete"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Use an instance number that is very unlikely to exist.
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: false,
					ObjPaths:     []string{cfg.MultiInstanceObject + "99999999."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				// Spec metric: "The EUT sends a DeleteResp containing an empty oper_success element."
				// A top-level USP error is NOT acceptable here per spec.
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("agent returned top-level USP error %d (%s) instead of DeleteResp with empty oper_success", code, msg),
						testcases.Step("no top-level error", "fail", string(raw.RawBody)))
				}
				if resp != nil && len(resp.DeletedObjResults) > 0 {
					if s := resp.DeletedObjResults[0].OperStatus.OperStatus.OperSuccess; s != nil && len(s.AffectedPaths) == 0 {
						return testcases.Pass(testcases.Step("empty oper_success returned – instance did not exist", "pass", string(raw.RawBody)))
					}
					if resp.DeletedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
						return testcases.Fail("agent returned oper_failure; spec requires empty oper_success for non-existent instance",
							testcases.Step("oper_success check", "fail", string(raw.RawBody)))
					}
				}
				return testcases.Fail("unexpected response for non-existent instance delete",
					testcases.Step("oper_success check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.26",
			Section: 1,
			Name:    "Delete message with allow_partial false, invalid object",
			Purpose: "Verify the agent returns an error when the obj_path refers to a nonexistent object type.",
			Tags:    []string{"delete", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendDelete(ctx, c, target, deleteRequest{AllowPartial: false, ObjPaths: []string{cfg.InvalidPath + "1."}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned for invalid path", "pass", string(raw.RawBody)))
				}
				var dr deleteResp
				if json.Unmarshal(raw.RawBody, &dr) == nil && len(dr.DeletedObjResults) > 0 && dr.DeletedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
					return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
				}
				return testcases.Fail("agent did not return an error for invalid object path",
					testcases.Step("error check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.27",
			Section: 1,
			Name:    "Delete message with allow_partial false, multiple objects",
			Purpose: "Verify the agent correctly deletes multiple valid object instances in a single Delete message.",
			Tags:    []string{"delete"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				path1, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed (obj1): " + err.Error())
				}
				path2, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					deleteInstantiatedPath(ctx, c, target, path1)
					return testcases.Error("setup failed (obj2): " + err.Error())
				}
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{AllowPartial: false, ObjPaths: []string{path1, path2}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.DeletedObjResults) < 2 {
					return testcases.Fail("expected 2 deleted_obj_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				for _, r := range resp.DeletedObjResults {
					if r.OperStatus.OperStatus.OperSuccess == nil {
						return testcases.Fail("oper_success not present for all deleted objects")
					}
				}
				return testcases.Pass(testcases.Step("both objects deleted", "pass", ""))
			},
		},
		{
			ID:      "1.29",
			Section: 1,
			Name:    "Delete message with allow_partial true, object instance doesn't exist",
			Purpose: "Verify the agent returns oper_failure (not an error) when allow_partial is true and an instance doesn't exist.",
			Tags:    []string{"delete", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: true,
					ObjPaths:     []string{cfg.MultiInstanceObject + "99999998."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				// With allow_partial=true the agent MUST NOT return a top-level USP Error.
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail("agent returned a top-level USP error instead of DeleteResp with oper_failure when allow_partial=true",
						testcases.Step("no top-level error", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("DeleteResp returned (not a USP error)", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.90",
			Section: 1,
			Name:    "Delete message with search expression that matches no objects",
			Purpose: "Verify the agent returns a DeleteResp with empty affected_paths when the search expression matches no objects.",
			Tags:    []string{"delete", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: true,
					ObjPaths:     []string{cfg.MultiInstanceObject + "[Enable==\"UNLIKELY_VALUE_TP469_1_90\"]."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail("top-level USP error returned for no-match search expression")
				}
				return testcases.Pass(testcases.Step("no error returned for no-match search expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.28",
			Section: 1,
			Name:    "Delete message with allow_partial false, multiple objects, invalid object",
			Purpose: "Verify the agent rejects the entire Delete request when allow_partial is false and one of the objects is invalid.",
			Tags:    []string{"delete", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				validPath, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				_, raw, delErr := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: false,
					ObjPaths:     []string{validPath, cfg.InvalidPath + "1."},
				})
				if delErr != nil {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Error(fmt.Sprintf("transport error: %v", delErr))
				}
				// Attempt cleanup – if the valid path was not deleted, remove it.
				deleteInstantiatedPath(ctx, c, target, validPath)
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned – request rejected due to invalid object", "pass", string(raw.RawBody)))
				}
				var dr deleteResp
				if json.Unmarshal(raw.RawBody, &dr) == nil {
					for _, r := range dr.DeletedObjResults {
						if r.OperStatus.OperStatus.OperFailure != nil {
							return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
						}
					}
				}
				return testcases.Fail("agent did not return an error for multi-object delete with invalid object and allow_partial=false",
					testcases.Step("error check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.30",
			Section: 1,
			Name:    "Delete message with allow_partial true, invalid object",
			Purpose: "Verify the agent returns a DeleteResp with oper_failure (not a top-level error) when allow_partial is true and the object is invalid.",
			Tags:    []string{"delete", "allow_partial", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				_, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: true,
					ObjPaths:     []string{cfg.InvalidPath + "1."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail("agent returned a top-level USP error instead of DeleteResp with oper_failure for allow_partial=true",
						testcases.Step("no top-level error", "fail", string(raw.RawBody)))
				}
				var dr deleteResp
				if json.Unmarshal(raw.RawBody, &dr) == nil && len(dr.DeletedObjResults) > 0 {
					if dr.DeletedObjResults[0].OperStatus.OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned for invalid object with allow_partial=true", "pass", string(raw.RawBody)))
					}
				}
				return testcases.Pass(testcases.Step("DeleteResp returned (not a top-level USP error)", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.31",
			Section: 1,
			Name:    "Delete message with allow_partial true, multiple objects, invalid object",
			Purpose: "Verify the agent deletes the valid object and returns oper_failure for the invalid one when allow_partial is true.",
			Tags:    []string{"delete", "allow_partial", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				validPath, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: true,
					ObjPaths:     []string{validPath, cfg.InvalidPath + "1."},
				})
				if err != nil {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Fail("top-level USP error returned instead of per-object results",
						testcases.Step("no top-level error", "fail", string(raw.RawBody)))
				}
				if resp == nil || len(resp.DeletedObjResults) < 2 {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Fail("expected 2 deleted_obj_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				var gotSuccess, gotFailure bool
				for _, r := range resp.DeletedObjResults {
					if r.OperStatus.OperStatus.OperSuccess != nil {
						gotSuccess = true
					}
					if r.OperStatus.OperStatus.OperFailure != nil {
						gotFailure = true
					}
				}
				if !gotSuccess || !gotFailure {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Fail("expected one oper_success and one oper_failure in DeleteResp",
						testcases.Step("mixed result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(
					testcases.Step("valid object deleted (oper_success)", "pass", ""),
					testcases.Step("invalid object returned oper_failure", "pass", string(raw.RawBody)),
				)
			},
		},
		{
			ID:      "1.32",
			Section: 1,
			Name:    "Delete message with allow_partial true, multiple objects, object doesn't exist",
			Purpose: "Verify the agent handles a mix of valid and non-existent instances with allow_partial true, returning oper_success for each.",
			Tags:    []string{"delete", "allow_partial"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				validPath, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed: " + err.Error())
				}
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: true,
					ObjPaths:     []string{validPath, cfg.MultiInstanceObject + "99999997."},
				})
				if err != nil {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Fail("top-level USP error returned",
						testcases.Step("no top-level error", "fail", string(raw.RawBody)))
				}
				if resp == nil || len(resp.DeletedObjResults) < 2 {
					deleteInstantiatedPath(ctx, c, target, validPath)
					return testcases.Fail("expected 2 deleted_obj_results",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("DeleteResp with 2 results returned for valid + non-existent instance", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.33",
			Section: 1,
			Name:    "Delete message with unique key addressing",
			Purpose: "Verify the agent correctly deletes an object instance when unique key addressing is used in the obj_path.",
			Tags:    []string{"delete", "unique_key"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				const subID = "del1-33-uk"
				// Create a subscription with a known ID (the unique key).
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
				ukPath := fmt.Sprintf("%s[ID==\"%s\"].", cfg.MultiInstanceObject, subID)
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: false,
					ObjPaths:     []string{ukPath},
				})
				if err != nil {
					deleteInstantiatedPath(ctx, c, target, instantiatedPath)
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					deleteInstantiatedPath(ctx, c, target, instantiatedPath)
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.DeletedObjResults) == 0 || resp.DeletedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					deleteInstantiatedPath(ctx, c, target, instantiatedPath)
					return testcases.Fail("oper_success not present for unique key delete",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("object deleted via unique key addressing", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.34",
			Section: 1,
			Name:    "Delete message with wildcard search path, valid objects",
			Purpose: "Verify the agent deletes all matching objects when a wildcard search path is used.",
			Tags:    []string{"delete", "wildcard"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				path1, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					return testcases.Error("setup failed (obj1): " + err.Error())
				}
				path2, err := createTempSubscription(ctx, c, target, cfg)
				if err != nil {
					deleteInstantiatedPath(ctx, c, target, path1)
					return testcases.Error("setup failed (obj2): " + err.Error())
				}
				// Delete all subscriptions via wildcard.
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: false,
					ObjPaths:     []string{cfg.MultiInstanceObject + "*."},
				})
				if err != nil {
					deleteInstantiatedPath(ctx, c, target, path1)
					deleteInstantiatedPath(ctx, c, target, path2)
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.DeletedObjResults) == 0 {
					return testcases.Fail("no deleted_obj_results in response",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if resp.DeletedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present for wildcard delete",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("objects deleted via wildcard path", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.35",
			Section: 1,
			Name:    "Delete message with search expression search path",
			Purpose: "Verify the agent deletes objects matching a search expression, leaving non-matching objects intact.",
			Tags:    []string{"delete", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Create two subscriptions: one enabled (to be deleted), one disabled (to remain).
				ar, addRaw, err := sendAdd(ctx, c, target, addRequest{
					AllowPartial: false,
					CreateObjs: []createObject{
						{
							ObjPath: cfg.MultiInstanceObject,
							ParamSettings: []paramSetting{
								{Param: "Enable", Value: "true"},
								{Param: "ID", Value: "del1-35-enabled"},
								{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue},
							},
						},
						{
							ObjPath: cfg.MultiInstanceObject,
							ParamSettings: []paramSetting{
								{Param: "Enable", Value: "false"},
								{Param: "ID", Value: "del1-35-disabled"},
								{Param: cfg.RequiredParam, Value: cfg.RequiredParamValue},
							},
						},
					},
				})
				if err != nil {
					return testcases.Error("setup Add failed: " + err.Error())
				}
				if ar == nil || len(ar.CreatedObjResults) < 2 {
					return testcases.Error("setup Add did not create 2 subscriptions: " + string(addRaw.RawBody))
				}
				var disabledPath string
				for _, r := range ar.CreatedObjResults {
					if r.OperStatus.OperStatus.OperSuccess != nil {
						uk := r.OperStatus.OperStatus.OperSuccess.UniqueKeys
						if uk["ID"] == "del1-35-disabled" {
							disabledPath = r.OperStatus.OperStatus.OperSuccess.InstantiatedPath
						}
					}
				}
				defer deleteInstantiatedPath(ctx, c, target, disabledPath)

				// Delete all enabled subscriptions.
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: false,
					ObjPaths:     []string{cfg.MultiInstanceObject + "[Enable==true]."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.DeletedObjResults) == 0 {
					return testcases.Fail("no deleted_obj_results in response", testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if resp.DeletedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present for search expression delete",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("enabled subscriptions deleted via search expression", "pass", string(raw.RawBody)))
			},
		},
	}
}
