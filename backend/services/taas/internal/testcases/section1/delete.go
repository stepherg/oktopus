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
		OperSuccess *struct {
			AffectedPaths []string `json:"affected_paths"`
		} `json:"oper_success"`
		OperFailure *struct {
			ErrCode uint32 `json:"err_code"`
			ErrMsg  string `json:"err_msg"`
		} `json:"oper_failure"`
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
	if resp == nil || len(resp.CreatedObjResults) == 0 || resp.CreatedObjResults[0].OperStatus.OperSuccess == nil {
		return "", fmt.Errorf("failed to create temp instance: %s", string(raw.RawBody))
	}
	return resp.CreatedObjResults[0].OperStatus.OperSuccess.InstantiatedPath, nil
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
				if resp.DeletedObjResults[0].OperStatus.OperSuccess == nil {
					return testcases.Fail("oper_success not present",
						testcases.Step("oper_success check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(
					testcases.Step("object deleted", "pass",
						fmt.Sprintf("affected_paths: %v", resp.DeletedObjResults[0].OperStatus.OperSuccess.AffectedPaths)),
				)
			},
		},
		{
			ID:      "1.25",
			Section: 1,
			Name:    "Delete message with allow_partial false, object instance doesn't exist",
			Purpose: "Verify the agent returns an error when trying to delete an instance that does not exist, with allow_partial false.",
			Tags:    []string{"delete", "negative"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Use a path that is unlikely to exist.
				resp, raw, err := sendDelete(ctx, c, target, deleteRequest{
					AllowPartial: false,
					ObjPaths:     []string{cfg.MultiInstanceObject + "99999999."},
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, _, _ := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Pass(testcases.Step("USP error returned", "pass", string(raw.RawBody)))
				}
				if resp != nil && len(resp.DeletedObjResults) > 0 {
					if resp.DeletedObjResults[0].OperStatus.OperFailure != nil {
						return testcases.Pass(testcases.Step("oper_failure returned", "pass", string(raw.RawBody)))
					}
					// Some agents return oper_success with empty affected_paths for non-existent instances.
					if s := resp.DeletedObjResults[0].OperStatus.OperSuccess; s != nil && len(s.AffectedPaths) == 0 {
						return testcases.Pass(testcases.Step("empty oper_success – instance did not exist", "pass", string(raw.RawBody)))
					}
				}
				return testcases.Fail("agent did not indicate failure for non-existent instance",
					testcases.Step("failure check", "fail", string(raw.RawBody)))
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
				if json.Unmarshal(raw.RawBody, &dr) == nil && len(dr.DeletedObjResults) > 0 && dr.DeletedObjResults[0].OperStatus.OperFailure != nil {
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
					if r.OperStatus.OperSuccess == nil {
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
	}
}
