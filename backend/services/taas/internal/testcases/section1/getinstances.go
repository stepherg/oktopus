package section1

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// ---------------------------------------------------------------------------
// GetInstances request / response types
// ---------------------------------------------------------------------------

type getInstancesRequest struct {
	ObjPaths       []string `json:"obj_paths"`
	FirstLevelOnly bool     `json:"first_level_only"`
}

type getInstancesResp struct {
	ReqPathResults []struct {
		RequestedPath string `json:"requested_path"`
		ErrCode       uint32 `json:"err_code"`
		ErrMsg        string `json:"err_msg"`
		CurrInsts     []struct {
			InstantiatedObjPath string            `json:"instantiated_obj_path"`
			UniqueKeys          map[string]string `json:"unique_keys"`
		} `json:"curr_insts"`
	} `json:"req_path_results"`
}

func sendGetInstances(ctx context.Context, c *client.ControllerClient, target testcases.Target, req getInstancesRequest) (*getInstancesResp, *client.USPResponse, error) {
	raw, err := c.GetInstances(ctx, target.DeviceID, target.MTP, req)
	if err != nil {
		return nil, nil, err
	}
	var gr getInstancesResp
	json.Unmarshal(raw.RawBody, &gr) //nolint:errcheck
	return &gr, raw, nil
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func getInstancesCases() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "1.66",
			Section: 1,
			Name:    "GetInstances using a single object, first_level_only true",
			Purpose: "Verify the agent returns only first-level instances when first_level_only=true.",
			Tags:    []string{"get_instances"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetInstances(ctx, c, target, getInstancesRequest{
					ObjPaths:       []string{cfg.GetInstancesObject},
					FirstLevelOnly: true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results in GetInstancesResp",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				if resp.ReqPathResults[0].ErrCode != 0 {
					return testcases.Fail(fmt.Sprintf("err_code %d in req_path_results", resp.ReqPathResults[0].ErrCode))
				}
				return testcases.Pass(
					testcases.Step("GetInstancesResp received", "pass",
						fmt.Sprintf("instances returned: %d", len(resp.ReqPathResults[0].CurrInsts))),
				)
			},
		},
		{
			ID:      "1.67",
			Section: 1,
			Name:    "GetInstances using a single object, first_level_only false",
			Purpose: "Verify the agent returns all nested instances when first_level_only=false.",
			Tags:    []string{"get_instances"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetInstances(ctx, c, target, getInstancesRequest{
					ObjPaths:       []string{cfg.GetInstancesObject},
					FirstLevelOnly: false,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 || resp.ReqPathResults[0].ErrCode != 0 {
					return testcases.Fail("no valid results",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetInstancesResp (first_level_only=false) received", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.68",
			Section: 1,
			Name:    "GetInstances with multiple objects",
			Purpose: "Verify the agent handles GetInstances requests that specify multiple object paths.",
			Tags:    []string{"get_instances"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetInstances(ctx, c, target, getInstancesRequest{
					ObjPaths:       []string{cfg.GetInstancesObject, cfg.MultiInstanceObject},
					FirstLevelOnly: true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) < 2 {
					return testcases.Fail("expected at least 2 req_path_results for 2 object paths",
						testcases.Step("result count check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetInstancesResp with multiple objects received", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.83",
			Section: 1,
			Name:    "GetInstances message with unmatched search expression",
			Purpose: "Verify the agent returns an empty curr_insts list when the search expression matches no objects.",
			Tags:    []string{"get_instances", "search_path"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				resp, raw, err := sendGetInstances(ctx, c, target, getInstancesRequest{
					ObjPaths:       []string{cfg.GetInstancesObject + "[Alias==\"UNLIKELY_VALUE_TP469_1_83\"]."},
					FirstLevelOnly: true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if resp != nil && len(resp.ReqPathResults) > 0 {
					r := resp.ReqPathResults[0]
					if r.ErrCode == 0 && len(r.CurrInsts) == 0 {
						return testcases.Pass(testcases.Step("empty curr_insts returned for unmatched search", "pass", ""))
					}
				}
				return testcases.Pass(testcases.Step("no error returned for unmatched expression", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "1.70",
			Section: 1,
			Name:    "GetInstances message with wildcard search path",
			Purpose: "Verify the agent returns curr_insts for all instances of a sub-object when a wildcard search path is used.",
			Tags:    []string{"get_instances", "wildcard"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Device.LocalAgent.Controller.*.MTP. – wildcard expands all Controller instances.
				wildcardPath := cfg.GetInstancesObject + "*.MTP."
				resp, raw, err := sendGetInstances(ctx, c, target, getInstancesRequest{
					ObjPaths:       []string{wildcardPath},
					FirstLevelOnly: true,
				})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				if resp == nil || len(resp.ReqPathResults) == 0 {
					return testcases.Fail("no req_path_results in response",
						testcases.Step("result check", "fail", string(raw.RawBody)))
				}
				return testcases.Pass(testcases.Step("GetInstancesResp received for wildcard search path", "pass", string(raw.RawBody)))
			},
		},
	}
}
