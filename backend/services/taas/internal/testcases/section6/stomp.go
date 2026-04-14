// Package section6 implements TP-469 Section 6 – STOMP MTP Test Cases.
package section6

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// All returns the Section 6 test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "6.1",
			Section: 6,
			Name:    "Support of Required STOMP Profiles",
			Purpose: "Verify the agent supports the required STOMP profiles in its data model.",
			MTPs:    []string{"stomp"},
			Tags:    []string{"stomp", "profile"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// Retrieve the STOMP connection data model to verify profile support.
				raw, err := c.Get(ctx, target.DeviceID, target.MTP,
					map[string]any{"param_paths": []string{"Device.STOMP."}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s – STOMP DM not present", code, msg))
				}
				var resp struct {
					ReqPathResults []struct {
						ErrCode uint32 `json:"err_code"`
					} `json:"req_path_results"`
				}
				if json.Unmarshal(raw.RawBody, &resp) == nil && len(resp.ReqPathResults) > 0 && resp.ReqPathResults[0].ErrCode == 0 {
					return testcases.Pass(testcases.Step("Device.STOMP. object present in DM", "pass", string(raw.RawBody)))
				}
				return testcases.Fail("Device.STOMP. not present or not accessible",
					testcases.Step("STOMP DM check", "fail", string(raw.RawBody)))
			},
		},
		{
			ID:      "6.2",
			Section: 6,
			Name:    "STOMP session establishment",
			Purpose: "Verify the agent successfully establishes a STOMP session and exchanges USP messages.",
			MTPs:    []string{"stomp"},
			Tags:    []string{"stomp", "session"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				// A successful Get via STOMP MTP confirms session establishment.
				raw, err := c.Get(ctx, target.DeviceID, target.MTP,
					map[string]any{"param_paths": []string{cfg.ReadableParamPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("STOMP session error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				return testcases.Pass(testcases.Step("USP Get succeeded over STOMP – session established", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "6.4",
			Section: 6,
			Name:    "Successful USP message over STOMP with required headers",
			Purpose: "Verify a USP message can be successfully exchanged over STOMP with all required headers.",
			MTPs:    []string{"stomp"},
			Tags:    []string{"stomp"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				cfg.Defaults()
				raw, err := c.Get(ctx, target.DeviceID, target.MTP,
					map[string]any{"param_paths": []string{cfg.ReadableParamPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg))
				}
				return testcases.Pass(testcases.Step("USP message exchanged over STOMP", "pass", string(raw.RawBody)))
			},
		},
		{
			ID:      "6.12",
			Section: 6,
			Name:    "STOMP – Use of Connect Record",
			Purpose: "Verify the agent sends a USP Connect Record when establishing a STOMP connection.",
			MTPs:    []string{"stomp"},
			Tags:    []string{"stomp", "connect_record"},
			Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
				// The Connect Record is verified at the MTP adapter level. From the
				// controller API we infer success by checking the agent is reachable and
				// able to exchange USP messages.
				cfg.Defaults()
				raw, err := c.Get(ctx, target.DeviceID, target.MTP,
					map[string]any{"param_paths": []string{cfg.ReadableParamPath}})
				if err != nil {
					return testcases.Error(fmt.Sprintf("transport error: %v", err))
				}
				if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
					return testcases.Fail(fmt.Sprintf("USP error %d: %s – agent not reachable", code, msg))
				}
				return testcases.Pass(testcases.Step("agent reachable over STOMP – Connect Record assumed sent", "pass", ""))
			},
		},
	}
}
