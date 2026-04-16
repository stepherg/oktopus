// Package section2 implements TP-469 Section 2 – USP Record Handling.
package section2

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// All returns the list of TP-469 Section 2 test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		{
			ID:      "2.1",
			Section: 2,
			Name:    "Agent does not accept messages from its own Endpoint ID",
			Run:     test2_1,
		},
		{
			ID:      "2.2",
			Section: 2,
			Name:    "Agent rejects messages that do not contain its to_id in the USP Record",
			Run:     test2_2,
		},
	}
}

// getRequest / getResp are minimal local copies of the Section 1 helpers needed
// to issue a USP GET and parse the result without importing the unexported types.
type s2GetRequest struct {
	ParamPaths []string `json:"param_paths"`
}

type s2GetResp struct {
	ReqPathResults []struct {
		ResolvedPathResults []struct {
			ResultParams map[string]string `json:"result_params"`
		} `json:"resolved_path_results"`
	} `json:"req_path_results"`
}

// test2_1 verifies that the agent ignores USP Records whose from_id equals the
// agent's own Endpoint ID (TP-469 §2.1).
//
// Steps:
//  1. GET Device.LocalAgent.EndpointID to learn the agent's own endpoint ID.
//  2. Send a GET with usp_from_id=<agent endpoint ID>.
//  3. The agent MUST NOT respond; the controller returns 504 after its timeout.
//  4. Pass if the response is non-200 (agent silently ignored the message).
func test2_1(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
	// Step 1: retrieve the agent's own Endpoint ID.
	raw, err := c.Get(ctx, target.DeviceID, target.MTP, s2GetRequest{
		ParamPaths: []string{"Device.LocalAgent.EndpointID"},
	})
	if err != nil {
		return testcases.Error("setup: GET Device.LocalAgent.EndpointID failed: " + err.Error())
	}
	var gr s2GetResp
	json.Unmarshal(raw.RawBody, &gr) //nolint:errcheck
	var agentEID string
	if len(gr.ReqPathResults) > 0 && len(gr.ReqPathResults[0].ResolvedPathResults) > 0 {
		agentEID = gr.ReqPathResults[0].ResolvedPathResults[0].ResultParams["EndpointID"]
	}
	if agentEID == "" {
		return testcases.Error("setup: could not extract Device.LocalAgent.EndpointID from response: " + string(raw.RawBody))
	}

	// Step 2 & 3: send a GET with from_id = agent's own EID.
	// The agent must not respond; the controller returns 504.
	resp, err := c.SendWithUSPOverrides(ctx, target.DeviceID, target.MTP, "get",
		s2GetRequest{ParamPaths: []string{"Device.LocalAgent.EndpointID"}},
		agentEID, "")
	if err != nil {
		// HTTP-level timeout from the client itself counts as "no response".
		return testcases.Pass(
			testcases.Step("agent ignored message with own from_id (client timeout)", "pass", err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		return testcases.Pass(
			testcases.Step("agent ignored message with own from_id", "pass",
				"controller returned non-200: "+http.StatusText(resp.StatusCode)))
	}
	return testcases.Fail("agent responded to a message whose from_id was its own Endpoint ID",
		testcases.Step("expect no response", "fail", string(resp.RawBody)))
}

// test2_2 verifies that the agent rejects USP Records whose to_id does not
// match its own Endpoint ID (TP-469 §2.2).
//
// Steps:
//  1. Send a GET with usp_to_id set to a bogus endpoint ID.
//  2. The agent MUST NOT process the message; the controller returns 504.
//  3. Pass if the response is non-200 (agent silently ignored the message).
func test2_2(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
	const bogusToID = "proto::wrong-endpoint-id-tp469-2-2"

	resp, err := c.SendWithUSPOverrides(ctx, target.DeviceID, target.MTP, "get",
		s2GetRequest{ParamPaths: []string{"Device.LocalAgent.EndpointID"}},
		"", bogusToID)
	if err != nil {
		return testcases.Pass(
			testcases.Step("agent ignored message with wrong to_id (client timeout)", "pass", err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		return testcases.Pass(
			testcases.Step("agent ignored message with wrong to_id", "pass",
				"controller returned non-200: "+http.StatusText(resp.StatusCode)))
	}
	return testcases.Fail("agent responded to a message whose to_id did not match its Endpoint ID",
		testcases.Step("expect no response", "fail", string(resp.RawBody)))
}
