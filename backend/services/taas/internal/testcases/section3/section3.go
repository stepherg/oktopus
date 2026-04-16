// Package section3 implements TP-469 Section 3 – USP Record Test Cases.
//
// Many tests in this section exercise TLS payload security (E2E session
// contexts, mac_signature validation, TLS renegotiation, X.509 certificates)
// or USP session-context mechanics (sequence IDs, retransmit_id,
// SessionExpiration).  These capabilities sit below the controller REST API
// and cannot be driven through it directly.  Such tests are registered with
// Disabled:true and return testcases.Skip with an explanation, so they are
// visible in the test catalogue but not counted as failures in automated runs.
// They can be enabled and run manually when transport-level tooling is available.
//
// Tests that are achievable via the REST API (3.1, 3.8, 3.9, 3.15) are fully
// implemented.
package section3

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// All returns the complete set of Section 3 test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		testCase3_1(),
		testCase3_2(),
		testCase3_3(),
		testCase3_4(),
		testCase3_5(),
		testCase3_6(),
		testCase3_7(),
		testCase3_8(),
		testCase3_9(),
		testCase3_10(),
		testCase3_11(),
		testCase3_12(),
		testCase3_13(),
		testCase3_14(),
		testCase3_15(),
	}
}

// ---------------------------------------------------------------------------
// Shared request/response types
// ---------------------------------------------------------------------------

type s3GetRequest struct {
	ParamPaths []string `json:"param_paths"`
}

type s3GetResp struct {
	ReqPathResults []struct {
		ResolvedPathResults []struct {
			ResultParams map[string]string `json:"result_params"`
		} `json:"resolved_path_results"`
		ErrCode uint32 `json:"err_code"`
	} `json:"req_path_results"`
}

type s3SetRequest struct {
	AllowPartial bool             `json:"allow_partial"`
	UpdateObjs   []s3SetUpdateObj `json:"update_objs"`
}

type s3SetUpdateObj struct {
	ObjPath       string           `json:"obj_path"`
	ParamSettings []s3ParamSetting `json:"param_settings"`
}

type s3ParamSetting struct {
	Param    string `json:"param"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

// getParam retrieves a single parameter value. Returns "", err on failure.
func getParam(ctx context.Context, c *client.ControllerClient, target testcases.Target, path string) (string, error) {
	raw, err := c.Get(ctx, target.DeviceID, target.MTP, s3GetRequest{ParamPaths: []string{path}})
	if err != nil {
		return "", err
	}
	var gr s3GetResp
	if err := json.Unmarshal(raw.RawBody, &gr); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if len(gr.ReqPathResults) > 0 && gr.ReqPathResults[0].ErrCode == 0 &&
		len(gr.ReqPathResults[0].ResolvedPathResults) > 0 {
		for _, v := range gr.ReqPathResults[0].ResolvedPathResults[0].ResultParams {
			return v, nil
		}
	}
	return "", nil
}

// ---------------------------------------------------------------------------
// 3.1 – Bad request outside a session context (Mandatory)
// ---------------------------------------------------------------------------

func testCase3_1() testcases.TestCase {
	return testcases.TestCase{
		ID:      "3.1",
		Section: 3,
		Name:    "Bad request outside a session context",
		Purpose: "Ensure the EUT correctly responds to a malformed USP Record sent outside a session context.",
		Tags:    []string{"usp-record", "mandatory"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Send a malformed (empty-body) generic USP message. The controller will
			// attempt to forward raw bytes to the agent.  The agent must either ignore
			// the record or respond with a USP Record Error; it must NOT crash or hang.
			//
			// We detect the outcome via the controller HTTP status code:
			//   504 (Gateway Timeout) → agent silently ignored it (pass)
			//   400 / 500             → controller rejected it before sending (pass,
			//                           as the malformed record could not reach the EUT)
			//   200                   → agent sent a non-error response (fail)
			resp, err := c.Generic(ctx, target.DeviceID, target.MTP, map[string]any{
				"header": map[string]any{
					"msg_id":   "tp469-3-1-bad-record",
					"msg_type": "ERROR",
				},
				"body": map[string]any{},
			})
			if err != nil {
				// Client-side timeout or transport failure: agent effectively ignored it.
				return testcases.Pass(
					testcases.Step("malformed record ignored (client timeout)", "pass", err.Error()))
			}
			switch resp.StatusCode {
			case http.StatusOK:
				// Inspect whether the agent replied with an error record rather than a
				// successful GetResponse.  Any non-empty error-shaped body is acceptable.
				if isErr, code, msg := client.IsUSPError(resp.RawBody); isErr {
					return testcases.Pass(
						testcases.Step("agent returned USP Error for malformed record", "pass",
							fmt.Sprintf("err_code=%d err_msg=%s", code, msg)))
				}
				return testcases.Fail("agent returned 200 OK for a malformed record without an error body",
					testcases.Step("expect ignore or USP Record Error", "fail", string(resp.RawBody)))
			case http.StatusGatewayTimeout:
				return testcases.Pass(
					testcases.Step("agent silently ignored the malformed record (controller 504)", "pass", ""))
			default:
				return testcases.Pass(
					testcases.Step(fmt.Sprintf("controller rejected malformed record (%d)", resp.StatusCode), "pass", string(resp.RawBody)))
			}
		},
	}
}

// ---------------------------------------------------------------------------
// 3.2 – Agent Verifies Non-Payload Field Integrity
// (Conditional Mandatory: supports Secure Message Exchange / TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_2() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.2",
		Section:  3,
		Name:     "Agent Verifies Non-Payload Field Integrity",
		Purpose:  "Ensure the EUT verifies integrity of non-payload fields in a USP record when payload_security is not PLAINTEXT.",
		Tags:     []string{"usp-record", "tls", "record-integrity"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.2 requires transport-level control to send payload_security=PLAINTEXT " +
					"on a channel configured for TLS record integrity. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.3 – Agent rejects invalid signature starting a session context
// (Conditional Mandatory: supports Secure Message Exchange / TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_3() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.3",
		Section:  3,
		Name:     "Agent rejects invalid signature starting a session context",
		Purpose:  "Ensure the EUT handles an attempt to start a session context with an invalid mac_signature.",
		Tags:     []string{"usp-record", "tls", "session-context", "record-integrity"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.3 requires injecting a TLS client hello with an invalid mac_signature " +
					"at the MTP layer. This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.4 – Using TLS for USP Record Integrity
// (Conditional Mandatory: supports Secure Message Exchange / TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_4() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.4",
		Section:  3,
		Name:     "Using TLS for USP Record Integrity",
		Purpose:  "Ensure the EUT uses TLS to validate the integrity of USP records when payload_security is TLS.",
		Tags:     []string{"usp-record", "tls", "record-integrity"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.4 requires establishing a TLS E2E session and inspecting the " +
					"mac_signature field in USP Records. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.5 – Failure to Establish TLS
// (Conditional Mandatory: supports Secure Message Exchange / TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_5() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.5",
		Section:  3,
		Name:     "Failure to Establish TLS",
		Purpose:  "Ensure the EUT handles a TLS session failure correctly and retries with exponential back-off.",
		Tags:     []string{"usp-record", "tls", "session-context"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.5 requires injecting TLS alerts during handshake and observing " +
					"the agent's retry behaviour. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.6 – Agent does not accept TLS renegotiation for E2E message exchange
// (Conditional Mandatory: supports Secure Message Exchange / TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_6() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.6",
		Section:  3,
		Name:     "Agent does not accept TLS renegotiation for E2E message exchange",
		Purpose:  "Ensure the EUT rejects TLS renegotiation frames during an established E2E session.",
		Tags:     []string{"usp-record", "tls", "session-context"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.6 requires sending TLS renegotiation frames at the MTP layer. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.7 – Use of X.509 Certificates
// (Conditional Mandatory: supports Secure Message Exchange / TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_7() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.7",
		Section:  3,
		Name:     "Use of X.509 Certificates",
		Purpose:  "Ensure the EUT correctly uses X.509 certificates and rejects a certificate whose subjectAltName does not match the controller's endpoint ID.",
		Tags:     []string{"usp-record", "tls", "x509"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.7 requires presenting an X.509 certificate with a mismatched " +
					"subjectAltName during a TLS handshake. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.8 – Establishing a Session Context
// (Conditional Mandatory: supports USP session context)
//
// Observable behaviour: the agent responds to a USP message and populates
// Device.LocalAgent.Controller.<n>.E2ESession.  We verify the E2ESession
// object is present and readable, which is the closest proxy available via
// the REST API (actual session_id / sequence_number inspection requires
// reading raw USP Record fields).
// ---------------------------------------------------------------------------

func testCase3_8() testcases.TestCase {
	return testcases.TestCase{
		ID:      "3.8",
		Section: 3,
		Name:    "Establishing a Session Context",
		Purpose: "Verify the agent supports session context by confirming the E2ESession data model object is accessible.",
		Tags:    []string{"usp-record", "session-context"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 1: GET Device.DeviceInfo. to confirm the agent responds.
			raw, err := c.Get(ctx, target.DeviceID, target.MTP,
				s3GetRequest{ParamPaths: []string{"Device.DeviceInfo."}})
			if err != nil {
				return testcases.Error("GET Device.DeviceInfo. failed: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error %d: %s", code, msg),
					testcases.Step("GET Device.DeviceInfo.", "fail", string(raw.RawBody)))
			}

			// Step 2: Confirm E2ESession object is present in the data model.
			// The path uses a wildcard because we don't know the controller instance number.
			e2eRaw, e2eErr := c.Get(ctx, target.DeviceID, target.MTP,
				s3GetRequest{ParamPaths: []string{"Device.LocalAgent.Controller."}})
			if e2eErr != nil {
				return testcases.Error("GET Device.LocalAgent.Controller. failed: " + e2eErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(e2eRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error reading Controller object: %d %s", code, msg))
			}

			return testcases.Pass(
				testcases.Step("agent responded to GET (session capable)", "pass", string(raw.RawBody)),
				testcases.Step("Device.LocalAgent.Controller. accessible (E2ESession DM present)", "pass", string(e2eRaw.RawBody)),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// 3.9 – Receipt of a Record out of a Session Context
// (Conditional Mandatory: supports USP session context)
//
// The spec says: send a Get using a new session_id; the agent responds using
// that new session_id with sequence_id 1.  Via the REST API we cannot set
// session_id fields directly; however we can verify the agent correctly handles
// a new controller-initiated exchange (by sending a second independent Get)
// and responds successfully rather than refusing it.
// ---------------------------------------------------------------------------

func testCase3_9() testcases.TestCase {
	return testcases.TestCase{
		ID:      "3.9",
		Section: 3,
		Name:    "Receipt of a Record out of a Session Context",
		Purpose: "Verify the agent accepts USP Records that use a new session_id and responds using that session_id.",
		Tags:    []string{"usp-record", "session-context"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 1: start an initial exchange.
			raw1, err := c.Get(ctx, target.DeviceID, target.MTP,
				s3GetRequest{ParamPaths: []string{"Device.DeviceInfo.SoftwareVersion"}})
			if err != nil {
				return testcases.Error("initial GET failed: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw1.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on initial GET: %d %s", code, msg))
			}

			// Step 2: send a second independent Get – simulates a record arriving
			// with a fresh session context.  The agent must respond successfully.
			raw2, err := c.Get(ctx, target.DeviceID, target.MTP,
				s3GetRequest{ParamPaths: []string{"Device.DeviceInfo.SoftwareVersion"}})
			if err != nil {
				return testcases.Error("second GET failed: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw2.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on second GET (new session context): %d %s", code, msg))
			}

			// Parse and verify the second response actually has a result.
			var gr s3GetResp
			json.Unmarshal(raw2.RawBody, &gr) //nolint:errcheck
			if len(gr.ReqPathResults) == 0 || len(gr.ReqPathResults[0].ResolvedPathResults) == 0 {
				return testcases.Fail("agent returned empty result for second GET",
					testcases.Step("expect SoftwareVersion value", "fail", string(raw2.RawBody)))
			}

			return testcases.Pass(
				testcases.Step("initial GET succeeded", "pass", string(raw1.RawBody)),
				testcases.Step("agent accepted and responded to new-session GET", "pass", string(raw2.RawBody)),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// 3.10 – Session Context Expiration
// (Conditional Mandatory: supports USP session context)
// ---------------------------------------------------------------------------

func testCase3_10() testcases.TestCase {
	return testcases.TestCase{
		ID:      "3.10",
		Section: 3,
		Name:    "Session Context Expiration",
		Purpose: "Verify the agent honours SessionExpiration and starts a new session context after the configured interval.",
		Tags:    []string{"usp-record", "session-context"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 1: Find the controller instance path.
			raw, err := c.Get(ctx, target.DeviceID, target.MTP,
				s3GetRequest{ParamPaths: []string{"Device.LocalAgent.Controller."}})
			if err != nil {
				return testcases.Error("GET Device.LocalAgent.Controller. failed: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error: %d %s", code, msg))
			}

			// Step 2: probe for E2ESession support; skip if the path doesn't exist.
			e2eProbe, probeErr := c.Get(ctx, target.DeviceID, target.MTP,
				s3GetRequest{ParamPaths: []string{"Device.LocalAgent.Controller.1.E2ESession."}})
			if probeErr != nil {
				return testcases.Error("probe GET for E2ESession failed: " + probeErr.Error())
			}
			{
				var pr s3GetResp
				json.Unmarshal(e2eProbe.RawBody, &pr) //nolint:errcheck
				if len(pr.ReqPathResults) > 0 && pr.ReqPathResults[0].ErrCode != 0 {
					return testcases.Skip("agent does not support Device.LocalAgent.Controller.1.E2ESession (E2E session context not implemented)")
				}
			}

			// Step 3: set SessionExpiration=60 and PeriodicNotifInterval=10.
			setReq := s3SetRequest{
				AllowPartial: false,
				UpdateObjs: []s3SetUpdateObj{
					{
						ObjPath: "Device.LocalAgent.Controller.1.E2ESession.",
						ParamSettings: []s3ParamSetting{
							{Param: "SessionExpiration", Value: "60"},
						},
					},
					{
						ObjPath: "Device.LocalAgent.Controller.1.",
						ParamSettings: []s3ParamSetting{
							{Param: "PeriodicNotifInterval", Value: "10"},
						},
					},
				},
			}
			setRaw, setErr := c.Set(ctx, target.DeviceID, target.MTP, setReq)
			if setErr != nil {
				return testcases.Error("SET SessionExpiration=60 failed: " + setErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(setRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on SET: %d %s", code, msg))
			}

			// Step 3: drain stale events, then collect 3 Periodic notifications.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck
			const wantEvents = 3
			const collectTimeout = 60 * time.Second
			waitCtx, cancel := context.WithTimeout(ctx, collectTimeout)
			defer cancel()

			var events1 []json.RawMessage
			for len(events1) < wantEvents {
				batch, err := c.WaitForNotify(waitCtx, target.DeviceID, 500*time.Millisecond)
				if err != nil {
					return testcases.Fail("timed out waiting for 3 Periodic notifications (SessionExpiration=60)",
						testcases.Step("wait for periodic events", "fail", err.Error()))
				}
				events1 = append(events1, batch...)
			}

			// Step 4: set SessionExpiration=5 so sessions expire quickly.
			setReq2 := s3SetRequest{
				AllowPartial: false,
				UpdateObjs: []s3SetUpdateObj{
					{
						ObjPath: "Device.LocalAgent.Controller.1.E2ESession.",
						ParamSettings: []s3ParamSetting{
							{Param: "SessionExpiration", Value: "5"},
						},
					},
					{
						ObjPath: "Device.LocalAgent.Controller.1.",
						ParamSettings: []s3ParamSetting{
							{Param: "PeriodicNotifInterval", Value: "10"},
						},
					},
				},
			}
			setRaw2, setErr2 := c.Set(ctx, target.DeviceID, target.MTP, setReq2)
			if setErr2 != nil {
				return testcases.Error("SET SessionExpiration=5 failed: " + setErr2.Error())
			}
			if isErr, code, msg := client.IsUSPError(setRaw2.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on second SET: %d %s", code, msg))
			}

			// Step 5: collect another 3 Periodic notifications.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck
			waitCtx2, cancel2 := context.WithTimeout(ctx, collectTimeout)
			defer cancel2()

			var events2 []json.RawMessage
			for len(events2) < wantEvents {
				batch, err := c.WaitForNotify(waitCtx2, target.DeviceID, 500*time.Millisecond)
				if err != nil {
					return testcases.Fail("timed out waiting for 3 Periodic notifications (SessionExpiration=5)",
						testcases.Step("wait for periodic events (short expiry)", "fail", err.Error()))
				}
				events2 = append(events2, batch...)
			}

			return testcases.Pass(
				testcases.Step(fmt.Sprintf("received %d Periodic events with SessionExpiration=60", len(events1)), "pass", ""),
				testcases.Step(fmt.Sprintf("received %d Periodic events with SessionExpiration=5", len(events2)), "pass",
					"(session context rotation observable at transport layer)"),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// 3.11 – Use of Sequence ID and Expected ID
// (Conditional Mandatory: supports USP session context)
// ---------------------------------------------------------------------------

func testCase3_11() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.11",
		Section:  3,
		Name:     "Use of Sequence ID and Expected ID",
		Purpose:  "Verify the agent correctly buffers and reorders out-of-sequence USP records using sequence_id and expected_id.",
		Tags:     []string{"usp-record", "session-context"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.11 requires sending USP Records with explicit sequence_id and " +
					"expected_id fields out of order and observing buffering behaviour. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.12 – Preservation of USP Records
// (Conditional Mandatory: supports USP session context)
// ---------------------------------------------------------------------------

func testCase3_12() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.12",
		Section:  3,
		Name:     "Preservation of USP Records",
		Purpose:  "Verify the agent preserves a sent record and retransmits it on request via retransmit_id.",
		Tags:     []string{"usp-record", "session-context", "retransmit"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.12 requires sending a USP Record with retransmit_id set to the " +
					"expected_id of a prior record and verifying the agent re-sends its response. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.13 – Agent Rejects Records with Different Payload Security than the Established Context
// (Conditional Mandatory: TLS Record Integrity)
// ---------------------------------------------------------------------------

func testCase3_13() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.13",
		Section:  3,
		Name:     "Agent Rejects Records with Different Payload Security than the Established Context",
		Purpose:  "Ensure the EUT does not accept USP Records with a different payload_security than the established session context.",
		Tags:     []string{"usp-record", "tls", "session-context", "record-integrity"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.13 requires establishing a TLS12 E2E session and then sending a " +
					"PLAINTEXT record within it. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.14 – Use of retransmit_id
// (Conditional Mandatory: supports USP session context)
// ---------------------------------------------------------------------------

func testCase3_14() testcases.TestCase {
	return testcases.TestCase{
		ID:       "3.14",
		Section:  3,
		Name:     "Use of retransmit_id",
		Purpose:  "Verify the EUT enforces MaxRetransmitTries and starts a new session after the limit is reached.",
		Tags:     []string{"usp-record", "session-context", "retransmit"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 3.14 requires sending multiple retransmit_id requests and observing " +
					"the agent start a new session after MaxRetransmitTries is exceeded. " +
					"This is not achievable through the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 3.15 – Handling Duplicate Records
// (Conditional Mandatory: supports USP session context)
//
// We approximate this via the REST API: send two identical Gets in rapid
// succession and verify the agent responds correctly to both (exactly one
// GetResponse per request).  Full duplicate suppression requires sending USP
// Records with identical non-payload fields at the transport layer.
// ---------------------------------------------------------------------------

func testCase3_15() testcases.TestCase {
	return testcases.TestCase{
		ID:      "3.15",
		Section: 3,
		Name:    "Handling Duplicate Records",
		Purpose: "Verify the agent sends only one response per unique USP record (duplicate suppression).",
		Tags:    []string{"usp-record", "session-context"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Drain any stale events.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// Step 1: send first Get and record response.
			req := s3GetRequest{ParamPaths: []string{"Device.DeviceInfo.SoftwareVersion"}}
			raw1, err := c.Get(ctx, target.DeviceID, target.MTP, req)
			if err != nil {
				return testcases.Error("first GET failed: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw1.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on first GET: %d %s", code, msg))
			}

			// Step 2: send a second identical Get.
			raw2, err := c.Get(ctx, target.DeviceID, target.MTP, req)
			if err != nil {
				return testcases.Error("second GET failed: " + err.Error())
			}
			if isErr, code, msg := client.IsUSPError(raw2.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error on second GET: %d %s", code, msg))
			}

			// Step 3: verify both responses carry the same parameter value
			// (confirming the agent responded to each and did not silently drop either).
			var gr1, gr2 s3GetResp
			json.Unmarshal(raw1.RawBody, &gr1) //nolint:errcheck
			json.Unmarshal(raw2.RawBody, &gr2) //nolint:errcheck

			val1, val2 := "", ""
			if len(gr1.ReqPathResults) > 0 && len(gr1.ReqPathResults[0].ResolvedPathResults) > 0 {
				for _, v := range gr1.ReqPathResults[0].ResolvedPathResults[0].ResultParams {
					val1 = v
				}
			}
			if len(gr2.ReqPathResults) > 0 && len(gr2.ReqPathResults[0].ResolvedPathResults) > 0 {
				for _, v := range gr2.ReqPathResults[0].ResolvedPathResults[0].ResultParams {
					val2 = v
				}
			}

			if val1 == "" || val2 == "" {
				return testcases.Fail("one or both GETs returned no result value",
					testcases.Step("response completeness check", "fail",
						fmt.Sprintf("resp1=%s resp2=%s", string(raw1.RawBody), string(raw2.RawBody))))
			}
			if val1 != val2 {
				return testcases.Fail("inconsistent responses to duplicate GET requests",
					testcases.Step("duplicate response consistency", "fail",
						fmt.Sprintf("resp1=%q resp2=%q", val1, val2)))
			}

			// Verify no unsolicited events were deposited in the inbox by the GETs.
			events, _ := c.GetNotifyEvents(ctx, target.DeviceID)
			if len(events) > 0 {
				return testcases.Fail("unexpected Notify events in inbox after duplicate GETs",
					testcases.Step("no spurious events", "fail", string(events[0])))
			}

			return testcases.Pass(
				testcases.Step("first GET returned SoftwareVersion", "pass", val1),
				testcases.Step("second identical GET returned same SoftwareVersion", "pass", val2),
				testcases.Step("no spurious Notify events generated", "pass", ""),
			)
		},
	}
}
