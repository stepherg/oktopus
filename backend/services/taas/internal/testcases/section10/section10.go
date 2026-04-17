// Package section10 implements TP-469 Section 10 – Bulk Data Collection Test Cases.
//
// Tests 10.1–10.9 require an external HTTP/HTTPS server that receives and
// validates BulkData POSTs from the EUT. These are registered with
// Disabled:true because the controller REST API cannot receive/inspect HTTP
// payloads from the agent's perspective.
//
// Tests 10.10–10.12 use the USPEventNotif protocol (Protocol=USPEventNotif),
// which delivers bulk data via a USP Push! event notification back to the
// controller. These CAN be automated and are fully enabled.
//
// Test 10.13 requires a dedicated MQTT endpoint and is disabled.
package section10

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// All returns the complete set of Section 10 test cases.
func All() []testcases.TestCase {
	return []testcases.TestCase{
		testCase10_1(),
		testCase10_2(),
		testCase10_3(),
		testCase10_4(),
		testCase10_5(),
		testCase10_6(),
		testCase10_7(),
		testCase10_8(),
		testCase10_9(),
		testCase10_10(),
		testCase10_11(),
		testCase10_12(),
		testCase10_13(),
	}
}

// ---------------------------------------------------------------------------
// Shared request / response types
// ---------------------------------------------------------------------------

type s10ParamSetting struct {
	Param    string `json:"param"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type s10CreateObj struct {
	ObjPath       string            `json:"obj_path"`
	ParamSettings []s10ParamSetting `json:"param_settings"`
}

type s10AddReq struct {
	AllowPartial bool           `json:"allow_partial"`
	CreateObjs   []s10CreateObj `json:"create_objs"`
}

type s10AddResp struct {
	CreatedObjResults []struct {
		RequestedPath string `json:"requested_path"`
		OperStatus    struct {
			OperStatus struct {
				OperSuccess *struct {
					InstantiatedPath string `json:"instantiated_path"`
				} `json:"OperSuccess"`
				OperFailure *struct {
					ErrCode uint32 `json:"err_code"`
					ErrMsg  string `json:"err_msg"`
				} `json:"OperFailure"`
			} `json:"OperStatus"`
		} `json:"oper_status"`
	} `json:"created_obj_results"`
}

type s10UpdateObj struct {
	ObjPath       string            `json:"obj_path"`
	ParamSettings []s10ParamSetting `json:"param_settings"`
}

type s10SetReq struct {
	AllowPartial bool           `json:"allow_partial"`
	UpdateObjs   []s10UpdateObj `json:"update_objs"`
}

type s10DelReq struct {
	AllowPartial bool     `json:"allow_partial"`
	ObjPaths     []string `json:"obj_paths"`
}

type s10GetReq struct {
	ParamPaths []string `json:"param_paths"`
}

type s10GetResp struct {
	ReqPathResults []struct {
		ResolvedPathResults []struct {
			ResolvedPath string            `json:"resolved_path"`
			ResultParams map[string]string `json:"result_params"`
		} `json:"resolved_path_results"`
		ErrCode uint32 `json:"err_code"`
		ErrMsg  string `json:"err_msg"`
	} `json:"req_path_results"`
}

// s10Notify is the unmarshalled shape of an agent-initiated Notify message.
type s10Notify struct {
	SubscriptionId string `json:"subscriptionId"`
	Event          *struct {
		ObjPath   string            `json:"objPath"`
		EventName string            `json:"eventName"`
		Params    map[string]string `json:"params"`
	} `json:"event"`
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// s10AddSubscription creates a Subscription object and returns its instantiated path.
func s10AddSubscription(ctx context.Context, c *client.ControllerClient, target testcases.Target,
	notifType, refList, id string) (string, *client.USPResponse, error) {
	raw, err := c.Add(ctx, target.DeviceID, target.MTP, s10AddReq{
		AllowPartial: false,
		CreateObjs: []s10CreateObj{{
			ObjPath: "Device.LocalAgent.Subscription.",
			ParamSettings: []s10ParamSetting{
				{Param: "Enable", Value: "true"},
				{Param: "NotifType", Value: notifType},
				{Param: "ReferenceList", Value: refList},
				{Param: "ID", Value: id},
			},
		}},
	})
	if err != nil {
		return "", nil, err
	}
	var ar s10AddResp
	json.Unmarshal(raw.RawBody, &ar) //nolint:errcheck
	if len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
		return "", raw, fmt.Errorf("add subscription failed: %s", string(raw.RawBody))
	}
	return ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath, raw, nil
}

// s10Delete deletes a path (best-effort; errors are silently ignored).
func s10Delete(ctx context.Context, c *client.ControllerClient, target testcases.Target, path string) {
	c.Delete(ctx, target.DeviceID, target.MTP, s10DelReq{ //nolint:errcheck
		AllowPartial: true,
		ObjPaths:     []string{path},
	})
}

// s10MinReportingInterval GETs Device.BulkData.MinReportingInterval and returns
// max(60, minInterval). If the param is unreadable, 60 is returned.
func s10MinReportingInterval(ctx context.Context, c *client.ControllerClient, target testcases.Target) int {
	raw, err := c.Get(ctx, target.DeviceID, target.MTP, s10GetReq{
		ParamPaths: []string{"Device.BulkData.MinReportingInterval"},
	})
	if err != nil {
		return 60
	}
	var gr s10GetResp
	if err := json.Unmarshal(raw.RawBody, &gr); err != nil {
		return 60
	}
	for _, rpr := range gr.ReqPathResults {
		for _, resolved := range rpr.ResolvedPathResults {
			if v, ok := resolved.ResultParams["MinReportingInterval"]; ok {
				if n, err := strconv.Atoi(v); err == nil && n > 60 {
					return n
				}
			}
		}
	}
	return 60
}

// s10ProbeBulkData checks if Device.BulkData.Protocols is readable. Returns
// the value (e.g. "HTTP,USPEventNotif") and a bool indicating reachability.
func s10ProbeBulkData(ctx context.Context, c *client.ControllerClient, target testcases.Target) (string, bool) {
	raw, err := c.Get(ctx, target.DeviceID, target.MTP, s10GetReq{
		ParamPaths: []string{"Device.BulkData.Protocols"},
	})
	if err != nil {
		return "", false
	}
	if isErr, code, _ := client.IsUSPError(raw.RawBody); isErr && code == 7026 {
		return "", false // path not in schema
	}
	var gr s10GetResp
	if err := json.Unmarshal(raw.RawBody, &gr); err != nil {
		return "", false
	}
	for _, rpr := range gr.ReqPathResults {
		for _, resolved := range rpr.ResolvedPathResults {
			if v, ok := resolved.ResultParams["Protocols"]; ok {
				return v, true
			}
		}
	}
	return "", false
}

// s10AddBulkDataProfile creates a BulkData.Profile. object and returns its instantiated path.
func s10AddBulkDataProfile(ctx context.Context, c *client.ControllerClient, target testcases.Target,
	protocol, encodingType string, reportingInterval int, extra []s10ParamSetting) (string, *client.USPResponse, error) {
	settings := []s10ParamSetting{
		{Param: "Protocol", Value: protocol},
		{Param: "EncodingType", Value: encodingType},
		{Param: "ReportingInterval", Value: strconv.Itoa(reportingInterval)},
	}
	settings = append(settings, extra...)
	raw, err := c.Add(ctx, target.DeviceID, target.MTP, s10AddReq{
		AllowPartial: false,
		CreateObjs:   []s10CreateObj{{ObjPath: "Device.BulkData.Profile.", ParamSettings: settings}},
	})
	if err != nil {
		return "", nil, err
	}
	var ar s10AddResp
	json.Unmarshal(raw.RawBody, &ar) //nolint:errcheck
	if len(ar.CreatedObjResults) == 0 || ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess == nil {
		return "", raw, fmt.Errorf("add BulkData.Profile. failed: %s", string(raw.RawBody))
	}
	return ar.CreatedObjResults[0].OperStatus.OperStatus.OperSuccess.InstantiatedPath, raw, nil
}

// s10EnableBulkData sends a Set enabling both Device.BulkData and a specific profile.
func s10EnableBulkData(ctx context.Context, c *client.ControllerClient, target testcases.Target, profilePath string) (*client.USPResponse, error) {
	return c.Set(ctx, target.DeviceID, target.MTP, s10SetReq{
		AllowPartial: false,
		UpdateObjs: []s10UpdateObj{
			{ObjPath: "Device.BulkData.", ParamSettings: []s10ParamSetting{{Param: "Enable", Value: "true"}}},
			{ObjPath: profilePath, ParamSettings: []s10ParamSetting{{Param: "Enable", Value: "true"}}},
		},
	})
}

// s10WaitForPushEvent polls for a BulkData Push! notify event, returning the
// raw event bytes for inspection. The deadline is provided by ctx.
func s10WaitForPushEvent(ctx context.Context, c *client.ControllerClient, target testcases.Target) ([]byte, error) {
	const poll = 2 * time.Second
	for {
		events, err := c.WaitForNotify(ctx, target.DeviceID, poll)
		if err != nil {
			return nil, err
		}
		for _, ev := range events {
			var n s10Notify
			if err := json.Unmarshal(ev, &n); err != nil {
				continue
			}
			if n.Event != nil && strings.Contains(n.Event.EventName, "Push!") {
				return ev, nil
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 10.1 – BulkData collection using HTTP and JSON
// ---------------------------------------------------------------------------

func testCase10_1() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.1",
		Section:  10,
		Name:     "Use BulkData collection using HTTP and JSON",
		Purpose:  "Verify that the EUT supports JSON BulkData collection over HTTP.",
		Tags:     []string{"bulk-data", "http", "json"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.1 requires an external HTTP server reachable by the EUT to receive " +
					"and validate JSON BulkData POST requests. " +
					"Configure a BulkData HTTP receiver and set bulk_data_http_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.2 – BulkData collection using HTTPS and JSON
// ---------------------------------------------------------------------------

func testCase10_2() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.2",
		Section:  10,
		Name:     "Use BulkData collection using HTTPS and JSON",
		Purpose:  "Verify that the EUT supports JSON BulkData collection over HTTPS.",
		Tags:     []string{"bulk-data", "https", "json"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.2 requires an external HTTPS server reachable by the EUT to receive " +
					"and validate JSON BulkData POST requests. " +
					"Configure a BulkData HTTPS receiver and set bulk_data_https_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.3 – BulkData collection using HTTP and CSV
// ---------------------------------------------------------------------------

func testCase10_3() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.3",
		Section:  10,
		Name:     "Use BulkData collection using HTTP and CSV",
		Purpose:  "Verify that the EUT supports CSV BulkData collection over HTTP.",
		Tags:     []string{"bulk-data", "http", "csv"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.3 requires an external HTTP server reachable by the EUT to receive " +
					"and validate CSV BulkData POST requests. " +
					"Configure a BulkData HTTP receiver and set bulk_data_http_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.4 – BulkData collection using HTTPS and CSV
// ---------------------------------------------------------------------------

func testCase10_4() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.4",
		Section:  10,
		Name:     "Use BulkData collection using HTTPS and CSV",
		Purpose:  "Verify that the EUT supports CSV BulkData collection over HTTPS.",
		Tags:     []string{"bulk-data", "https", "csv"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.4 requires an external HTTPS server reachable by the EUT to receive " +
					"and validate CSV BulkData POST requests. " +
					"Configure a BulkData HTTPS receiver and set bulk_data_https_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.5 – BulkData collection using HTTP with URI Parameters
// ---------------------------------------------------------------------------

func testCase10_5() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.5",
		Section:  10,
		Name:     "Use BulkData collection using HTTP with URI Parameters",
		Purpose:  "Verify that the EUT supports BulkData collection over HTTP with extra URI parameters.",
		Tags:     []string{"bulk-data", "http", "uri-parameters"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.5 requires an external HTTP server reachable by the EUT that records " +
					"URI query parameters from BulkData POST requests. " +
					"Configure a BulkData HTTP receiver and set bulk_data_http_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.6 – BulkData collection using HTTPS with URI Parameters
// ---------------------------------------------------------------------------

func testCase10_6() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.6",
		Section:  10,
		Name:     "Use BulkData collection using HTTPS with URI Parameters",
		Purpose:  "Verify that the EUT supports BulkData collection over HTTPS with extra URI parameters.",
		Tags:     []string{"bulk-data", "https", "uri-parameters"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.6 requires an external HTTPS server reachable by the EUT that records " +
					"URI query parameters from BulkData POST requests. " +
					"Configure a BulkData HTTPS receiver and set bulk_data_https_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.7 – BulkData collection retry mechanism over HTTP
// ---------------------------------------------------------------------------

func testCase10_7() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.7",
		Section:  10,
		Name:     "BulkData collection retry mechanism over HTTP",
		Purpose:  "Verify that the EUT retries a failed BulkData HTTP transfer according to the configured retry policy.",
		Tags:     []string{"bulk-data", "http", "retry"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.7 requires an external HTTP server that can be deliberately taken offline " +
					"mid-test to trigger the EUT retry mechanism. " +
					"This cannot be orchestrated via the controller REST API.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.8 – BulkData collection using HTTP with wildcard parameter
// ---------------------------------------------------------------------------

func testCase10_8() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.8",
		Section:  10,
		Name:     "Use BulkData collection using HTTP with wildcard parameter",
		Purpose:  "Verify that the EUT supports BulkData collection over HTTP with a wildcarded parameter reference.",
		Tags:     []string{"bulk-data", "http", "wildcard"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.8 requires an external HTTP server reachable by the EUT to receive " +
					"and validate BulkData POST requests containing wildcard-resolved parameters. " +
					"Configure a BulkData HTTP receiver and set bulk_data_http_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.9 – BulkData collection using HTTP with Object Path
// ---------------------------------------------------------------------------

func testCase10_9() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.9",
		Section:  10,
		Name:     "Use BulkData collection using HTTP with Object Path",
		Purpose:  "Verify that the EUT supports BulkData collection over HTTP using an object path parameter reference.",
		Tags:     []string{"bulk-data", "http", "object-path"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.9 requires an external HTTP server reachable by the EUT to receive " +
					"and validate BulkData POST requests containing object-path resolved parameters. " +
					"Configure a BulkData HTTP receiver and set bulk_data_http_url in the test config.")
		},
	}
}

// ---------------------------------------------------------------------------
// 10.10 – BulkData collection Push event
// Conditional Mandatory: supports BulkDataColl:1, "USPEventNotif" ∈ Device.BulkData.Protocols
// ---------------------------------------------------------------------------

func testCase10_10() testcases.TestCase {
	return testcases.TestCase{
		ID:      "10.10",
		Section: 10,
		Name:    "Use BulkData collection Push event",
		Purpose: "Verify that the EUT supports BulkData collection via the USPEventNotif Push! event, delivering Device.DeviceInfo.UpTime to the controller.",
		Tags:    []string{"bulk-data", "push", "uspeventnotif", "notify"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 0: Probe Device.BulkData.Protocols.
			protocols, supported := s10ProbeBulkData(ctx, c, target)
			if !supported {
				return testcases.Skip("Device.BulkData is not present in the agent data model (err 7026).")
			}
			if !strings.Contains(protocols, "USPEventNotif") {
				return testcases.Skip(fmt.Sprintf(
					"USPEventNotif not in Device.BulkData.Protocols (%q). Test is conditionally mandatory.", protocols))
			}

			// Step 1: Get MinReportingInterval and compute the actual interval.
			interval := s10MinReportingInterval(ctx, c, target)
			waitDeadline := time.Duration(interval*2+10) * time.Second

			// Step 2: Add BulkData.Profile. with Protocol=USPEventNotif.
			profilePath, profileRaw, err := s10AddBulkDataProfile(ctx, c, target, "USPEventNotif", "JSON", interval, nil)
			if err != nil {
				return testcases.Error("setup: add BulkData.Profile. failed: " + string(profileRaw.RawBody))
			}
			defer s10Delete(ctx, c, target, profilePath)

			// Step 3: Add BulkData.Profile.{i}.Parameter. with Name=UpTime, Reference=Device.DeviceInfo.UpTime.
			paramRaw, paramErr := c.Add(ctx, target.DeviceID, target.MTP, s10AddReq{
				AllowPartial: false,
				CreateObjs: []s10CreateObj{{
					ObjPath: profilePath + "Parameter.",
					ParamSettings: []s10ParamSetting{
						{Param: "Name", Value: "UpTime"},
						{Param: "Reference", Value: "Device.DeviceInfo.UpTime"},
					},
				}},
			})
			if paramErr != nil {
				return testcases.Error("setup: add BulkData Parameter failed: " + paramErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(paramRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error adding BulkData Parameter: %d %s", code, msg))
			}

			// Step 4: Create a subscription for the Push! event.
			subPath, subRaw, subErr := s10AddSubscription(ctx, c, target,
				"Event", profilePath+"Push!", "bulkdata-10-10")
			if subErr != nil {
				return testcases.Error("setup: create Push! subscription failed: " + string(subRaw.RawBody))
			}
			defer s10Delete(ctx, c, target, subPath)

			// Step 5: Drain stale notifications.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// Step 6: Enable Device.BulkData and the profile.
			setRaw, setErr := s10EnableBulkData(ctx, c, target, profilePath)
			if setErr != nil {
				return testcases.Error("Set Enable failed: " + setErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(setRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error enabling BulkData: %d %s", code, msg))
			}

			// Step 7: Wait for at least one Push! event within the deadline.
			waitCtx, cancel := context.WithTimeout(ctx, waitDeadline)
			defer cancel()

			ev, waitErr := s10WaitForPushEvent(waitCtx, c, target)
			if waitErr != nil {
				return testcases.Fail(
					fmt.Sprintf("did not receive a Push! event within %s", waitDeadline),
					testcases.Step("wait for Push! event", "fail", waitErr.Error()),
				)
			}

			// Step 8: Verify the Push! event Data parameter contains "UpTime".
			var n s10Notify
			json.Unmarshal(ev, &n) //nolint:errcheck
			data := ""
			if n.Event != nil {
				data = n.Event.Params["Data"]
			}
			if !strings.Contains(data, "UpTime") {
				return testcases.Fail(
					"Push! event Data parameter does not contain the expected 'UpTime' parameter",
					testcases.Step("verify Push! event contains UpTime", "fail", string(ev)),
				)
			}

			return testcases.Pass(
				testcases.Step("Device.BulkData.Protocols contains USPEventNotif", "pass", protocols),
				testcases.Step(fmt.Sprintf("BulkData.Profile. created with ReportingInterval=%d", interval), "pass", profilePath),
				testcases.Step("Push! event received from EUT", "pass", string(ev)),
				testcases.Step("Data parameter contains 'UpTime'", "pass", data),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// 10.11 – BulkData collection Push event with Wildcard path
// Conditional Mandatory: supports BulkDataColl:1, "USPEventNotif" ∈ Device.BulkData.Protocols
// ---------------------------------------------------------------------------

func testCase10_11() testcases.TestCase {
	return testcases.TestCase{
		ID:      "10.11",
		Section: 10,
		Name:    "Use BulkData collection Push event with Wildcard path",
		Purpose: "Verify that the EUT supports BulkData collection via the USPEventNotif Push! event using a wildcard parameter reference (Device.LocalAgent.Controller.*.BootParameter.*.Enable).",
		Tags:    []string{"bulk-data", "push", "uspeventnotif", "wildcard", "notify"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 0: Probe Device.BulkData.Protocols.
			protocols, supported := s10ProbeBulkData(ctx, c, target)
			if !supported {
				return testcases.Skip("Device.BulkData is not present in the agent data model (err 7026).")
			}
			if !strings.Contains(protocols, "USPEventNotif") {
				return testcases.Skip(fmt.Sprintf(
					"USPEventNotif not in Device.BulkData.Protocols (%q). Test is conditionally mandatory.", protocols))
			}

			// Step 1: Compute ReportingInterval.
			interval := s10MinReportingInterval(ctx, c, target)
			waitDeadline := time.Duration(interval*2+10) * time.Second

			// Step 2: Add BulkData.Profile. with Protocol=USPEventNotif.
			profilePath, profileRaw, err := s10AddBulkDataProfile(ctx, c, target, "USPEventNotif", "JSON", interval, nil)
			if err != nil {
				return testcases.Error("setup: add BulkData.Profile. failed: " + string(profileRaw.RawBody))
			}
			defer s10Delete(ctx, c, target, profilePath)

			// Step 3: Add Parameter with wildcard Reference.
			paramRaw, paramErr := c.Add(ctx, target.DeviceID, target.MTP, s10AddReq{
				AllowPartial: false,
				CreateObjs: []s10CreateObj{{
					ObjPath: profilePath + "Parameter.",
					ParamSettings: []s10ParamSetting{
						{Param: "Name", Value: "Enabled"},
						{Param: "Reference", Value: "Device.LocalAgent.Controller.*.BootParameter.*.Enable"},
					},
				}},
			})
			if paramErr != nil {
				return testcases.Error("setup: add BulkData Parameter failed: " + paramErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(paramRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error adding BulkData Parameter: %d %s", code, msg))
			}

			// Step 4: Create Push! subscription.
			subPath, subRaw, subErr := s10AddSubscription(ctx, c, target,
				"Event", profilePath+"Push!", "bulkdata-10-11")
			if subErr != nil {
				return testcases.Error("setup: create Push! subscription failed: " + string(subRaw.RawBody))
			}
			defer s10Delete(ctx, c, target, subPath)

			// Step 5: Drain stale notifications.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// Step 6: Enable BulkData and the profile.
			setRaw, setErr := s10EnableBulkData(ctx, c, target, profilePath)
			if setErr != nil {
				return testcases.Error("Set Enable failed: " + setErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(setRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error enabling BulkData: %d %s", code, msg))
			}

			// Step 7: Wait for a Push! event.
			waitCtx, cancel := context.WithTimeout(ctx, waitDeadline)
			defer cancel()

			ev, waitErr := s10WaitForPushEvent(waitCtx, c, target)
			if waitErr != nil {
				return testcases.Fail(
					fmt.Sprintf("did not receive a Push! event within %s", waitDeadline),
					testcases.Step("wait for Push! event", "fail", waitErr.Error()),
				)
			}

			// Step 8: Verify the Data parameter contains at least 2 "Enabled" entries.
			// Per the spec, names should match the pattern Enabled\.[1-9][0-9]*\.[1-9][0-9]*
			var n s10Notify
			json.Unmarshal(ev, &n) //nolint:errcheck
			data := ""
			if n.Event != nil {
				data = n.Event.Params["Data"]
			}
			count := strings.Count(data, "Enabled.")
			if count < 2 {
				return testcases.Fail(
					fmt.Sprintf("Push! event Data contains %d 'Enabled.*' entry/entries; expected at least 2", count),
					testcases.Step("verify wildcard expansion in Data", "fail", string(ev)),
				)
			}

			return testcases.Pass(
				testcases.Step("Device.BulkData.Protocols contains USPEventNotif", "pass", protocols),
				testcases.Step(fmt.Sprintf("BulkData.Profile. created with ReportingInterval=%d", interval), "pass", profilePath),
				testcases.Step("Push! event received from EUT", "pass", string(ev)),
				testcases.Step(fmt.Sprintf("Data contains %d 'Enabled.*' wildcard entries", count), "pass", data),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// 10.12 – BulkData collection Push event with Object path
// Conditional Mandatory: supports BulkDataColl:1, "USPEventNotif" ∈ Device.BulkData.Protocols
// ---------------------------------------------------------------------------

func testCase10_12() testcases.TestCase {
	return testcases.TestCase{
		ID:      "10.12",
		Section: 10,
		Name:    "Use BulkData collection Push event with Object path",
		Purpose: "Verify that the EUT supports BulkData collection via the USPEventNotif Push! event using an object path reference (Device.LocalAgent.Controller.).",
		Tags:    []string{"bulk-data", "push", "uspeventnotif", "object-path", "notify"},
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			cfg.Defaults()

			// Step 0: Probe Device.BulkData.Protocols.
			protocols, supported := s10ProbeBulkData(ctx, c, target)
			if !supported {
				return testcases.Skip("Device.BulkData is not present in the agent data model (err 7026).")
			}
			if !strings.Contains(protocols, "USPEventNotif") {
				return testcases.Skip(fmt.Sprintf(
					"USPEventNotif not in Device.BulkData.Protocols (%q). Test is conditionally mandatory.", protocols))
			}

			// Step 1: Compute ReportingInterval.
			interval := s10MinReportingInterval(ctx, c, target)
			waitDeadline := time.Duration(interval*2+10) * time.Second

			// Step 2: Add BulkData.Profile. with Protocol=USPEventNotif.
			profilePath, profileRaw, err := s10AddBulkDataProfile(ctx, c, target, "USPEventNotif", "JSON", interval, nil)
			if err != nil {
				return testcases.Error("setup: add BulkData.Profile. failed: " + string(profileRaw.RawBody))
			}
			defer s10Delete(ctx, c, target, profilePath)

			// Step 3: Add Parameter with object path Reference (all params under Controller).
			paramRaw, paramErr := c.Add(ctx, target.DeviceID, target.MTP, s10AddReq{
				AllowPartial: false,
				CreateObjs: []s10CreateObj{{
					ObjPath: profilePath + "Parameter.",
					ParamSettings: []s10ParamSetting{
						{Param: "Name", Value: "Controller"},
						{Param: "Reference", Value: "Device.LocalAgent.Controller."},
					},
				}},
			})
			if paramErr != nil {
				return testcases.Error("setup: add BulkData Parameter failed: " + paramErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(paramRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error adding BulkData Parameter: %d %s", code, msg))
			}

			// Step 4: Create Push! subscription.
			subPath, subRaw, subErr := s10AddSubscription(ctx, c, target,
				"Event", profilePath+"Push!", "bulkdata-10-12")
			if subErr != nil {
				return testcases.Error("setup: create Push! subscription failed: " + string(subRaw.RawBody))
			}
			defer s10Delete(ctx, c, target, subPath)

			// Step 5: Drain stale notifications.
			c.GetNotifyEvents(ctx, target.DeviceID) //nolint:errcheck

			// Step 6: Enable BulkData and the profile.
			setRaw, setErr := s10EnableBulkData(ctx, c, target, profilePath)
			if setErr != nil {
				return testcases.Error("Set Enable failed: " + setErr.Error())
			}
			if isErr, code, msg := client.IsUSPError(setRaw.RawBody); isErr {
				return testcases.Fail(fmt.Sprintf("USP error enabling BulkData: %d %s", code, msg))
			}

			// Step 7: Wait for a Push! event.
			waitCtx, cancel := context.WithTimeout(ctx, waitDeadline)
			defer cancel()

			ev, waitErr := s10WaitForPushEvent(waitCtx, c, target)
			if waitErr != nil {
				return testcases.Fail(
					fmt.Sprintf("did not receive a Push! event within %s", waitDeadline),
					testcases.Step("wait for Push! event", "fail", waitErr.Error()),
				)
			}

			// Step 8: Verify the Data parameter contains parameters prefixed with "Controller".
			var n s10Notify
			json.Unmarshal(ev, &n) //nolint:errcheck
			data := ""
			if n.Event != nil {
				data = n.Event.Params["Data"]
			}
			if !strings.Contains(data, "Controller") {
				return testcases.Fail(
					"Push! event Data parameter does not contain any 'Controller' prefixed parameters",
					testcases.Step("verify object path expansion in Data", "fail", string(ev)),
				)
			}

			return testcases.Pass(
				testcases.Step("Device.BulkData.Protocols contains USPEventNotif", "pass", protocols),
				testcases.Step(fmt.Sprintf("BulkData.Profile. created with ReportingInterval=%d", interval), "pass", profilePath),
				testcases.Step("Push! event received from EUT", "pass", string(ev)),
				testcases.Step("Data contains 'Controller' prefixed parameters", "pass", data),
			)
		},
	}
}

// ---------------------------------------------------------------------------
// 10.13 – BulkData collection over MQTT
// Conditional Mandatory: supports BulkDataColl:1, "MQTT" ∈ Device.BulkData.Protocols
// ---------------------------------------------------------------------------

func testCase10_13() testcases.TestCase {
	return testcases.TestCase{
		ID:       "10.13",
		Section:  10,
		Name:     "Use BulkData collection over MQTT",
		Purpose:  "Verify that the EUT supports BulkData collection via MQTT, publishing data to a configured broker topic.",
		Tags:     []string{"bulk-data", "mqtt"},
		Disabled: true,
		Run: func(ctx context.Context, c *client.ControllerClient, target testcases.Target, cfg testcases.TestConfig) testcases.Result {
			return testcases.Skip(
				"Test 10.13 requires a dedicated MQTT broker reachable by the EUT, " +
					"a Device.MQTT.Client. entry in the agent data model pointing to that broker, " +
					"and the ability to subscribe to the configured publish topic to verify delivery. " +
					"These prerequisites cannot be provided via the controller REST API alone.")
		},
	}
}
