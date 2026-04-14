// Package testcases defines the interfaces and shared types used by all TP-469
// conformance test case implementations.
package testcases

import (
	"context"

	"github.com/leandrofars/oktopus/taas/internal/runner/client"
)

// Target identifies the device under test.
type Target struct {
	DeviceID string
	MTP      string // "mqtt" | "ws" | "stomp" | "webpa"
}

// TestConfig allows callers to override data model paths used by tests.
// Defaults are chosen to cover the mandatory Device:2 data model paths for a
// USP agent.
type TestConfig struct {
	// Multi-instance object used for Add / Delete tests.
	// Must be a table object the agent allows controllers to create.
	// Default: "Device.LocalAgent.Subscription."
	MultiInstanceObject string `json:"multi_instance_object"`

	// A required parameter name within MultiInstanceObject.
	// Default: "NotifType"
	RequiredParam string `json:"required_param"`

	// A valid value for RequiredParam.
	// Default: "ValueChange"
	RequiredParamValue string `json:"required_param_value"`

	// A writable parameter path (including trailing dot or param name).
	// Default: "Device.LocalAgent.EndpointID"
	WritableParamPath string `json:"writable_param_path"`

	// A read-only, always-present parameter path.
	// Default: "Device.DeviceInfo.Manufacturer"
	ReadableParamPath string `json:"readable_param_path"`

	// An object path for GetInstances.
	// Default: "Device.LocalAgent.Controller."
	GetInstancesObject string `json:"get_instances_object"`

	// Root object path for GetSupportedDM.
	// Default: "Device.DeviceInfo."
	GetSupportedDMObject string `json:"get_supported_dm_object"`

	// A deliberately invalid / nonexistent path for negative tests.
	// Default: "Device.Bogus."
	InvalidPath string `json:"invalid_path"`

	// Command path for Operate tests.
	// Default: "Device.Reboot()"
	RebootCommand string `json:"reboot_command"`
}

// Defaults fills in zero-value fields with sensible defaults.
// It is exported so test case packages can call it as cfg.Defaults().
func (c *TestConfig) Defaults() {
	c.defaults()
}

// defaults is the unexported internal implementation.
func (c *TestConfig) defaults() {
	if c.MultiInstanceObject == "" {
		c.MultiInstanceObject = "Device.LocalAgent.Subscription."
	}
	if c.RequiredParam == "" {
		c.RequiredParam = "NotifType"
	}
	if c.RequiredParamValue == "" {
		c.RequiredParamValue = "ValueChange"
	}
	if c.WritableParamPath == "" {
		c.WritableParamPath = "Device.LocalAgent.EndpointID"
	}
	if c.ReadableParamPath == "" {
		c.ReadableParamPath = "Device.DeviceInfo.Manufacturer"
	}
	if c.GetInstancesObject == "" {
		c.GetInstancesObject = "Device.LocalAgent.Controller."
	}
	if c.GetSupportedDMObject == "" {
		c.GetSupportedDMObject = "Device.DeviceInfo."
	}
	if c.InvalidPath == "" {
		c.InvalidPath = "Device.Bogus."
	}
	if c.RebootCommand == "" {
		c.RebootCommand = "Device.Reboot()"
	}
}

// StepResult records the outcome of a single step within a test case.
type StepResult struct {
	Description string
	Status      string // "pass" | "fail"
	Detail      string
}

// Result is the overall outcome of running a single test case.
type Result struct {
	Status string // "pass" | "fail" | "error" | "skip"
	Steps  []StepResult
	Note   string
}

func Pass(steps ...StepResult) Result {
	return Result{Status: "pass", Steps: steps}
}

func Fail(note string, steps ...StepResult) Result {
	return Result{Status: "fail", Steps: steps, Note: note}
}

func Error(note string) Result {
	return Result{Status: "error", Note: note}
}

func Skip(reason string) Result {
	return Result{Status: "skip", Note: reason}
}

func Step(description, status, detail string) StepResult {
	return StepResult{Description: description, Status: status, Detail: detail}
}

// RunFunc is the signature every test case must implement.
type RunFunc func(ctx context.Context, c *client.ControllerClient, target Target, cfg TestConfig) Result

// TestCase metadata and implementation.
type TestCase struct {
	// ID is the TP-469 test identifier, e.g. "1.1".
	ID string
	// Section is the numeric section number, e.g. 1.
	Section int
	// Name is the short TP-469 title.
	Name string
	// Purpose is a brief human-readable description.
	Purpose string
	// MTPs this test applies to. nil / empty = all MTPs.
	MTPs []string
	// Tags for filtering (e.g. "add", "set", "negative").
	Tags []string
	// Run executes the test and returns its result.
	Run RunFunc
}

// AppliesToMTP returns true when the test applies to the given MTP.
func (tc TestCase) AppliesToMTP(mtp string) bool {
	if len(tc.MTPs) == 0 {
		return true
	}
	for _, m := range tc.MTPs {
		if m == mtp {
			return true
		}
	}
	return false
}
