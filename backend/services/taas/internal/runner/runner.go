// Package runner executes TP-469 conformance test cases against a USP agent
// via the Oktopus controller REST API and persists the results.
package runner

import (
	"context"
	"log"
	"time"

	"github.com/leandrofars/oktopus/taas/internal/db"
	"github.com/leandrofars/oktopus/taas/internal/runner/client"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// Runner orchestrates test case execution.
type Runner struct {
	database db.Database
	registry *testcases.Registry
}

// New creates a new Runner.
func New(database db.Database, registry *testcases.Registry) *Runner {
	return &Runner{database: database, registry: registry}
}

// RunRequest describes a test run requested by the API.
type RunRequest struct {
	Name            string `json:"name"`
	DeviceID        string `json:"device_id"`
	MTP             string `json:"mtp"`
	ControllerURL   string `json:"controller_url"`
	ControllerToken string `json:"controller_token"`
	// Filter by explicit test IDs. Empty = run all applicable.
	TestIDs []string `json:"test_ids"`
	// Filter by section number. Empty = run all sections.
	Sections []int                `json:"sections"`
	Config   testcases.TestConfig `json:"config"`
}

// StartRun inserts a pending run document and executes tests asynchronously.
// It returns the run ID immediately.
func (r *Runner) StartRun(req RunRequest) (string, error) {
	doc := db.TestRunDocument{
		Name:     req.Name,
		DeviceID: req.DeviceID,
		MTP:      req.MTP,
	}
	id, err := r.database.InsertRun(doc)
	if err != nil {
		return "", err
	}

	go r.execute(id, req)
	return id, nil
}

func (r *Runner) execute(runID string, req RunRequest) {
	c := client.New(req.ControllerURL, req.ControllerToken)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cases := r.registry.Filter(req.TestIDs, req.Sections)

	var results []db.TestResultRecord
	summary := db.RunSummary{Total: len(cases)}

	for _, tc := range cases {
		// Skip tests that don't apply to the requested MTP.
		if !tc.AppliesToMTP(req.MTP) {
			record := db.TestResultRecord{
				TestID:   tc.ID,
				TestName: tc.Name,
				Section:  tc.Section,
				Status:   "skip",
				Note:     "does not apply to MTP " + req.MTP,
			}
			results = append(results, record)
			summary.Skipped++
			continue
		}

		log.Printf("[taas] run %s: executing %s – %s", runID, tc.ID, tc.Name)
		start := time.Now()
		target := testcases.Target{DeviceID: req.DeviceID, MTP: req.MTP}
		result := tc.Run(ctx, c, target, req.Config)
		end := time.Now()

		record := db.TestResultRecord{
			TestID:    tc.ID,
			TestName:  tc.Name,
			Section:   tc.Section,
			Status:    result.Status,
			StartTime: start,
			EndTime:   end,
			Note:      result.Note,
		}
		for _, s := range result.Steps {
			record.Steps = append(record.Steps, db.StepRecord{
				Description: s.Description,
				Status:      s.Status,
				Detail:      s.Detail,
			})
		}
		results = append(results, record)

		switch result.Status {
		case "pass":
			summary.Passed++
		case "fail":
			summary.Failed++
		case "error":
			summary.Errored++
		default:
			summary.Skipped++
		}
	}

	final := db.TestRunDocument{
		Name:     req.Name,
		DeviceID: req.DeviceID,
		MTP:      req.MTP,
		EndTime:  time.Now(),
		Results:  results,
		Summary:  summary,
	}
	if err := r.database.UpdateRun(runID, final); err != nil {
		log.Printf("[taas] run %s: failed to persist results: %v", runID, err)
	}
	log.Printf("[taas] run %s complete: %+v", runID, summary)
}
