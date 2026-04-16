package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/leandrofars/oktopus/taas/internal/api/cors"
	"github.com/leandrofars/oktopus/taas/internal/api/middleware"
	"github.com/leandrofars/oktopus/taas/internal/config"
	"github.com/leandrofars/oktopus/taas/internal/db"
	"github.com/leandrofars/oktopus/taas/internal/runner"
	"github.com/leandrofars/oktopus/taas/internal/testcases"
)

// Api wires together the TaaS HTTP REST layer.
type Api struct {
	port     string
	database db.Database
	runner   *runner.Runner
	registry *testcases.Registry
}

// NewApi constructs a new Api.
func NewApi(c *config.Config, database db.Database, registry *testcases.Registry) Api {
	return Api{
		port:     c.RestApi.Port,
		database: database,
		runner:   runner.New(database, registry),
		registry: registry,
	}
}

// StartApi registers routes and starts the HTTP server in a goroutine.
func (a *Api) StartApi() {
	r := mux.NewRouter()

	taas := r.PathPrefix("/api/taas").Subrouter()
	taas.Use(func(next http.Handler) http.Handler { return middleware.Middleware(next) })

	// Test catalogue
	taas.HandleFunc("/tests", a.listTests).Methods(http.MethodGet)

	// Runs
	taas.HandleFunc("/runs", a.startRun).Methods(http.MethodPost)
	taas.HandleFunc("/runs", a.listRuns).Methods(http.MethodGet)
	taas.HandleFunc("/runs/{id}", a.getRun).Methods(http.MethodGet)
	taas.HandleFunc("/runs/{id}", a.deleteRun).Methods(http.MethodDelete)

	corsOpts := cors.GetCorsConfig()

	srv := &http.Server{
		Addr:         "0.0.0.0:" + a.port,
		WriteTimeout: time.Second * 60,
		ReadTimeout:  time.Second * 60,
		IdleTimeout:  time.Second * 60,
		Handler:      corsOpts.Handler(r),
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()
	log.Println("TaaS REST API running on port", a.port)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// listTests returns metadata for all registered test cases.
func (a *Api) listTests(w http.ResponseWriter, r *http.Request) {
	type testMeta struct {
		ID       string   `json:"id"`
		Section  int      `json:"section"`
		Name     string   `json:"name"`
		Purpose  string   `json:"purpose"`
		Disabled bool     `json:"disabled"`
		MTPs     []string `json:"mtps"`
		Tags     []string `json:"tags"`
	}

	// Optional ?section= and ?mtp= query filters.
	sectionFilter := r.URL.Query().Get("section")
	mtpFilter := r.URL.Query().Get("mtp")

	cases := a.registry.All()
	out := make([]testMeta, 0, len(cases))
	for _, tc := range cases {
		if sectionFilter != "" {
			sec, err := strconv.Atoi(sectionFilter)
			if err != nil || tc.Section != sec {
				continue
			}
		}
		if mtpFilter != "" && !tc.AppliesToMTP(mtpFilter) {
			continue
		}
		out = append(out, testMeta{
			ID:       tc.ID,
			Section:  tc.Section,
			Name:     tc.Name,
			Purpose:  tc.Purpose,
			Disabled: tc.Disabled,
			MTPs:     tc.MTPs,
			Tags:     tc.Tags,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Section != out[j].Section {
			return out[i].Section < out[j].Section
		}
		return testcases.TestIDKey(out[i].ID) < testcases.TestIDKey(out[j].ID)
	})
	writeJSON(w, http.StatusOK, out)
}

// startRun accepts a RunRequest, persists a run document, and executes tests
// asynchronously. It returns the newly created run ID immediately.
func (a *Api) startRun(w http.ResponseWriter, r *http.Request) {
	var req runner.RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if req.DeviceID == "" || req.MTP == "" || req.ControllerURL == "" || req.ControllerToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id, mtp, controller_url, and controller_token are required"})
		return
	}
	if req.Name == "" {
		req.Name = "Run – " + req.DeviceID
	}

	id, err := a.runner.StartRun(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"run_id": id})
}

// listRuns returns the most recent test runs.
func (a *Api) listRuns(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := int64(50)
	if limitStr != "" {
		if l, err := strconv.ParseInt(limitStr, 10, 64); err == nil && l > 0 {
			limit = l
		}
	}
	runs, err := a.database.ListRuns(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if runs == nil {
		runs = []db.TestRunDocument{}
	}
	writeJSON(w, http.StatusOK, runs)
}

// getRun returns a single run document including per-test results.
func (a *Api) getRun(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	run, err := a.database.GetRun(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found"})
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// deleteRun removes a run document.
func (a *Api) deleteRun(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := a.database.DeleteRun(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "run not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Println("writeJSON encode error:", err)
	}
}
