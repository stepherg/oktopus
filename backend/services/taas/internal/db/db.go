package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	databaseName   = "taas"
	runsCollection = "test_runs"
)

type Database struct {
	client *mongo.Client
	db     *mongo.Database
	ctx    context.Context
}

func NewDatabase(ctx context.Context, uri string) Database {
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("failed to connect to MongoDB:", err)
	}
	if err = client.Ping(ctx, nil); err != nil {
		log.Fatal("failed to ping MongoDB:", err)
	}
	log.Println("Connected to MongoDB (taas)")

	mdb := client.Database(databaseName)

	// Ensure TTL index on test runs for automatic cleanup (optional – 90 days).
	idxModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "start_time", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(60 * 60 * 24 * 90),
	}
	mdb.Collection(runsCollection).Indexes().CreateOne(ctx, idxModel)

	return Database{client: client, db: mdb, ctx: ctx}
}

// InsertRun inserts a new TestRun document and returns the inserted ID as hex.
func (d Database) InsertRun(run TestRunDocument) (string, error) {
	run.ID = primitive.NewObjectID()
	run.StartTime = time.Now()
	run.Status = "running"

	res, err := d.db.Collection(runsCollection).InsertOne(d.ctx, run)
	if err != nil {
		return "", err
	}
	return res.InsertedID.(primitive.ObjectID).Hex(), nil
}

// UpdateRun persists the final state of a test run.
func (d Database) UpdateRun(id string, update TestRunDocument) error {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	update.Status = "completed"
	_, err = d.db.Collection(runsCollection).UpdateOne(
		d.ctx,
		bson.M{"_id": oid},
		bson.M{"$set": update},
	)
	return err
}

// GetRun retrieves a single TestRunDocument by ID.
func (d Database) GetRun(id string) (TestRunDocument, error) {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return TestRunDocument{}, err
	}
	var run TestRunDocument
	err = d.db.Collection(runsCollection).FindOne(d.ctx, bson.M{"_id": oid}).Decode(&run)
	return run, err
}

// ListRuns returns the most recent runs (newest first), up to limit docs.
func (d Database) ListRuns(limit int64) ([]TestRunDocument, error) {
	opts := options.Find().
		SetSort(bson.D{{Key: "start_time", Value: -1}}).
		SetLimit(limit)
	cur, err := d.db.Collection(runsCollection).Find(d.ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	var runs []TestRunDocument
	if err = cur.All(d.ctx, &runs); err != nil {
		return nil, err
	}
	return runs, nil
}

// DeleteRun removes a run document by ID.
func (d Database) DeleteRun(id string) error {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	_, err = d.db.Collection(runsCollection).DeleteOne(d.ctx, bson.M{"_id": oid})
	return err
}

// ---------------------------------------------------------------------------
// Document types
// ---------------------------------------------------------------------------

type TestRunDocument struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"       json:"id,omitempty"`
	Name      string             `bson:"name"                json:"name"`
	DeviceID  string             `bson:"device_id"           json:"device_id"`
	MTP       string             `bson:"mtp"                 json:"mtp"`
	StartTime time.Time          `bson:"start_time"          json:"start_time"`
	EndTime   time.Time          `bson:"end_time"            json:"end_time"`
	Status    string             `bson:"status"              json:"status"`
	Results   []TestResultRecord `bson:"results"             json:"results"`
	Summary   RunSummary         `bson:"summary"             json:"summary"`
}

type TestResultRecord struct {
	TestID    string       `bson:"test_id"   json:"test_id"`
	TestName  string       `bson:"test_name" json:"test_name"`
	Section   int          `bson:"section"   json:"section"`
	Status    string       `bson:"status"    json:"status"` // pass | fail | skip | error
	StartTime time.Time    `bson:"start_time" json:"start_time"`
	EndTime   time.Time    `bson:"end_time"   json:"end_time"`
	Steps     []StepRecord `bson:"steps"     json:"steps"`
	Note      string       `bson:"note"      json:"note"`
}

type StepRecord struct {
	Description string `bson:"description" json:"description"`
	Status      string `bson:"status"      json:"status"` // pass | fail
	Detail      string `bson:"detail"      json:"detail"`
}

type RunSummary struct {
	Total   int `bson:"total"   json:"total"`
	Passed  int `bson:"passed"  json:"passed"`
	Failed  int `bson:"failed"  json:"failed"`
	Errored int `bson:"errored" json:"errored"`
	Skipped int `bson:"skipped" json:"skipped"`
}
