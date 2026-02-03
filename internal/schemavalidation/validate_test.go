package schemavalidation

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type schemaCase struct {
	name         string
	schemaPath   string
	instancePath string
}

func TestSchemaValidation(t *testing.T) {
	repoRoot := repoRoot(t)
	cases := []schemaCase{
		{
			name:         "witness-proof",
			schemaPath:   filepath.Join(repoRoot, "docs", "schema", "witness-proof-v1.schema.json"),
			instancePath: filepath.Join(repoRoot, "docs", "spec", "fixtures", "witness-proof-v1.json"),
		},
		{
			name:         "forensic-profile",
			schemaPath:   filepath.Join(repoRoot, "docs", "schema", "forensic-profile-v1.schema.json"),
			instancePath: filepath.Join(repoRoot, "docs", "spec", "fixtures", "forensic-profile-v1.json"),
		},
		{
			name:         "attestation-template",
			schemaPath:   filepath.Join(repoRoot, "docs", "schema", "attestation-v1.schema.json"),
			instancePath: filepath.Join(repoRoot, "attestation.template.json"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validateInstance(t, tc.schemaPath, tc.instancePath)
		})
	}
}

func validateInstance(t *testing.T, schemaPath, instancePath string) {
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	instanceData, err := os.ReadFile(instancePath)
	if err != nil {
		t.Fatalf("read instance: %v", err)
	}

	var instance any
	if err := json.Unmarshal(instanceData, &instance); err != nil {
		t.Fatalf("unmarshal instance: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaPath, bytes.NewReader(schemaData)); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema validation failed for %s: %v", filepath.Base(instancePath), err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve caller path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
