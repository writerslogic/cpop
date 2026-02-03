package attestation

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEmbeddedTemplateMatchesRepoTemplate(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve caller path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	repoTemplatePath := filepath.Join(repoRoot, "attestation.template.json")

	repoTemplate, err := os.ReadFile(repoTemplatePath)
	if err != nil {
		t.Fatalf("read repo template: %v", err)
	}

	if !bytes.Equal(bytes.TrimSpace(repoTemplate), bytes.TrimSpace(templateJSON)) {
		t.Fatalf("embedded template differs from %s", repoTemplatePath)
	}
}
