package inventory_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/saintmalik/helm-sca/internal/inventory"
)

func TestInventoryArgoApps_KustomizeAndNestedApp(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not on PATH")
	}
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	result, warnings, err := inventory.Run(inventory.Options{
		ArgoApps:   filepath.Join(repoRoot, "testdata", "apps", "kustomize-application.yaml"),
		RepoRoot:   repoRoot,
		SkipStatic: true,
		SkipRegex:  true,
	})
	if err != nil {
		t.Fatalf("Run: %v (warnings=%v)", err, warnings)
	}

	names := map[string]bool{}
	for _, img := range result.Images {
		names[img.Name] = true
	}
	if !names["redis:7.2.4"] {
		t.Fatalf("expected redis:7.2.4 from kustomize image rewrite, got %v (warnings=%v)", names, warnings)
	}
	if !names["nginx:1.27.0"] {
		t.Fatalf("expected nginx from nested Application chart, got %v (warnings=%v)", names, warnings)
	}
}

func TestKustomizeFixturePresent(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "kustomize", "base")
	if _, err := os.Stat(filepath.Join(root, "kustomization.yaml")); err != nil {
		t.Fatalf("missing fixture: %v", err)
	}
}
