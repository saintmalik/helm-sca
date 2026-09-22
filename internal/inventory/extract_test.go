package inventory_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saintmalik/helm-sca/internal/inventory"
)

func TestExtractFromYAML_Workloads(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "manifests", "workloads.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := inventory.ExtractFromYAML(data, path, false, false)
	findings = inventory.Dedupe(findings)

	want := map[string]bool{
		"busybox:1.36": true,
		"nginx:1.27.0": true,
		"ghcr.io/example/sidecar@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true,
		"curlimages/curl:8.5.0": true,
		"alpine:3.20":           true,
		"nicolaka/netshoot:latest": true,
	}
	if len(findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(findings), len(want), findings)
	}
	for _, f := range findings {
		if !want[f.Name] {
			t.Errorf("unexpected image %q", f.Name)
		}
		if f.Confidence != inventory.ConfidenceHigh {
			t.Errorf("%s: confidence=%s want high", f.Name, f.Confidence)
		}
		if f.Source != inventory.SourceRendered {
			t.Errorf("%s: source=%s want rendered-manifest", f.Name, f.Source)
		}
	}
}

func TestNormalizeAndDedupe(t *testing.T) {
	in := []inventory.ImageFinding{
		{Name: "nginx:1.26", Confidence: inventory.ConfidenceLow, Source: inventory.SourceRegex},
		{Name: "nginx:1.27.0", Confidence: inventory.ConfidenceHigh, Source: inventory.SourceRendered},
		{Name: "  nginx:1.27.0  ", Confidence: inventory.ConfidenceMedium, Source: inventory.SourceStatic},
	}
	out := inventory.Dedupe(in)
	if len(out) != 1 {
		t.Fatalf("want 1 after dedupe, got %d: %+v", len(out), out)
	}
	if out[0].Name != "nginx:1.27.0" || out[0].Confidence != inventory.ConfidenceHigh {
		t.Fatalf("unexpected winner: %+v", out[0])
	}
}

func TestJoinImage(t *testing.T) {
	if got := inventory.JoinImage("nginx", "1.27.0"); got != "nginx:1.27.0" {
		t.Fatalf("got %q", got)
	}
	if got := inventory.JoinImage("nginx", "sha256:abc"); got != "nginx@sha256:abc" {
		t.Fatalf("got %q", got)
	}
	if got := inventory.JoinImage("{{ .Values.x }}", "1"); got != "" {
		t.Fatalf("want empty for template, got %q", got)
	}
}

func TestWalkManifests(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "manifests")
	findings, err := inventory.WalkManifests(root, false, false)
	if err != nil {
		t.Fatal(err)
	}
	findings = inventory.Dedupe(findings)
	if len(findings) < 5 {
		t.Fatalf("expected several images, got %d", len(findings))
	}
}
