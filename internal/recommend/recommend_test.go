package recommend

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saintmalik/helm-sca/internal/inventory"
	"github.com/saintmalik/helm-sca/internal/scan"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.4", "1.2.3", 1},
		{"1.2.3", "1.2.4", -1},
		{"v4.11.0", "4.10.0", 1},
		{"4.10.0", "v4.11.0", -1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("compareVersions(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestFilterNewer(t *testing.T) {
	versions := []string{"4.12.0", "4.11.2", "4.11.0", "4.10.0"}
	got := filterNewer("4.11.0", versions)
	if len(got) != 2 || got[0] != "4.12.0" || got[1] != "4.11.2" {
		t.Fatalf("filterNewer = %#v", got)
	}
	if got := filterNewer("4.12.0", versions); len(got) != 0 {
		t.Fatalf("expected empty, got %#v", got)
	}
}

func TestImprovedHeuristic(t *testing.T) {
	cur := scan.Score{High: 5, Critical: 2}
	betterCrit := scan.Score{High: 10, Critical: 1}
	betterHigh := scan.Score{High: 3, Critical: 2}
	worse := scan.Score{High: 5, Critical: 2}
	if !scan.Improved(cur, betterCrit) {
		t.Fatal("expected critical improvement")
	}
	if !scan.Improved(cur, betterHigh) {
		t.Fatal("expected high improvement")
	}
	if scan.Improved(cur, worse) {
		t.Fatal("expected no improvement")
	}
}

func TestRunRecommendBump(t *testing.T) {
	dir := t.TempDir()
	appPath := filepath.Join(dir, "app.yaml")
	appYAML := `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: nginx
spec:
  source:
    repoURL: https://charts.example.com
    chart: ingress-nginx
    targetRevision: 4.10.0
`
	if err := os.WriteFile(appPath, []byte(appYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	var buf bytes.Buffer
	err := Run(context.Background(), &buf, Options{
		Inventory: inventory.Options{ArgoApps: appPath, RepoRoot: dir},
		OutDir:    outDir,
		MaxApps:   5,
		OnlyFixed: true,
		Format:    "json",
		SkipScore: false,
		ListVersions: func(chart, repoURL, helmBin string) ([]string, error) {
			return []string{"4.11.0", "4.10.0"}, nil
		},
		TemplatePin: func(pin inventory.ChartPin, version, helmBin string) ([]byte, error) {
			img := "registry.k8s.io/ingress-nginx/controller:v1.10.0"
			if version == "4.11.0" {
				img = "registry.k8s.io/ingress-nginx/controller:v1.11.0"
			}
			return []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        image: " + img + "\n"), nil
		},
		ScoreImages: func(ctx context.Context, images []string, onlyFixed bool, workDir string) (scan.Score, []string, error) {
			s := scan.Score{BySeverity: map[string]int{}, Images: images}
			for _, img := range images {
				if strings.Contains(img, "v1.10.0") {
					s.Critical = 2
					s.High = 4
					s.BySeverity["critical"] = 2
					s.BySeverity["high"] = 4
				} else {
					s.Critical = 0
					s.High = 1
					s.BySeverity["critical"] = 0
					s.BySeverity["high"] = 1
				}
			}
			return s, nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "bump-recommended") {
		t.Fatalf("expected bump-recommended in output: %s", out)
	}
	if !strings.Contains(out, "4.11.0") {
		t.Fatalf("expected recommended pin 4.11.0: %s", out)
	}
	mdPath := filepath.Join(outDir, "upgrade-recommendations.md")
	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("missing markdown artifact: %v", err)
	}
}

func TestRunRecommendUpToDate(t *testing.T) {
	dir := t.TempDir()
	appPath := filepath.Join(dir, "app.yaml")
	if err := os.WriteFile(appPath, []byte(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: nginx
spec:
  source:
    repoURL: https://charts.example.com
    chart: ingress-nginx
    targetRevision: 4.11.0
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := Run(context.Background(), &buf, Options{
		Inventory: inventory.Options{ArgoApps: appPath, RepoRoot: dir},
		OutDir:    filepath.Join(dir, "out"),
		Format:    "json",
		ListVersions: func(chart, repoURL, helmBin string) ([]string, error) {
			return []string{"4.11.0"}, nil
		},
		TemplatePin: func(pin inventory.ChartPin, version, helmBin string) ([]byte, error) {
			t.Fatal("should not template when up-to-date")
			return nil, nil
		},
		ScoreImages: func(ctx context.Context, images []string, onlyFixed bool, workDir string) (scan.Score, []string, error) {
			t.Fatal("should not score when up-to-date")
			return scan.Score{}, nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "up-to-date") {
		t.Fatalf("expected up-to-date: %s", buf.String())
	}
}

func TestListArgoPins(t *testing.T) {
	dir := t.TempDir()
	appPath := filepath.Join(dir, "app.yaml")
	if err := os.WriteFile(appPath, []byte(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: demo
spec:
  source:
    repoURL: https://charts.bitnami.com/bitnami
    chart: redis
    targetRevision: 18.0.0
`), 0o644); err != nil {
		t.Fatal(err)
	}
	pins, _, err := inventory.ListChartPins(inventory.Options{ArgoApps: appPath, RepoRoot: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 1 {
		t.Fatalf("pins=%d want 1", len(pins))
	}
	if pins[0].Chart != "redis" || pins[0].Version != "18.0.0" {
		t.Fatalf("unexpected pin: %+v", pins[0])
	}
}
