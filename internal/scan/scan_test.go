package scan

import (
	"testing"

	"github.com/saintmalik/helm-sca/internal/inventory"
)

func TestUniqueImageNames(t *testing.T) {
	got := uniqueImageNames([]inventory.ImageFinding{
		{Name: "a:1"},
		{Name: "b:2"},
		{Name: "a:1"},
	})
	if len(got) != 2 || got[0] != "a:1" || got[1] != "b:2" {
		t.Fatalf("uniqueImageNames = %#v", got)
	}
}

func TestGatedCount(t *testing.T) {
	by := map[string]int{"low": 2, "high": 1, "critical": 3}
	if n := gatedCount(by, "none"); n != 0 {
		t.Fatalf("none: got %d", n)
	}
	if n := gatedCount(by, "high"); n != 4 {
		t.Fatalf("high: got %d want 4", n)
	}
	if n := gatedCount(by, "low"); n != 6 {
		t.Fatalf("low: got %d want 6", n)
	}
}
