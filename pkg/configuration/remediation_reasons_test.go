package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetRemediationReasons(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reasons.txt")
	content := "# descriptions\n\nlocal/http-421-scan = \"Suspicious café scanning.\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	reasons, err := GetRemediationReasons(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reasons["local/http-421-scan"]; got != "Suspicious café scanning." {
		t.Fatalf("unexpected reason %q", got)
	}
}

func TestGetRemediationReasonsRejectsMalformedEntries(t *testing.T) {
	for _, content := range []string{"scenario = unquoted\n", "scenario = \"\"\n", "scenario = \"one\"\nscenario = \"two\"\n", " = \"empty scenario\"\n"} {
		path := filepath.Join(t.TempDir(), "reasons.txt")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := GetRemediationReasons(path)
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "line") {
			t.Fatalf("expected path and line error for %q, got %v", content, err)
		}
	}
}
