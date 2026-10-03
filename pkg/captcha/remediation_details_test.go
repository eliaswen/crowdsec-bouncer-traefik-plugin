package captcha

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
)

func TestServeHTTPWithDataIncludesDecisionAndGracePeriod(t *testing.T) {
	client := &Client{
		Valid:               true,
		template:            template.Must(template.New("captcha").Parse(`{{.DecisionReason}}|{{.DecisionScenario}}|{{.DecisionExpiresAt}}|{{.DecisionRemainingSeconds}}|{{.DecisionRemainingTime}}|{{.CaptchaGracePeriodSeconds}}|{{.CaptchaGracePeriod}}|{{.ClientIP}}|{{.TraceID}}`)),
		templateContentType: "application/json",
		gracePeriodSeconds:  3723,
		infoProvider:        &infoProvider{},
		log:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	rw := httptest.NewRecorder()
	client.ServeHTTPWithData(rw, httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1", map[string]string{
		"DecisionReason": "mapped reason", "DecisionScenario": "local/test", "DecisionExpiresAt": "2030-01-01T00:00:00Z", "DecisionRemainingSeconds": "42", "DecisionRemainingTime": "42 seconds", "ClientIP": "192.0.2.1", "TraceID": "trace-1",
	})
	want := "mapped reason|local/test|2030-01-01T00:00:00Z|42|42 seconds|3723|1 hour 2 minutes 3 seconds|192.0.2.1|trace-1"
	if strings.TrimSpace(rw.Body.String()) != want {
		t.Fatalf("got %q, want %q", rw.Body.String(), want)
	}
}
