package crowdsec_bouncer_traefik_plugin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	cache "github.com/eliaswen/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

func TestDecisionTemplateDataReasonFallbackAndRemainingTime(t *testing.T) {
	expiry := time.Now().Add(2200 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	bouncer := &Bouncer{remediationReasons: map[string]string{"local/test": "Mapped <reason> & safe"}}
	record := cache.DecisionRecord{Verdict: cache.BannedValue, Scenario: "local/test", ExpiresAt: expiry}
	first := bouncer.decisionTemplateData(record, "LAPI")
	if first["DecisionReason"] != "Mapped <reason> & safe" || first["DecisionReasonHTML"] != "Mapped &lt;reason&gt; &amp; safe" {
		t.Fatalf("unexpected reasons: %#v", first)
	}
	if first["DecisionScenario"] != "local/test" || first["DecisionExpiresAt"] != expiry {
		t.Fatalf("missing metadata: %#v", first)
	}
	firstSeconds, err := strconv.Atoi(first["DecisionRemainingSeconds"])
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := strconv.Atoi(bouncer.decisionTemplateData(record, "LAPI")["DecisionRemainingSeconds"])
	if err != nil {
		t.Fatal(err)
	}
	if second >= firstSeconds {
		t.Fatalf("remaining time did not decrease: %d then %d", firstSeconds, second)
	}

	raw := bouncer.decisionTemplateData(cache.DecisionRecord{Scenario: "raw/scenario"}, "LAPI")
	if raw["DecisionReason"] != "raw/scenario" || raw["DecisionRemainingSeconds"] != "" {
		t.Fatalf("unexpected raw fallback: %#v", raw)
	}
	missing := bouncer.decisionTemplateData(cache.DecisionRecord{}, "APPSEC")
	if missing["DecisionReason"] != "APPSEC" || missing["DecisionExpiresAt"] != "" {
		t.Fatalf("unexpected missing fallback: %#v", missing)
	}
}

func TestBanDecisionCustomJSONTemplate(t *testing.T) {
	tmpl := template.Must(template.New("json").Parse(`{"scenario":{{printf "%q" .DecisionScenario}},"reason":{{printf "%q" .DecisionReason}},"expires":{{printf "%q" .DecisionExpiresAt}}}`))
	bouncer := &Bouncer{banTemplate: tmpl, banTemplateContentType: "application/json", remediationStatusCode: http.StatusForbidden, remediationReasons: map[string]string{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rw := httptest.NewRecorder()
	bouncer.handleDecisionBanServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/", nil), "192.0.2.1", "LAPI", cache.DecisionRecord{Scenario: "raw/<scenario>"})
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), `"reason":"raw/<scenario>"`) {
		t.Fatalf("unexpected response: %d %s", rw.Code, rw.Body.String())
	}
}
