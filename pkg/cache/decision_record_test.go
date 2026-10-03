package cache

import (
	"log/slog"
	"testing"
)

func TestDecisionRecordLegacyAndLocalRoundTrip(t *testing.T) {
	legacy, err := ParseDecisionRecord(BannedValue)
	if err != nil || legacy.Verdict != BannedValue || legacy.Scenario != "" || legacy.ExpiresAt != "" {
		t.Fatalf("unexpected legacy record: %#v, %v", legacy, err)
	}
	client := &Client{}
	client.New(slog.Default(), false, "", nil, "", "")
	want := DecisionRecord{Verdict: CaptchaValue, Scenario: "local/test", ExpiresAt: "2030-01-02T03:04:05Z"}
	if err := client.SetDecision(t.Name(), want, 60); err != nil {
		t.Fatal(err)
	}
	got, err := client.GetDecision(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
