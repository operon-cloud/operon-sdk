package version

import "testing"

func TestStringReturnsDefaultVersion(t *testing.T) {
	if got := String(); got != "v1.3.0" {
		t.Fatalf("expected v1.3.0, got %s", got)
	}
}
