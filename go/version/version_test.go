package version

import "testing"

func TestStringReturnsDefaultVersion(t *testing.T) {
	if got := String(); got != "v1.2.0" {
		t.Fatalf("expected v1.2.0, got %s", got)
	}
}
