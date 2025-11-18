package version

import "testing"

func TestStringReturnsDefaultVersion(t *testing.T) {
	if got := String(); got != "v1.1.4" {
		t.Fatalf("expected v1.1.4, got %s", got)
	}
}
