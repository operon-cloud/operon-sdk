package version

import "testing"

func TestStringReturnsDefaultVersion(t *testing.T) {
	if got := String(); got != "v1.1.1" {
		t.Fatalf("expected v1.1.1, got %s", got)
	}
}
