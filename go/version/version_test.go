package version

import "testing"

func TestStringReturnsDefaultVersion(t *testing.T) {
	if got := String(); got != "v1.1.2" {
		t.Fatalf("expected v1.1.2, got %s", got)
	}
}
