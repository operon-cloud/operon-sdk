package version

import "testing"

func TestStringReturnsDefaultVersion(t *testing.T) {
	if got := String(); got != "v1.1.3" {
		t.Fatalf("expected v1.1.3, got %s", got)
	}
}
