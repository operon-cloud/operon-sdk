package version

import "strings"

var buildVersion = "v1.0.0"

// String returns the semantic version of the SDK. Override via ldflags, e.g.:
// go build -ldflags "-X github.com/operonmaster/operon-sdk/go/version.buildVersion=v1.0.0".
func String() string {
	return strings.TrimSpace(buildVersion)
}
