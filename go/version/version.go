package version

import "strings"

var buildVersion = "v1.1.4"

// String returns the semantic version of the SDK. Override via ldflags, e.g.:
// go build -ldflags "-X github.com/operon-cloud/operon-sdk/go/version.buildVersion=v1.0.0".
func String() string {
	return strings.TrimSpace(buildVersion)
}
