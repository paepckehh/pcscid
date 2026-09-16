package pcscid

import "runtime/debug"

// defaultVersion is the final Version() fallback for plain go builds
// without a link time semver and without VCS build info. It carries
// the current release tag and is bumped together with the git tag on
// every code update (hardwired requirement, see AGENTS.md top
// section).
var defaultVersion = "v0.0.141"

// version is overridden at build time by the Go linker, for example:
//
//	go build -ldflags "-X paepcke.de/pcscid.version=v0.0.1" ./cmd/pcscid
var version = ""

// Version returns the semantic version of the pcscid library or
// binary. The value is injected at build time via the go linker
// (-ldflags "-X paepcke.de/pcscid.version=<semver>"). When not
// injected, for plain go builds, it falls back to the VCS revision
// recorded in the Go build info, and finally to defaultVersion, the
// current release tag.
func Version() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && len(setting.Value) >= 7 {
				return "devel-" + setting.Value[:7]
			}
		}
	}
	return defaultVersion
}
