package pcscid

import "runtime/debug"

// version is overridden at build time by the Go linker, for example:
//
//	go build -ldflags "-X paepcke.de/pcscid.version=v0.0.1" ./cmd/pcscid
var version = ""

// Version returns the semantic version of the pcscid library or
// binary. The value is injected at build time via the go linker
// (-ldflags "-X paepcke.de/pcscid.version=<semver>"). When not
// injected, for plain go builds, it falls back to the VCS revision
// recorded in the Go build info, and finally to "dev".
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
	return "dev"
}
