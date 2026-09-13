package pcscid

import "testing"

// TestVersionInjected pins the precedence: a linker injected version
// always wins over the VCS fallback. The test must not run in
// parallel, it flips the package variable for a moment.
func TestVersionInjected(t *testing.T) {
	saved := version
	version = "v9.9.9-test"
	defer func() { version = saved }()
	if got := Version(); got != "v9.9.9-test" {
		t.Errorf("Version() = %q, want the injected v9.9.9-test", got)
	}
}

// TestVersionFallback asserts Version always answers with something
// usable: injected semver, VCS revision or the current tag fallback
// (defaultVersion).
func TestVersionFallback(t *testing.T) {
	saved := version
	version = ""
	defer func() { version = saved }()
	if Version() == "" {
		t.Error("Version() is empty without injection")
	}
}
