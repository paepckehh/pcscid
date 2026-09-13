package main

import (
	"os"
	"testing"
)

// TestEnvEnabled pins the truthiness rule of the environment config:
// unset or "0" is off, anything else is on.
func TestEnvEnabled(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"0":     false,
		"1":     true,
		"false": true, // anything but empty or 0 counts as enabled
		"yes":   true,
	}
	for value, want := range cases {
		t.Setenv("PCSCID_TEST_ENV", value)
		if got := envEnabled("PCSCID_TEST_ENV"); got != want {
			t.Errorf("envEnabled with %q = %v, want %v", value, got, want)
		}
	}
	if err := os.Unsetenv("PCSCID_TEST_ENV"); err != nil {
		t.Fatal(err)
	}
	if envEnabled("PCSCID_TEST_ENV") {
		t.Error("envEnabled of an unset variable must be false")
	}
}
