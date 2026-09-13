package pcscid

import (
	"slices"
	"testing"
)

func TestDetectType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		atr  string
		want string
	}{
		{
			name: "mifare classic 1k",
			atr:  "3B8F8001804F0CA000000306030001943726CB24",
			want: "mifare classic 1k",
		},
		{
			name: "mifare classic 4k",
			atr:  "3B8F8001804F0CA0000003060300020000000069",
			want: "mifare classic 4k",
		},
		{
			name: "mifare ultralight",
			atr:  "3B8F8001804F0CA000000306030003000000006A",
			want: "mifare ultralight",
		},
		{
			name: "mifare ultralight ev1",
			atr:  "3B8F8001804F0CA00000030603003D0000000065",
			want: "mifare ultralight ev1",
		},
		{
			name: "mifare plus sl1 2k",
			atr:  "3B8F8001804F0CA0000003060300360000000060",
			want: "mifare plus sl1 2k",
		},
		{
			name: "felica",
			atr:  "3B8F8001804F0CA00000030603003B000000006B",
			want: "felica",
		},
		{
			name: "picopass 16k",
			atr:  "3B8F8001804F0CA0000003060300190000000075",
			want: "picopass 16k",
		},
		{
			name: "german npa",
			atr:  "3B8480018082900097",
			want: "german eid/passport (npa)",
		},
		{
			name: "yubikey 5 nfc",
			atr:  "3B8D80018073C021C057597562694B65FF7F",
			want: "yubikey 5 nfc",
		},
		{
			name: "deutschlandticket",
			atr:  "3B8580015A4356445659",
			want: "deutschlandticket (vdv-ka)",
		},
		{
			name: "unknown plain atr",
			atr:  "3B00",
			want: "unknown",
		},
		{
			name: "unknown junk",
			atr:  "3B02FFFF",
			want: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DetectType(mustHex(t, tt.atr)); got != tt.want {
				t.Errorf("DetectType(%s) = %q, want %q", tt.atr, got, tt.want)
			}
		})
	}
}

func TestDetectTypeStandardFallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		atr  string
		want string
	}{
		{
			// SS byte 0x01, card type byte absent from the table.
			name: "iso 14443 type a part 1",
			atr:  "3B8F8001804F0CA0000003060100550000000060",
			want: "rfid, iso 14443 type a part 1",
		},
		{
			// SS byte 0x03 with an unmapped card type byte.
			name: "iso 14443 type a part 3, unmapped type",
			atr:  "3B8F8001804F0CA0000003060300420000000069",
			want: "iso 14443 type a, pc/sc part 3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DetectType(mustHex(t, tt.atr)); got != tt.want {
				t.Errorf("DetectType(%s) = %q, want %q", tt.atr, got, tt.want)
			}
		})
	}
}

func TestDetectTypeKnownATRListMatchesFixtures(t *testing.T) {
	t.Parallel()
	types := make([]string, 0, len(knownATR))
	for _, name := range knownATR {
		types = append(types, name)
	}
	slices.Sort(types)
	want := []string{
		"deutschlandticket (vdv-ka)",
		"german eid/passport (npa)",
		"yubikey 5 nfc",
	}
	if !slices.Equal(types, want) {
		t.Errorf("knownATR = %v, want %v", types, want)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	// Without linker injection the fallback is the VCS revision or
	// the current tag (defaultVersion).
	if Version() == "" {
		t.Error("Version() is empty")
	}
}
