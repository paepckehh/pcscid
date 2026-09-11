package pcscid

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseProtocols(t *testing.T, spec string) []byte {
	t.Helper()
	var out []byte
	for p := range strings.SplitSeq(spec, ",") {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, byte(n))
	}
	return out
}

func TestParseATR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		atr        string
		historical string
		protocols  string
		tck        byte
		hasTCK     bool
		checksum   bool
		wantErr    string
	}{
		{
			name:       "mifare classic 1k",
			atr:        "3B8F8001804F0CA000000306030001000000006A",
			historical: "804F0CA00000030603000100000000",
			protocols:  "0,1",
			tck:        0x6A,
			hasTCK:     true,
			checksum:   true,
		},
		{
			name:       "german npa",
			atr:        "3B8480018082900097",
			historical: "80829000",
			protocols:  "0,1",
			tck:        0x97,
			hasTCK:     true,
			checksum:   true,
		},
		{
			name:       "deutschlandticket",
			atr:        "3B8580015A4356445659",
			historical: "5A43564456",
			protocols:  "0,1",
			tck:        0x59,
			hasTCK:     true,
			checksum:   true,
		},
		{
			name:       "yubikey 5 nfc",
			atr:        "3B8D80018073C021C057597562694B65FF7F",
			historical: "8073C021C057597562694B65FF",
			protocols:  "0,1",
			tck:        0x7F,
			hasTCK:     true,
			checksum:   true,
		},
		{
			name:       "plain t=0",
			atr:        "3B00",
			historical: "",
			protocols:  "0",
			hasTCK:     false,
			checksum:   true,
		},
		{
			name:    "too short",
			atr:     "3B",
			wantErr: "atr too short",
		},
		{
			name:    "bad initial character",
			atr:     "3A00",
			wantErr: "invalid atr initial character",
		},
		{
			name:    "truncated interface bytes",
			atr:     "3B70",
			wantErr: "missing interface byte",
		},
		{
			name:    "truncated historical bytes",
			atr:     "3B02",
			wantErr: "expected 2 historical bytes",
		},
		{
			name:    "trailing bytes",
			atr:     "3B0001",
			wantErr: "trailing bytes",
		},
		{
			name:    "missing tck",
			atr:     "3B84800180829000",
			wantErr: "missing tck",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			atr := mustHex(t, tt.atr)
			got, err := ParseATR(atr)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseATR(% X) = nil error, want containing %q", atr, tt.wantErr)
				}
				if !bytes.Contains([]byte(err.Error()), []byte(tt.wantErr)) {
					t.Errorf("ParseATR(% X) error = %q, want containing %q", atr, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseATR(% X): %v", atr, err)
			}
			if !bytes.Equal(got.Historical, mustHex(t, tt.historical)) {
				t.Errorf("historical = % X, want % X", got.Historical, mustHex(t, tt.historical))
			}
			if !bytes.Equal(got.Protocols, parseProtocols(t, tt.protocols)) {
				t.Errorf("protocols = %v, want %v", got.Protocols, tt.protocols)
			}
			if got.HasTCK != tt.hasTCK {
				t.Errorf("hasTCK = %v, want %v", got.HasTCK, tt.hasTCK)
			}
			if got.TCK != tt.tck {
				t.Errorf("tck = 0x%02X, want 0x%02X", got.TCK, tt.tck)
			}
			if got.ChecksumOK(atr) != tt.checksum {
				t.Errorf("ChecksumOK = %v, want %v", got.ChecksumOK(atr), tt.checksum)
			}
		})
	}
}

func TestParseATRBadChecksum(t *testing.T) {
	t.Parallel()
	// German npa ATR with a broken last byte.
	atr := mustHex(t, "3B84800180829000FF")
	parsed, err := ParseATR(atr)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ChecksumOK(atr) {
		t.Error("ChecksumOK = true for corrupted TCK, want false")
	}
}

func TestParseATRInterfaceGroups(t *testing.T) {
	t.Parallel()
	// Yubikey: TD1 = 80, TD2 = 01, one group each.
	parsed, err := ParseATR(mustHex(t, "3B8D80018073C021C057597562694B65FF7F"))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.InterfaceBytes) != 2 {
		t.Fatalf("interface groups = %d, want 2", len(parsed.InterfaceBytes))
	}
	if !bytes.Equal(parsed.InterfaceBytes[0], []byte{0x80}) {
		t.Errorf("group 1 = % X, want 80", parsed.InterfaceBytes[0])
	}
	if !bytes.Equal(parsed.InterfaceBytes[1], []byte{0x01}) {
		t.Errorf("group 2 = % X, want 01", parsed.InterfaceBytes[1])
	}
}
