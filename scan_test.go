package pcscid

import (
	"bufio"
	"os"
	"slices"
	"testing"
)

// parseScanLines feeds lines through a fresh scanParser.
func parseScanLines(lines ...string) []Event {
	parser := newScanParser()
	var events []Event
	for _, line := range lines {
		if ev := parser.line(line); ev != nil {
			events = append(events, *ev)
		}
	}
	return events
}

// parseScanCapture feeds one pcsc_scan capture file through a fresh
// scanParser.
func parseScanCapture(t *testing.T, path string) []Event {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parser := newScanParser()
	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if ev := parser.line(scanner.Text()); ev != nil {
			events = append(events, *ev)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func TestScanParserExampleCaptures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file     string
		atr      string
		cardType string
	}{
		{
			file:     "pcsc-scan-example-mifare-01.txt",
			atr:      "3B8F8001804F0CA000000306030001000000006A",
			cardType: "mifare classic 1k",
		},
		{
			file:     "pcsc-scan-example-mifare-02.txt",
			atr:      "3B8F8001804F0CA000000306030001000000006A",
			cardType: "mifare classic 1k",
		},
		{
			file:     "pcsc-scan-example-mifare-03.txt",
			atr:      "3B8F8001804F0CA000000306030001000000006A",
			cardType: "mifare classic 1k",
		},
		{
			file:     "pcsc-scan-example-mifare-04.txt",
			atr:      "3B8F8001804F0CA000000306030001000000006A",
			cardType: "mifare classic 1k",
		},
		{
			file:     "pcsc-scan-example-nfc-dticket.txt",
			atr:      "3B8580015A4356445659",
			cardType: "deutschlandticket (vdv-ka)",
		},
		{
			file:     "pcsc-scan-example-nfc-npa.txt",
			atr:      "3B8480018082900097",
			cardType: "german eid/passport (npa)",
		},
		{
			file:     "pcsc-scan-example-nfc-yubikey.txt",
			atr:      "3B8D80018073C021C057597562694B65FF7F",
			cardType: "yubikey 5 nfc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			atr := mustHex(t, tt.atr)
			events := parseScanCapture(t, tt.file)
			want := []Event{
				{
					Kind:   KindInsert,
					Card:   &Card{ID: Btag(tt.cardType, atr), Type: tt.cardType, ATR: atr, Reader: "ACS ACR122U 00 00", Source: "scan"},
					Reader: "ACS ACR122U 00 00",
				},
				{Kind: KindRemove, Reader: "ACS ACR122U 00 00"},
			}
			if len(events) != len(want) {
				t.Fatalf("events = %d, want %d: %+v", len(events), len(want), events)
			}
			for i, ev := range events {
				if ev.Kind != want[i].Kind {
					t.Errorf("event %d kind = %v, want %v", i, ev.Kind, want[i].Kind)
				}
				if ev.Reader != want[i].Reader {
					t.Errorf("event %d reader = %q, want %q", i, ev.Reader, want[i].Reader)
				}
			}
			card := events[0].Card
			exp := want[0].Card
			if card.ID != exp.ID || card.Type != exp.Type || card.Source != exp.Source {
				t.Errorf("card = id %q type %q source %q, want id %q type %q source %q",
					card.ID, card.Type, card.Source, exp.ID, exp.Type, exp.Source)
			}
			if !slices.Equal(card.ATR, atr) {
				t.Errorf("atr = % X, want % X", card.ATR, atr)
			}
		})
	}
}

func TestScanParserIgnoresNoise(t *testing.T) {
	t.Parallel()
	events := parseScanLines(
		"Insert or remove a card or a reader..",
		"Fri Sep 11 08:03:02 2026",
		" Reader 0: ACS ACR122U 00 00",
		"  Event number: 5",
		"  Card state: Card inserted,",
		"Possibly identified card (using ...smartcard_list.txt):",
		"3B 84 80 01 80 82 90 00 97",
		"  ATR: 3B 84 80 01 80 82 90 00 97",
		"Insert or remove a card or a reader... /  (use Ctrl-C to exit)",
	)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Kind != KindInsert {
		t.Fatalf("kind = %v, want insert", ev.Kind)
	}
	if ev.Reader != "ACS ACR122U 00 00" {
		t.Errorf("reader = %q", ev.Reader)
	}
	atr := mustHex(t, "3B8480018082900097")
	if !slices.Equal(ev.Card.ATR, atr) {
		t.Errorf("atr = % X, want % X", ev.Card.ATR, atr)
	}
	if ev.Card.ID != Btag("german eid/passport (npa)", atr) {
		t.Errorf("id = %q", ev.Card.ID)
	}
}

func TestScanParserDeduplicatesAnalysisBlock(t *testing.T) {
	t.Parallel()
	events := parseScanLines(
		" Reader 0: R",
		"  ATR: 3B 84 80 01 80 82 90 00 97",
		"ATR: 3B 84 80 01 80 82 90 00 97",
	)
	if len(events) != 1 {
		t.Fatalf("events = %d, want the analysis block to collapse", len(events))
	}
}

func TestScanParserRemoveOnlyAfterTrackedInsert(t *testing.T) {
	t.Parallel()
	events := parseScanLines(
		" Reader 0: R",
		"  Card state: Card removed,", // leading removal, no tracked card
		"  ATR: 3B 00",
		"  Card state: Card removed,", // real removal
		"  Card state: Card removed,", // duplicate removal
	)
	if len(events) != 2 {
		t.Fatalf("events = %d, want insert plus one removal: %+v", len(events), events)
	}
	if events[0].Kind != KindInsert || events[1].Kind != KindRemove {
		t.Errorf("kinds = %v, %v, want insert, remove", events[0].Kind, events[1].Kind)
	}
}

func TestScanParserTracksReadersSeparately(t *testing.T) {
	t.Parallel()
	events := parseScanLines(
		" Reader 0: R0",
		"  ATR: 3B 00",
		" Reader 1: R1",
		"  ATR: 3B 00",
		" Reader 1: R1",
		"  Card state: Card removed,",
		" Reader 0: R0",
		"  Card state: Card removed,",
	)
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4: %+v", len(events), events)
	}
	wantKinds := []Kind{KindInsert, KindInsert, KindRemove, KindRemove}
	wantReaders := []string{"R0", "R1", "R1", "R0"}
	for i, ev := range events {
		if ev.Kind != wantKinds[i] {
			t.Errorf("event %d kind = %v, want %v", i, ev.Kind, wantKinds[i])
		}
		if ev.Reader != wantReaders[i] {
			t.Errorf("event %d reader = %q, want %q", i, ev.Reader, wantReaders[i])
		}
	}
}

func TestScanParserRejectsMalformedATRLine(t *testing.T) {
	t.Parallel()
	events := parseScanLines(
		" Reader 0: R",
		"  ATR: 3B 84 80 ZZ", // non hex
		"  ATR: 3B 8",        // odd digit count
	)
	if len(events) != 0 {
		t.Errorf("events = %d, want 0: %+v", len(events), events)
	}
}

func TestScanParserTrailingJunkLine(t *testing.T) {
	t.Parallel()
	// A line with the ATR prefix but extra text after the hex bytes
	// must not be treated as a card identity.
	if events := parseScanLines("ATR: 3B 84 80 01 80 82 90 00 97 extra"); len(events) != 0 {
		t.Errorf("events = %d, want 0", len(events))
	}
}
