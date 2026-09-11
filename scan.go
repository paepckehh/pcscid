package pcscid

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
)

// lookScan reports the absolute path of the pcsc_scan binary or an
// error when it is not installed.
func lookScan(scanCommand string) (string, error) {
	return exec.LookPath(scanCommand)
}

// atrLineRe matches the ATR lines pcsc_scan prints, both the
// indented one inside the reader event block and the standalone one
// before its ATR analysis. Date lines, event numbers, reader states
// and the identification dump never carry the "ATR: " prefix, so
// they cannot be mistaken for a card identity.
var atrLineRe = regexp.MustCompile(`^\s*ATR: ((?:[0-9A-Fa-f]{2} )*[0-9A-Fa-f]{2})\s*$`)

// scanParser turns pcsc_scan output lines into events. It is used by
// scanWatch and covered by the pcsc-scan-example-*.txt fixtures.
type scanParser struct {
	reader string
	last   map[string]string // reader to last reported ATR hex
}

func newScanParser() *scanParser {
	return &scanParser{last: make(map[string]string)}
}

// line consumes one output line and reports the event it implies, if
// any. The same ATR is deduplicated until the card is removed, which
// collapses the duplicate event and analysis ATR blocks of one
// insertion into a single event.
func (p *scanParser) line(text string) *Event {
	if strings.Contains(text, " Reader ") {
		if _, name, found := strings.Cut(text, ": "); found {
			p.reader = name
		}
		return nil
	}
	if strings.Contains(text, "Card state: Card removed") {
		if _, tracked := p.last[p.reader]; tracked {
			delete(p.last, p.reader)
			return &Event{Kind: KindRemove, Reader: p.reader}
		}
		return nil
	}
	match := atrLineRe.FindStringSubmatch(text)
	if match == nil {
		return nil
	}
	atr, err := hex.DecodeString(strings.ReplaceAll(match[1], " ", ""))
	if err != nil {
		return nil
	}
	atrHex := strings.ToUpper(hex.EncodeToString(atr))
	if p.last[p.reader] == atrHex {
		return nil // analysis block of the same insertion
	}
	p.last[p.reader] = atrHex
	cardType := DetectType(atr)
	return &Event{
		Kind: KindInsert,
		Card: &Card{
			ID:     Btag(cardType, atr),
			Type:   cardType,
			ATR:    atr,
			Reader: p.reader,
			Source: "scan",
		},
		Reader: p.reader,
	}
}

// scanWatch runs the pcsc_scan command, continuously parses its
// output and feeds events into ch until ctx is cancelled. When the
// tool exits it is restarted. The fallback identifies cards on type
// level only, pcsc_scan never reads a card unique tag.
func scanWatch(ctx context.Context, scanBin string, lg *slog.Logger, ch chan<- Event) {
	defer close(ch)
	lg.Debug("pcsc_scan fallback started, type level identity only", "scan", scanBin)
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, scanBin)
		cmd.Stderr = io.Discard
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			lg.Debug("pcsc_scan pipe failed", "error", err)
			return
		}
		if err := cmd.Start(); err != nil {
			lg.Debug("pcsc_scan start failed", "error", err)
			return
		}
		parser := newScanParser()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			ev := parser.line(scanner.Text())
			if ev == nil {
				continue
			}
			if ev.Kind == KindInsert {
				lg.Debug("card inserted via scan",
					"reader", ev.Reader,
					"id", ev.Card.ID,
					"type", ev.Card.Type,
					"atr", fmt.Sprintf("% X", ev.Card.ATR))
			}
			if !emit(ctx, ch, *ev) {
				_ = cmd.Wait()
				return
			}
		}
		if err := scanner.Err(); err != nil {
			lg.Debug("pcsc_scan output truncated", "error", err)
		}
		waitErr := cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		if waitErr != nil {
			lg.Debug("pcsc_scan exited, restarting", "error", waitErr)
		}
		if !sleepCtx(ctx, reconnectDelay) {
			return
		}
	}
}
