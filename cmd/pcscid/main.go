// Command pcscid prints a short unique identifier for every smart
// card presented to any reader registered with the local pcscd.
//
// In normal mode it prints the bare identifier and a newline, nothing
// else, one line per card presentation. With DEBUG=1 in the
// environment it logs a full verbose trace of every protocol step to
// stderr while stdout stays machine readable.
//
// With PCSCID_HTTP_ADDR set to a listen address, for example
// "127.0.0.1:8976", it additionally serves the loopback HTTP bridge
// (pcscid.Bridge): every card presentation's reader tag and btag as an
// SSE stream plus a polling fallback, so browser pages that cannot
// open the pcscd Unix socket can react to card scans. The address
// must be loopback unless PCSCID_HTTP_ALLOW_REMOTE=1 lifts the guard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"paepcke.de/pcscid"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("pcscid", pcscid.Version())
		return nil
	}

	var logger *slog.Logger
	if debugEnabled() {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	} else {
		logger = slog.New(slog.DiscardHandler)
	}
	fmt.Fprintln(os.Stderr, "pcscid", pcscid.Version())
	logger.Debug("pcscid starting", "version", pcscid.Version())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The loopback HTTP bridge, off unless PCSCID_HTTP_ADDR configures
	// it. A browser sandbox cannot open the pcscd Unix socket, so the
	// bridge is the minimal local footprint for kiosk pages reacting
	// to card scans.
	bridgeAddr := os.Getenv("PCSCID_HTTP_ADDR")
	var bridge *pcscid.Bridge
	if bridgeAddr != "" {
		if err := pcscid.RequireLoopback(bridgeAddr, envEnabled("PCSCID_HTTP_ALLOW_REMOTE")); err != nil {
			return err
		}
		bridge = pcscid.NewBridge(nil)
		go func() {
			logger.Debug("bridge listening", "addr", bridgeAddr)
			if err := bridge.Serve(ctx, bridgeAddr); err != nil {
				fmt.Fprintln(os.Stderr, "pcscid bridge:", err)
			}
		}()
	}

	events, err := pcscid.Watch(ctx, &pcscid.Options{Logger: logger})
	if err != nil {
		return err
	}
	for ev := range events {
		if ev.Kind != pcscid.KindInsert {
			continue
		}
		fmt.Println(pcscid.ReaderTag(ev.Reader) + ": " + ev.Card.ID)
		if bridge != nil {
			bridge.Feed(ev)
		}
	}
	return nil
}

// debugEnabled reports whether DEBUG requests the verbose trace.
// DEBUG=1 is the documented spelling, any other non empty value
// except 0 is accepted as well.
func debugEnabled() bool {
	return envEnabled("DEBUG")
}

// envEnabled reports whether the environment variable holds a truthy
// value: non empty and not "0".
func envEnabled(name string) bool {
	value := os.Getenv(name)
	return value != "" && value != "0"
}
