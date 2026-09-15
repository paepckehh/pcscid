// Command pcscid prints a short unique identifier for every smart
// card presented to any reader registered with the local pcscd.
//
// In normal mode stdout carries one line per card presentation and
// nothing else: a '#' mark, the reader tag, a colon and the btag. A
// version banner always goes to stderr; with DEBUG=1 in the
// environment stderr additionally carries a full verbose trace of
// every protocol step, while stdout stays machine readable.
//
// With PCSCID_HTTP_ADDR set to a listen address, for example
// "127.0.0.1:8976", it additionally serves the loopback HTTP bridge
// (pcscid.Bridge): every card presentation's reader tag and btag as an
// SSE stream plus a polling fallback, so browser pages that cannot
// open the pcscd Unix socket can react to card scans. The address
// must be loopback unless PCSCID_HTTP_ALLOW_REMOTE=1 lifts the guard.
//
// With PCSCID_SIGN_KEY set to the path of a usable, passphrase-less
// ssh-ed25519 private key, every output line is extended by '$' and
// the base64 SSHSIG signature of the line itself, verifiable with
// ssh-keygen -Y verify under the namespace "pcscid".
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
	if envEnabled("DEBUG") {
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
	// to card scans. The listener is bound here, so a bad address
	// fails the startup instead of the background goroutine.
	bridgeAddr := os.Getenv("PCSCID_HTTP_ADDR")
	var bridge *pcscid.Bridge
	if bridgeAddr != "" {
		if err := pcscid.RequireLoopback(bridgeAddr, envEnabled("PCSCID_HTTP_ALLOW_REMOTE")); err != nil {
			return err
		}
		ln, err := net.Listen("tcp", bridgeAddr)
		if err != nil {
			return fmt.Errorf("bridge listen on %q: %w", bridgeAddr, err)
		}
		bridge = pcscid.NewBridge(nil)
		go func() {
			logger.Debug("bridge listening", "addr", bridgeAddr)
			if err := bridge.ServeListener(ctx, ln); err != nil {
				fmt.Fprintln(os.Stderr, "pcscid bridge:", err)
			}
		}()
	}

	// The SSHSIG signer: when PCSCID_SIGN_KEY points at a usable
	// ssh-ed25519 private key, every output line carries '$' and the
	// base64 signature of the line itself, so downstream consumers can
	// prove each line came from this kiosk. A configured but unusable
	// key fails the startup instead of silently unsigned output.
	var signer *pcscid.Signer
	if keyPath := os.Getenv("PCSCID_SIGN_KEY"); keyPath != "" {
		s, err := pcscid.NewSigner(keyPath)
		if err != nil {
			return fmt.Errorf("PCSCID_SIGN_KEY: %w", err)
		}
		signer = s
		logger.Debug("line signatures enabled", "key", keyPath)
	}

	events, err := pcscid.Watch(ctx, &pcscid.Options{Logger: logger})
	if err != nil {
		return err
	}
	for ev := range events {
		if ev.Kind != pcscid.KindInsert {
			continue
		}
		line := "#" + pcscid.ReaderTagWithUnit(ev.Reader, ev.ReaderSerial, ev.ReaderPort) + ":" + ev.Card.ID
		if signer != nil {
			line = signer.SignLine(line)
		}
		fmt.Println(line)
		if bridge != nil {
			bridge.Feed(ev)
		}
	}
	return nil
}

// envEnabled reports whether the environment variable holds a truthy
// value: non empty and not "0".
func envEnabled(name string) bool {
	value := os.Getenv(name)
	return value != "" && value != "0"
}
