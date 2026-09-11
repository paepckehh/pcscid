// Command pcscid prints a short unique identifier for every smart
// card presented to any reader registered with the local pcscd.
//
// In normal mode it prints the bare identifier and a newline, nothing
// else, one line per card presentation. With DEBUG=1 in the
// environment it logs a full verbose trace of every protocol step to
// stderr while stdout stays machine readable.
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
	logger.Debug("pcscid starting", "version", pcscid.Version())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	events, err := pcscid.Watch(ctx, &pcscid.Options{Logger: logger})
	if err != nil {
		return err
	}
	for ev := range events {
		if ev.Kind == pcscid.KindInsert {
			fmt.Println(ev.Card.ID)
		}
	}
	return nil
}

// debugEnabled reports whether DEBUG requests the verbose trace.
// DEBUG=1 is the documented spelling, any other non empty value
// except 0 is accepted as well.
func debugEnabled() bool {
	value := os.Getenv("DEBUG")
	return value != "" && value != "0"
}
