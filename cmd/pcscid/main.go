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
// With PCSCID_USB_PATH_ID set to 1, readers whose driver serves no
// usable hardware serial (the all zero iSerial of the ACS ACR122U
// family) are identified by their physical USB port path instead of
// falling back to the model level tag: one distinct tag per unit,
// stable as long as the reader stays in its port.
//
// With PCSCID_MAC_ID set to 1, the machine identity, the MAC
// addresses of the physical ethernet ports, is mixed into every
// reader tag: identical readers on different machines serve distinct
// tags.
//
// With PCSCID_SIGN_KEY set to the path of a usable, passphrase-less
// ssh-ed25519 private key, every output line is extended by '$' and
// the base64 SSHSIG signature of the line itself, verifiable with
// ssh-keygen -Y verify under the namespace "pcscid" — and the bridge
// serves the same signature per event in its sig field, so kiosk
// pages can forward it to consumers that enforce signed punches.
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

	debugOn := envEnabled("DEBUG")
	// The settings and identity reports below go to stderr at info
	// level even without DEBUG, so an operator always sees the
	// effective setup; only the verbose protocol and probe trace
	// needs DEBUG=1. Stdout stays machine readable either way.
	var logger *slog.Logger
	if debugOn {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}
	fmt.Fprintln(os.Stderr, "pcscid", pcscid.Version())
	logger.Debug("pcscid starting", "version", pcscid.Version())

	// Gather every environment driven parameter once, then dump the
	// whole effective configuration in one always visible startup
	// report on stderr.
	usbPathID := envEnabled("PCSCID_USB_PATH_ID")
	macID := envEnabled("PCSCID_MAC_ID")
	bridgeAddr := os.Getenv("PCSCID_HTTP_ADDR")
	allowRemote := envEnabled("PCSCID_HTTP_ALLOW_REMOTE")
	signKey := os.Getenv("PCSCID_SIGN_KEY")
	logger.Info("settings",
		"version", pcscid.Version(),
		"debug", debugOn,
		"socket", socketSetting(),
		"usb_path_id", usbPathID,
		"mac_id", macID,
		"sign_key", settingOrOff(signKey),
		"http_addr", settingOrOff(bridgeAddr),
		"http_allow_remote", allowRemote)
	if macID {
		if machine := pcscid.MachineID(); machine != "" {
			logger.Info("machine identity detected", "machine", machine)
		} else {
			logger.Info("machine identity not detected, reader tags stay unit level")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The SSHSIG signer: when PCSCID_SIGN_KEY points at a usable
	// ssh-ed25519 private key, every output line carries '$' and the
	// base64 signature of the line itself, so downstream consumers can
	// prove each line came from this kiosk — and the bridge serves the
	// same signature per event (BridgeOptions.Signer), so kiosk pages can
	// forward it to consumers that enforce signed punches. A configured
	// but unusable key fails the startup instead of silently unsigned
	// output. The signer loads BEFORE the bridge so one key serves both
	// surfaces from the start.
	var signer *pcscid.Signer
	if signKey != "" {
		s, err := pcscid.NewSigner(signKey)
		if err != nil {
			return fmt.Errorf("PCSCID_SIGN_KEY: %w", err)
		}
		signer = s
		logger.Debug("line signatures enabled", "key", signKey)
	}

	// The loopback HTTP bridge, off unless PCSCID_HTTP_ADDR configures
	// it. A browser sandbox cannot open the pcscd Unix socket, so the
	// bridge is the minimal local footprint for kiosk pages reacting
	// to card scans. The listener is bound here, so a bad address
	// fails the startup instead of the background goroutine.
	var bridge *pcscid.Bridge
	if bridgeAddr != "" {
		if err := pcscid.RequireLoopback(bridgeAddr, allowRemote); err != nil {
			return err
		}
		ln, err := net.Listen("tcp", bridgeAddr)
		if err != nil {
			return fmt.Errorf("bridge listen on %q: %w", bridgeAddr, err)
		}
		bridge = pcscid.NewBridge(&pcscid.BridgeOptions{Signer: signer})
		go func() {
			logger.Debug("bridge listening", "addr", bridgeAddr)
			if err := bridge.ServeListener(ctx, ln); err != nil {
				fmt.Fprintln(os.Stderr, "pcscid bridge:", err)
			}
		}()
	}

	// Reader identity options: PCSCID_USB_PATH_ID allows the physical
	// USB port path as the per-unit fallback for serial-less readers
	// (stable per port, changes when the reader moves), PCSCID_MAC_ID
	// mixes the machine identity, the hardware MAC addresses of the
	// physical ethernet ports, into every reader tag (distinct tags
	// per machine, not portable across machines).
	events, err := pcscid.Watch(ctx, &pcscid.Options{
		Logger:    logger,
		USBPathID: usbPathID,
		MACID:     macID,
	})
	if err != nil {
		return err
	}
	for ev := range events {
		if ev.Kind != pcscid.KindInsert {
			continue
		}
		readerTag := ev.ReaderTag
		if readerTag == "" {
			readerTag = pcscid.ReaderTagWithUnit(ev.Reader, ev.ReaderSerial, ev.ReaderPort)
		}
		line := "#" + readerTag + ":" + ev.Card.ID
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

// socketSetting describes the pcscd socket the client will dial: the
// PCSCLITE_CSOCK_NAME override when set, the platform defaults
// otherwise.
func socketSetting() string {
	if env := os.Getenv("PCSCLITE_CSOCK_NAME"); env != "" {
		return env + " (PCSCLITE_CSOCK_NAME)"
	}
	return "default (/run/pcscd/pcscd.comm, /var/run/pcscd/pcscd.comm)"
}

// settingOrOff renders an unset parameter as "off" so the settings
// report shows explicitly disabled switches instead of empty strings.
func settingOrOff(value string) string {
	if value == "" {
		return "off"
	}
	return value
}
