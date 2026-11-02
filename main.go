// ifstat - sample traffic statistics for a network interface on Linux.
//
// It reads the kernel counters from /proc/net/dev at the start and end of a
// sampling window (default 30s) and reports totals and average rates. While
// sampling it also captures packets (AF_PACKET, needs root or CAP_NET_RAW) to
// report the top connections, ports and talkers.
//
// Usage:
//
//	sudo ifstat -i eth0
//	sudo ifstat -i eth0 -d 10s -top 20 -sort bytes
//	sudo ifstat -i wlan0 -d 1m -interval 5s -no-local
//	ifstat -i eth0 -no-capture      # counters only, no privileges needed
//	ifstat -list
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const procNetDev = "/proc/net/dev"

// Counters holds the raw kernel counters for one interface.
type Counters struct {
	RxBytes, RxPackets, RxErrs, RxDrop uint64
	TxBytes, TxPackets, TxErrs, TxDrop uint64
}

// readAll parses /proc/net/dev and returns counters keyed by interface name.
func readAll() (map[string]Counters, error) {
	f, err := os.Open(procNetDev)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]Counters)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // header lines have no colon-separated interface name
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			continue
		}
		vals := make([]uint64, 16)
		for i := 0; i < 16; i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing %s for %s: %w", fields[i], name, err)
			}
			vals[i] = v
		}
		result[name] = Counters{
			RxBytes: vals[0], RxPackets: vals[1], RxErrs: vals[2], RxDrop: vals[3],
			TxBytes: vals[8], TxPackets: vals[9], TxErrs: vals[10], TxDrop: vals[11],
		}
	}
	return result, sc.Err()
}

func interfaceNames(m map[string]Counters) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// read returns counters for a single interface.
func read(iface string) (Counters, error) {
	all, err := readAll()
	if err != nil {
		return Counters{}, err
	}
	c, ok := all[iface]
	if !ok {
		return Counters{}, fmt.Errorf("interface %q not found (available: %s)",
			iface, strings.Join(interfaceNames(all), ", "))
	}
	return c, nil
}

// delta returns end-start and reports whether the counter appeared to reset.
func delta(start, end uint64, reset *bool) uint64 {
	if end < start {
		*reset = true
		return 0
	}
	return end - start
}

// Diff is the change in counters over a sampling window.
type Diff struct {
	Counters
	Elapsed time.Duration
	Reset   bool // a counter went backwards (e.g. interface was reset)
}

func diff(a, b Counters, elapsed time.Duration) Diff {
	d := Diff{Elapsed: elapsed}
	d.RxBytes = delta(a.RxBytes, b.RxBytes, &d.Reset)
	d.RxPackets = delta(a.RxPackets, b.RxPackets, &d.Reset)
	d.RxErrs = delta(a.RxErrs, b.RxErrs, &d.Reset)
	d.RxDrop = delta(a.RxDrop, b.RxDrop, &d.Reset)
	d.TxBytes = delta(a.TxBytes, b.TxBytes, &d.Reset)
	d.TxPackets = delta(a.TxPackets, b.TxPackets, &d.Reset)
	d.TxErrs = delta(a.TxErrs, b.TxErrs, &d.Reset)
	d.TxDrop = delta(a.TxDrop, b.TxDrop, &d.Reset)
	return d
}

// humanBytes formats a byte count using binary units.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// humanBits formats a bits-per-second rate using decimal (network) units.
func humanBits(bps float64) string {
	units := []string{"bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"}
	i := 0
	for bps >= 1000 && i < len(units)-1 {
		bps /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", bps, units[i])
}

func rate(n uint64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / d.Seconds()
}

func printReport(iface string, d Diff, partial bool) {
	title := "Traffic statistics"
	if partial {
		title += " (interrupted - partial sample)"
	}
	fmt.Printf("\n%s for %s over %s\n", title, iface, d.Elapsed.Round(time.Millisecond))
	fmt.Println(strings.Repeat("-", 64))
	fmt.Printf("%-4s %14s %12s %16s %12s %8s %8s\n",
		"", "Total", "Packets", "Avg rate", "Avg pkt/s", "Errors", "Drops")
	row := func(label string, bytes, pkts, errs, drops uint64) {
		fmt.Printf("%-4s %14s %12d %16s %12.1f %8d %8d\n",
			label, humanBytes(bytes), pkts,
			humanBits(rate(bytes, d.Elapsed)*8),
			rate(pkts, d.Elapsed), errs, drops)
	}
	row("RX", d.RxBytes, d.RxPackets, d.RxErrs, d.RxDrop)
	row("TX", d.TxBytes, d.TxPackets, d.TxErrs, d.TxDrop)
	totalBytes := d.RxBytes + d.TxBytes
	fmt.Printf("%-4s %14s %12d %16s %12.1f\n", "ALL",
		humanBytes(totalBytes), d.RxPackets+d.TxPackets,
		humanBits(rate(totalBytes, d.Elapsed)*8),
		rate(d.RxPackets+d.TxPackets, d.Elapsed))
	if d.Reset {
		fmt.Println("\nWarning: a counter went backwards (interface reset?); affected values were reported as 0.")
	}
}

type options struct {
	iface     string
	duration  time.Duration
	interval  time.Duration
	list      bool
	top       int
	byBytes   bool
	noLocal   bool
	noCapture bool
}

func main() {
	var (
		o      options
		sortBy string
	)
	flag.StringVar(&o.iface, "i", "", "network interface to monitor (e.g. eth0)")
	flag.DurationVar(&o.duration, "d", 30*time.Second, "sample duration (e.g. 10s, 1m, 2m30s)")
	flag.DurationVar(&o.interval, "interval", 0, "print live per-interval rates every N (e.g. 5s); 0 disables")
	flag.BoolVar(&o.list, "list", false, "list available interfaces and exit")
	flag.IntVar(&o.top, "top", 10, "number of entries in each top-N table")
	flag.StringVar(&sortBy, "sort", "packets", `rank top-N tables by "packets" or "bytes"`)
	flag.BoolVar(&o.noLocal, "no-local", false, "omit this interface's own addresses from the top talkers")
	flag.BoolVar(&o.noCapture, "no-capture", false, "skip packet capture (counters only; no root needed)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -i <interface> [options]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	switch sortBy {
	case "packets":
	case "bytes":
		o.byBytes = true
	default:
		fmt.Fprintln(os.Stderr, `error: -sort must be "packets" or "bytes"`)
		os.Exit(1)
	}

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	all, err := readAll()
	if err != nil {
		return fmt.Errorf("reading %s (this tool requires Linux): %w", procNetDev, err)
	}
	if o.list {
		for _, n := range interfaceNames(all) {
			fmt.Println(n)
		}
		return nil
	}
	if o.iface == "" {
		return errors.New("an interface is required: use -i <name> (try -list to see available ones)")
	}
	if o.duration <= 0 {
		return errors.New("duration must be greater than zero")
	}
	if o.interval < 0 {
		return errors.New("interval must not be negative")
	}
	if o.top < 1 {
		return errors.New("top must be at least 1")
	}
	if _, ok := all[o.iface]; !ok {
		return fmt.Errorf("interface %q not found (available: %s)",
			o.iface, strings.Join(interfaceNames(all), ", "))
	}

	// Allow Ctrl-C to stop early and still print a report.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the packet capture first so it covers the whole sample window.
	capCtx, capCancel := context.WithCancel(ctx)
	defer capCancel()
	var pc *Capture
	if !o.noCapture {
		pc, err = StartCapture(capCtx, o.iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: packet capture disabled: %v\n", err)
		}
	}

	start, err := read(o.iface)
	if err != nil {
		return err
	}
	startTime := time.Now()
	fmt.Printf("Sampling %s for %s (Ctrl-C to stop early)...\n", o.iface, o.duration)

	deadline := time.NewTimer(o.duration)
	defer deadline.Stop()

	var tick <-chan time.Time
	if o.interval > 0 {
		t := time.NewTicker(o.interval)
		defer t.Stop()
		tick = t.C
		fmt.Printf("%-10s %16s %16s\n", "elapsed", "RX rate", "TX rate")
	}

	last, lastTime := start, startTime
	partial := false

loop:
	for {
		select {
		case <-deadline.C:
			break loop
		case <-ctx.Done():
			partial = true
			break loop
		case now := <-tick:
			cur, err := read(o.iface)
			if err != nil {
				return err
			}
			d := diff(last, cur, now.Sub(lastTime))
			fmt.Printf("%-10s %16s %16s\n",
				now.Sub(startTime).Round(time.Second),
				humanBits(rate(d.RxBytes, d.Elapsed)*8),
				humanBits(rate(d.TxBytes, d.Elapsed)*8))
			last, lastTime = cur, now
		}
	}

	end, err := read(o.iface)
	if err != nil {
		return err
	}
	elapsed := time.Since(startTime)

	// Stop the capture and wait for it to finish before reading its results.
	capCancel()
	if pc != nil {
		pc.Wait()
	}

	printReport(o.iface, diff(start, end, elapsed), partial)
	if pc != nil {
		pc.Report(o.top, o.byBytes, o.noLocal)
	}
	return nil
}
