// Package cli implements the WIRECASE command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
	"github.com/iamtonmoy0/wirecase/internal/probe"
)

const version = "0.1.0"

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "capture":
		return capture(args[1:], stdout, stderr)
	case "diff":
		return diff(args[1:], stdout, stderr)
	case "inspect":
		return inspect(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "wirecase %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func capture(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "output .wcase file (default: <host>-<timestamp>.wcase)")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout for each network probe")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wirecase capture [--output file.wcase] [--timeout 5s] <host-or-url>")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "timeout must be greater than zero")
		return 2
	}
	target, err := probe.ParseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 2
	}
	result, err := probe.Capture(context.Background(), target, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: capture failed: %v\n", err)
		return 1
	}
	path := *output
	if path == "" {
		path = fmt.Sprintf("%s-%s.wcase", safeFilename(target.Host), time.Now().Format("20060102-150405"))
	}
	if err := casefile.Write(path, result); err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Captured %s\nCase: %s\n", target.Value, path)
	for _, item := range result.Results {
		fmt.Fprintf(stdout, "  %-5s %-7s %dms", strings.ToUpper(item.Name), item.Status, item.DurationMS)
		if item.Error != "" {
			fmt.Fprintf(stdout, " — %s", item.Error)
		}
		fmt.Fprintln(stdout)
	}
	return 0
}

func diff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: wirecase diff <baseline.wcase> <comparison.wcase>")
		return 2
	}
	left, err := casefile.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	right, err := casefile.Read(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	if left.Target != right.Target {
		fmt.Fprintf(stdout, "Target differs: %s → %s\n", left.Target, right.Target)
	}
	leftByName, rightByName := make(map[string]casefile.ProbeResult), make(map[string]casefile.ProbeResult)
	for _, result := range left.Results {
		leftByName[result.Name] = result
	}
	for _, result := range right.Results {
		rightByName[result.Name] = result
	}
	names, differences := []string{"dns", "tcp", "tls", "http"}, 0
	fmt.Fprintf(stdout, "Diagnostic comparison\n  A: %s (%s)\n  B: %s (%s)\n", fs.Arg(0), left.CapturedAt.Format(time.RFC3339), fs.Arg(1), right.CapturedAt.Format(time.RFC3339))
	for _, name := range names {
		a, aOK := leftByName[name]
		b, bOK := rightByName[name]
		if !aOK || !bOK {
			fmt.Fprintf(stdout, "  %-5s missing from one case\n", strings.ToUpper(name))
			differences++
			continue
		}
		changed := a.Status != b.Status || !reflect.DeepEqual(a.Details, b.Details) || a.Error != b.Error
		if changed {
			differences++
			fmt.Fprintf(stdout, "  %-5s DIFFERENT  %s → %s\n", strings.ToUpper(name), summary(a), summary(b))
		} else {
			fmt.Fprintf(stdout, "  %-5s same       %s (%dms) → %s (%dms)\n", strings.ToUpper(name), a.Status, a.DurationMS, b.Status, b.DurationMS)
		}
	}
	if differences == 0 {
		fmt.Fprintln(stdout, "No diagnostic evidence differences found.")
	} else {
		fmt.Fprintf(stdout, "%d diagnostic difference(s) found.\n", differences)
	}
	return 0
}

func inspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wirecase inspect <file.wcase>")
		return 2
	}
	c, err := casefile.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		fmt.Fprintf(stderr, "wirecase: write output: %v\n", err)
		return 1
	}
	return 0
}

func summary(result casefile.ProbeResult) string {
	if result.Error != "" {
		return result.Status + " (" + result.Error + ")"
	}
	if result.Details == nil {
		return result.Status
	}
	encoded, err := json.Marshal(result.Details)
	if err != nil {
		return result.Status
	}
	return result.Status + " " + string(encoded)
}

func safeFilename(host string) string {
	name := strings.ToLower(host)
	name = strings.ReplaceAll(name, ":", "-")
	name = strings.ReplaceAll(name, "/", "-")
	if name == "" || name == "." {
		return "case"
	}
	return name
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "WIRECASE — capture and compare network diagnostics\n\nUsage: wirecase <command> [arguments]\n\nCommands:")
	fmt.Fprintln(w, "  capture <host-or-url>     Run DNS, TCP, TLS, and HTTP probes")
	fmt.Fprintln(w, "  diff <a.wcase> <b.wcase> Compare two diagnostic cases")
	fmt.Fprintln(w, "  inspect <file.wcase>      Print a case as JSON")
	fmt.Fprintln(w, "  version                   Print version\n\nRun 'wirecase capture --help' for capture options.")
}
