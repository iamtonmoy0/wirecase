// Package cli implements the WIRECASE command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/iamtonmoy0/wirecase/internal/agent"
	"github.com/iamtonmoy0/wirecase/internal/casefile"
	"github.com/iamtonmoy0/wirecase/internal/diagnosis"
	"github.com/iamtonmoy0/wirecase/internal/probe"
	"github.com/iamtonmoy0/wirecase/internal/report"
)

var version = "0.2.0"

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
	case "scrub":
		return scrub(args[1:], stdout, stderr)
	case "diagnose":
		return diagnose(args[1:], stdout, stderr)
	case "report":
		return reportHTML(args[1:], stdout, stderr)
	case "agent":
		return agentCommand(args[1:], stdout, stderr)
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
	names, differences := []string{"dns", "tcp", "ipv6", "tls", "http"}, 0
	fmt.Fprintf(stdout, "Diagnostic comparison\n  A: %s (%s, %s)\n  B: %s (%s, %s)\n", fs.Arg(0), left.CapturedAt.Format(time.RFC3339), vantage(left), fs.Arg(1), right.CapturedAt.Format(time.RFC3339), vantage(right))
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

func vantage(c casefile.Case) string {
	if c.Vantage != "" {
		return c.Vantage
	}
	return "local"
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

func scrub(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scrub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	redactAddresses := fs.Bool("redact-addresses", false, "remove resolved and connected IP addresses")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: wirecase scrub [--redact-addresses] <input.wcase> <output.wcase>")
		return 2
	}
	c, err := casefile.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	c = casefile.Scrub(c, *redactAddresses)
	if err := casefile.Write(fs.Arg(1), c); err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Scrubbed case written to %s\n", fs.Arg(1))
	return 0
}

func diagnose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wirecase diagnose <file.wcase>")
		return 2
	}
	c, err := casefile.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	for _, finding := range diagnosis.Analyze(c) {
		fmt.Fprintf(stdout, "[%s] %s — %s\n  %s\n", strings.ToUpper(finding.Severity), finding.Title, finding.Layer, finding.Explanation)
	}
	return 0
}

func reportHTML(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "output HTML path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *output == "" {
		fmt.Fprintln(stderr, "usage: wirecase report --output report.html <file.wcase>")
		return 2
	}
	c, err := casefile.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: %v\n", err)
		return 1
	}
	f, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(stderr, "wirecase: create report: %v\n", err)
		return 1
	}
	writeErr := report.WriteHTML(f, c)
	closeErr := f.Close()
	if writeErr != nil {
		fmt.Fprintf(stderr, "wirecase: render report: %v\n", writeErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "wirecase: close report: %v\n", closeErr)
		return 1
	}
	fmt.Fprintf(stdout, "Offline report written to %s\n", *output)
	return 0
}

func agentCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		agentUsage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("agent keygen", flag.ContinueOnError)
		fs.SetOutput(stderr)
		privatePath := fs.String("private", "wirecase-agent-private.pem", "private signing key path")
		publicPath := fs.String("public", "wirecase-agent-public.pem", "public verification key path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := agent.GenerateKeyFiles(*privatePath, *publicPath); err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Created signing key %s and verification key %s\n", *privatePath, *publicPath)
		return 0
	case "create-job":
		fs := flag.NewFlagSet("agent create-job", flag.ContinueOnError)
		fs.SetOutput(stderr)
		keyPath := fs.String("private-key", "", "trusted Ed25519 private key")
		target := fs.String("target", "", "HTTP(S) target host")
		output := fs.String("output", "", "new signed job JSON file")
		timeout := fs.Duration("timeout", 5*time.Second, "per-probe timeout (maximum 15s)")
		lifetime := fs.Duration("expires", 24*time.Hour, "job lifetime (maximum 7d)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *keyPath == "" || *target == "" || *output == "" {
			fmt.Fprintln(stderr, "usage: wirecase agent create-job --private-key key.pem --target https://example.com --output job.json")
			return 2
		}
		privateKey, err := agent.LoadPrivateKey(*keyPath)
		if err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		job, err := agent.NewJob(*target, *timeout, *lifetime)
		if err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 2
		}
		signed, err := agent.Sign(job, privateKey)
		if err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		if err := agent.WriteSignedJob(*output, signed); err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Signed job %s written to %s (expires %s)\n", job.ID, *output, job.ExpiresAt.Format(time.RFC3339))
		return 0
	case "run-job":
		fs := flag.NewFlagSet("agent run-job", flag.ContinueOnError)
		fs.SetOutput(stderr)
		publicPath := fs.String("public-key", "", "trusted Ed25519 public key")
		jobPath := fs.String("job", "", "signed job JSON")
		allowedHost := fs.String("allow-host", "", "exact hostname explicitly permitted by this operator")
		label := fs.String("label", "", "shareable vantage label (avoid personal information)")
		output := fs.String("output", "", "output result .wcase file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *publicPath == "" || *jobPath == "" || *allowedHost == "" || *label == "" || *output == "" {
			fmt.Fprintln(stderr, "usage: wirecase agent run-job --public-key key.pem --job job.json --allow-host example.com --label wifi --output result.wcase")
			return 2
		}
		publicKey, err := agent.LoadPublicKey(*publicPath)
		if err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		signed, err := agent.LoadSignedJob(*jobPath)
		if err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		result, err := agent.Run(signed, publicKey, *allowedHost, *label, time.Now())
		if err != nil {
			fmt.Fprintf(stderr, "wirecase: refusing job: %v\n", err)
			return 1
		}
		if err := casefile.Write(*output, result); err != nil {
			fmt.Fprintf(stderr, "wirecase: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Job %s captured from vantage %q; result written to %s\n", result.JobID, result.Vantage, *output)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown agent command %q\n", args[0])
		agentUsage(stderr)
		return 2
	}
}

func agentUsage(w io.Writer) {
	fmt.Fprintln(w, "Agent commands (single-shot; no listener or shell execution):")
	fmt.Fprintln(w, "  agent keygen [--private file.pem] [--public file.pem]")
	fmt.Fprintln(w, "  agent create-job --private-key key.pem --target https://host --output job.json")
	fmt.Fprintln(w, "  agent run-job --public-key key.pem --job job.json --allow-host host --label label --output result.wcase")
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
	fmt.Fprintln(w, "  capture <host-or-url>     Run DNS, TCP, IPv6, TLS, and HTTP probes")
	fmt.Fprintln(w, "  diff <a.wcase> <b.wcase> Compare two diagnostic cases")
	fmt.Fprintln(w, "  inspect <file.wcase>      Print a case as JSON")
	fmt.Fprintln(w, "  scrub [options] <in> <out> Remove sensitive case data")
	fmt.Fprintln(w, "  diagnose <file.wcase>     Explain likely failing layers")
	fmt.Fprintln(w, "  report --output x.html <file.wcase>  Create an offline report")
	fmt.Fprintln(w, "  agent keygen|create-job|run-job Signed restricted diagnostic jobs")
	fmt.Fprintln(w, "  version                   Print version\n\nRun 'wirecase capture --help' for capture options.")
}
