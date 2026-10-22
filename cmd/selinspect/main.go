package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/nexryai/selinspect/internal/policy"
	"github.com/nexryai/selinspect/internal/tui"
)

const version = "0.1.0-dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "selinspect:", err)
		os.Exit(1)
	}
}
func run() error {
	opts := tui.Options{}
	versionFlag := flag.Bool("version", false, "print version")
	flag.BoolVar(&opts.NoColor, "no-color", false, "monochrome terminal output")
	flag.IntVar(&opts.PID, "pid", 0, "highlight a running PID")
	flag.StringVar(&opts.Type, "type", "", "open an existing policy Type")
	policyFile := flag.String("policy", "", "inspect an offline binary policy (separate from live labels)")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "selinspect — read-only SELinux relationship explorer\n\nUsage: selinspect [options]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *versionFlag {
		fmt.Println("selinspect", version)
		return nil
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments; use --help")
	}
	if *policyFile != "" && opts.PID != 0 {
		return fmt.Errorf("--policy and --pid cannot be combined")
	}
	ctx := context.Background()
	backend, err := policy.New(ctx, *policyFile)
	diagnostics := ""
	if err != nil {
		diagnostics = err.Error()
		backend = nil
	}
	_, err = tea.NewProgram(tui.New(backend, opts, diagnostics)).Run()
	return err
}
