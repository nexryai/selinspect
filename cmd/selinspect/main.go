package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/nexryai/selinspect/internal/policy"
	"github.com/nexryai/selinspect/internal/procfs"
	"github.com/nexryai/selinspect/internal/selinux"
)

const version = "0.1.0-dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "selinspect:", err)
		os.Exit(1)
	}
}
func run() error {
	versionFlag := flag.Bool("version", false, "print version")
	flag.Bool("no-color", false, "disable color (core diagnostic output is monochrome)")
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
	ctx := context.Background()
	fmt.Println("SELinux:", selinux.Enforcement())
	processes, err := (procfs.Source{}).List(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Process inventory: %d entries\n", len(processes))
	backend, err := policy.New(ctx, "")
	if err != nil {
		fmt.Println(err)
		return nil
	}
	types, err := backend.Types(ctx)
	if err != nil {
		fmt.Println("Limited mode:", err)
		return nil
	}
	fmt.Printf("Policy Types: %d\n", len(types))
	return nil
}
