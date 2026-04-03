package main

import (
	"fmt"
	"io"
)

func runCLI(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	command := args[0]
	commandArgs := args[1:]
	var err error

	switch command {
	case "init":
		err = cmdInit(commandArgs, stdout, stderr)
	case "install":
		err = cmdInstall(commandArgs, stdout, stderr)
	case "uninstall":
		err = cmdUninstall(commandArgs, stdout, stderr)
	case "doctor":
		err = cmdDoctor(commandArgs, stdout, stderr)
	case "run":
		err = cmdRun(commandArgs, stdin, stdout, stderr)
	case "cleanup":
		err = cmdCleanup(commandArgs, stdout, stderr)
	case "version", "-v", "--version":
		_, err = fmt.Fprintln(stdout, version)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", command)
		printUsage(stderr)
		return 2
	}

	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "prehook - local git hook security gates")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  prehook init")
	fmt.Fprintln(w, "  prehook install")
	fmt.Fprintln(w, "  prehook uninstall")
	fmt.Fprintln(w, "  prehook doctor")
	fmt.Fprintln(w, "  prehook run --stage pre-commit|pre-push")
	fmt.Fprintln(w, "  prehook cleanup")
	fmt.Fprintln(w, "  prehook version")
}
