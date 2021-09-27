package main

import (
	"fmt"
	"os"

	"github.com/motifd/motif-blockchain/cmd/motif/launcher"
)

func main() {
	if err := launcher.Launch(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
