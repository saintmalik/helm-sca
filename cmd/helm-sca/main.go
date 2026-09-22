package main

import (
	"os"

	"github.com/saintmalik/helm-sca/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
