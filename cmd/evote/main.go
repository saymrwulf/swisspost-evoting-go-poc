package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "evote",
	Short: "Swiss Post E-Voting Protocol PoC",
	Long:  "A proof-of-concept reimplementation of the Swiss Post e-voting cryptographic protocol in Go.",
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
