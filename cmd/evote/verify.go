package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify all proofs (requires tallied artifacts)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Verify subcommand: use 'evote demo' for the full ceremony.")
		fmt.Println("Standalone verify requires loading tallied artifacts from JSON.")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
