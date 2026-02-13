package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var tallyCmd = &cobra.Command{
	Use:   "tally",
	Short: "Run the tally phase (requires voted artifacts)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Tally subcommand: use 'evote demo' for the full ceremony.")
		fmt.Println("Standalone tally requires loading voted artifacts from JSON.")
	},
}

func init() {
	rootCmd.AddCommand(tallyCmd)
}
