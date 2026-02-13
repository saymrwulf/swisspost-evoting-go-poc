package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var voteCmd = &cobra.Command{
	Use:   "vote",
	Short: "Cast a vote (requires setup artifacts)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Vote subcommand: use 'evote demo' for the full ceremony.")
		fmt.Println("Standalone vote requires loading setup artifacts from JSON.")
	},
}

func init() {
	rootCmd.AddCommand(voteCmd)
}
