package main

import (
	"github.com/spf13/cobra"
	"github.com/user/evote/pkg/protocol"
)

var demoVoters int
var demoOptions int

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run a full election ceremony end-to-end",
	Long:  "Runs setup → vote → tally → verify in one command.",
	Run: func(cmd *cobra.Command, args []string) {
		protocol.RunDemoElection(demoVoters, demoOptions)
	},
}

func init() {
	demoCmd.Flags().IntVar(&demoVoters, "voters", 10, "Number of voters")
	demoCmd.Flags().IntVar(&demoOptions, "options", 2, "Number of voting options")
	rootCmd.AddCommand(demoCmd)
}
