package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/user/evote/pkg/protocol"
)

var demoVoters int
var demoOptions int

const maxDemoScale = 10000

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run a full election ceremony end-to-end",
	Long:  "Runs setup → vote → tally → verify in one command.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if demoVoters < 0 || demoVoters > maxDemoScale {
			return fmt.Errorf("--voters must be in [0, %d], got %d", maxDemoScale, demoVoters)
		}
		if demoOptions < 1 || demoOptions > maxDemoScale {
			return fmt.Errorf("--options must be in [1, %d], got %d", maxDemoScale, demoOptions)
		}
		protocol.RunDemoElection(demoVoters, demoOptions)
		return nil
	},
}

func init() {
	demoCmd.Flags().IntVar(&demoVoters, "voters", 10, "Number of voters")
	demoCmd.Flags().IntVar(&demoOptions, "options", 2, "Number of voting options")
	rootCmd.AddCommand(demoCmd)
}
