package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/spf13/cobra"
	"github.com/user/evote/pkg/party"
	"github.com/user/evote/pkg/protocol"
)

var (
	netVoters  int
	netOptions int
	netVerbose bool
)

var netdemoCmd = &cobra.Command{
	Use:   "netdemo",
	Short: "Run the full election as separate parties over Rust-signed transport",
	Long: "Runs setup, voting, tally, and verification as distinct endpoints " +
		"(setup component, 4 control components, electoral board, voting server, " +
		"voters, verifier) communicating only through Ed25519-signed, X25519-" +
		"encrypted messages — all transport cryptography performed in Rust.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if netVoters < 1 || netVoters > 1000 {
			return fmt.Errorf("--voters must be in [1, 1000], got %d", netVoters)
		}
		if netOptions < 1 || netOptions > 1000 {
			return fmt.Errorf("--options must be in [1, 1000], got %d", netOptions)
		}
		return runNetDemo(netVoters, netOptions, netVerbose)
	},
}

func init() {
	netdemoCmd.Flags().IntVar(&netVoters, "voters", 5, "Number of voters")
	netdemoCmd.Flags().IntVar(&netOptions, "options", 3, "Number of voting options")
	netdemoCmd.Flags().BoolVar(&netVerbose, "verbose", false, "Log every transport message")
	rootCmd.AddCommand(netdemoCmd)
}

func runNetDemo(voters, options int, verbose bool) error {
	cfg := protocol.DefaultConfig(voters, options)

	logf := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }
	if !verbose {
		// Non-verbose: suppress the per-message transport lines but keep phase
		// summaries. The bus log lines start with "  [transport]".
		logf = func(format string, a ...any) {
			if len(format) >= 14 && format[:14] == "  [transport] " {
				return
			}
			fmt.Printf(format+"\n", a...)
		}
	}

	fmt.Println("========================================")
	fmt.Println(" Swiss Post E-Voting — Multi-Party PoC")
	fmt.Println("========================================")
	fmt.Printf(" Voters: %d, Options: %d, Parties: %d\n",
		voters, options, 4+cfg.NumCCs+voters)

	c, err := party.NewCeremony(cfg, logf)
	if err != nil {
		return err
	}
	if err := c.Handshake(); err != nil {
		return err
	}
	if err := c.RunSetup(); err != nil {
		return err
	}
	if err := c.RunCards(); err != nil {
		return err
	}

	// Random selections (one option per voter) via CSPRNG.
	selections := make([][]int, voters)
	for v := 0; v < voters; v++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(options)))
		if err != nil {
			return err
		}
		selections[v] = []int{int(n.Int64())}
	}
	if err := c.RunVoting(selections); err != nil {
		return err
	}
	if err := c.RunTally(); err != nil {
		return err
	}
	if err := c.RunVerify(); err != nil {
		fmt.Printf("\nVERIFICATION FAILED: %v\n", err)
		return err
	}

	fmt.Println("\n--- ELECTION RESULT ---")
	result := c.Result()
	opts := make([]int, 0, len(result))
	for opt := range result {
		opts = append(opts, opt)
	}
	sort.Ints(opts)
	for _, opt := range opts {
		fmt.Printf("  Option %d: %d votes\n", opt, result[opt])
	}
	fmt.Printf("\n  Verified transport messages carried: %d\n", c.Bus.Count())
	fmt.Println("  All parties authenticated via Ed25519 (Rust); channels via X25519 ECDH (Rust).")
	fmt.Println("  Election integrity: VERIFIED")
	return nil
}
