package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/evote/pkg/trace"
)

var (
	panelRole  string
	panelFile  string
	panelWidth int
)

// panelViewCmd is run inside each tmux pane. It follows a shared NDJSON event
// file and renders the operations belonging to one stakeholder as ASCII/Unicode
// math. It is an internal helper for `evote cockpit --tmux`, but works standalone
// against any NDJSON trace file.
var panelViewCmd = &cobra.Command{
	Use:    "panelview",
	Short:  "Render one stakeholder's live crypto activity (used by cockpit --tmux)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if panelRole == "" || panelFile == "" {
			return fmt.Errorf("--role and --file are required")
		}
		return runPanelView()
	},
}

func init() {
	panelViewCmd.Flags().StringVar(&panelRole, "role", "", "Stakeholder role to display (or 'voters', 'all')")
	panelViewCmd.Flags().StringVar(&panelFile, "file", "", "Shared NDJSON event file to follow")
	panelViewCmd.Flags().IntVar(&panelWidth, "width", 0, "Wrap width (0 = terminal default)")
	rootCmd.AddCommand(panelViewCmd)
}

// ANSI colors keyed by operation kind.
var kindColor = map[trace.Kind]string{
	trace.KindSign:      "\x1b[35m", // magenta
	trace.KindShuffle:   "\x1b[95m", // bright magenta
	trace.KindEncrypt:   "\x1b[32m", // green
	trace.KindDecrypt:   "\x1b[36m", // cyan
	trace.KindChallenge: "\x1b[33m", // yellow
	trace.KindKeyEx:     "\x1b[34m", // blue
	trace.KindProof:     "\x1b[36m",
	trace.KindVerify:    "\x1b[92m",
	trace.KindSample:    "\x1b[36m",
}

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
)

func panelMatches(role, party string) bool {
	if role == "all" {
		return true
	}
	if role == "voters" {
		return strings.HasPrefix(party, "voter")
	}
	return party == role
}

func runPanelView() error {
	// Header.
	title := panelRole
	switch {
	case panelRole == "voters":
		title = "Voters"
	case strings.HasPrefix(panelRole, "control-component-"):
		title = "CC" + strings.TrimPrefix(panelRole, "control-component-")
	default:
		title = strings.Title(strings.ReplaceAll(panelRole, "-", " "))
	}
	fmt.Printf("%s%s▐ %s ▌%s\n", ansiBold, "\x1b[7m", title, ansiReset)
	fmt.Printf("%swaiting for activity…%s\n", ansiDim, ansiReset)

	f, err := openWithRetry(panelFile, 5*time.Second)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	shown := 0
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if line == `{"done":true}` {
				fmt.Printf("\n%s%s✓ ceremony complete%s\n", ansiBold, "\x1b[32m", ansiReset)
				return nil
			}
			var e trace.Event
			if json.Unmarshal([]byte(line), &e) == nil && panelMatches(panelRole, e.Party) {
				if shown == 0 {
					fmt.Print("\x1b[1A\x1b[2K") // erase the "waiting…" line
				}
				printPanelEvent(e)
				shown++
			}
		}
		if err != nil { // EOF: wait for more lines
			time.Sleep(80 * time.Millisecond)
		}
	}
}

func printPanelEvent(e trace.Event) {
	col := kindColor[e.Kind]
	if col == "" {
		col = "\x1b[37m"
	}
	fmt.Printf("%s%s%-9s%s %s#%d%s %s\n", ansiBold, col, strings.ToUpper(string(e.Kind)), ansiReset,
		ansiDim, e.Seq, ansiReset, e.Caption)
	if e.ASCII != "" {
		fmt.Printf("   %s%s%s\n", col, e.ASCII, ansiReset)
	} else if e.LaTeX != "" {
		fmt.Printf("   %s%s%s\n", ansiDim, e.LaTeX, ansiReset)
	}
	if len(e.Values) > 0 {
		parts := make([]string, 0, len(e.Values))
		for k, v := range e.Values {
			parts = append(parts, fmt.Sprintf("%s=%s", k, trace.Short(v)))
		}
		fmt.Printf("   %s%s%s\n", ansiDim, strings.Join(parts, "  "), ansiReset)
	}
}

// openWithRetry waits up to timeout for the file to appear (the writer may start
// a moment after the panes).
func openWithRetry(path string, timeout time.Duration) (*os.File, error) {
	deadline := time.Now().Add(timeout)
	for {
		f, err := os.Open(path)
		if err == nil {
			return f, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}
