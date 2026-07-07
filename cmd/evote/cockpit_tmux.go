package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/user/evote/pkg/party"
	"github.com/user/evote/pkg/trace"
)

// runCockpitTmux runs the ceremony and shows one tmux pane per stakeholder, each
// rendering that party's live crypto activity as ASCII/Unicode math. The panes
// follow a shared NDJSON event file that the ceremony writes to, paced.
func runCockpitTmux() error {
	if _, err := exec.LookPath("tmux"); err != nil {
		return fmt.Errorf("tmux not found on PATH: %w", err)
	}
	if os.Getenv("TMUX") != "" {
		return fmt.Errorf("already inside a tmux session — run `evote cockpit --tmux` from a plain terminal (tmux cannot nest an attach)")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Shared event file the panes tail and the ceremony appends to.
	f, err := os.CreateTemp("", "evote-cockpit-*.ndjson")
	if err != nil {
		return err
	}
	eventPath := f.Name()
	defer os.Remove(eventPath)

	// One pane per infrastructure party, plus one aggregate pane for all voters.
	panes := []string{
		party.NameSetup,
		party.CCName(0), party.CCName(1), party.CCName(2), party.CCName(3),
		party.NameEB, party.NameServer, party.NameVerifier,
		"voters",
	}

	session := "evote-cockpit"
	_ = exec.Command("tmux", "kill-session", "-t", session).Run() // best-effort clean slate

	paneCmd := func(role string) string {
		return fmt.Sprintf("%s panelview --role=%s --file=%s", exe, role, eventPath)
	}

	// First pane creates the (detached) session.
	if out, err := exec.Command("tmux", "new-session", "-d", "-s", session, paneCmd(panes[0])).CombinedOutput(); err != nil {
		return fmt.Errorf("tmux new-session: %v: %s", err, out)
	}
	for _, role := range panes[1:] {
		if out, err := exec.Command("tmux", "split-window", "-t", session, paneCmd(role)).CombinedOutput(); err != nil {
			exec.Command("tmux", "kill-session", "-t", session).Run()
			return fmt.Errorf("tmux split-window: %v: %s", err, out)
		}
		// Re-tile after each split so panes stay balanced.
		exec.Command("tmux", "select-layout", "-t", session, "tiled").Run()
	}
	exec.Command("tmux", "select-layout", "-t", session, "tiled").Run()
	exec.Command("tmux", "set-option", "-t", session, "mouse", "on").Run()

	// Run the ceremony in the background, writing paced NDJSON to the file.
	go writeCeremonyEvents(f)

	fmt.Printf("Launching tmux cockpit '%s' — %d panes. Detach with Ctrl-b d; it closes when you exit.\n", session, len(panes))
	time.Sleep(400 * time.Millisecond) // let panes open the file first

	// Attach in the foreground; blocks until the user detaches or exits.
	attach := exec.Command("tmux", "attach", "-t", session)
	attach.Stdin, attach.Stdout, attach.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = attach.Run()

	exec.Command("tmux", "kill-session", "-t", session).Run()
	if err != nil {
		return fmt.Errorf("tmux attach failed (run this from an interactive terminal): %w", err)
	}
	return nil
}

// writeCeremonyEvents subscribes a paced file sink, runs the full ceremony, and
// writes a final done marker.
func writeCeremonyEvents(f *os.File) {
	delay := time.Duration(cockpitDelayMs) * time.Millisecond
	sink := &fileSink{f: f, delay: delay, enc: json.NewEncoder(f)}
	unsub := trace.Subscribe(sink)
	defer unsub()

	_ = runCockpitCeremony()

	f.WriteString(`{"done":true}` + "\n")
	f.Sync()
}

// fileSink appends each event as one JSON line, pacing between events so the
// panes render at a watchable rate.
type fileSink struct {
	f     *os.File
	delay time.Duration
	enc   *json.Encoder
}

func (s *fileSink) Handle(e trace.Event) {
	_ = s.enc.Encode(e) // Encode writes the trailing newline
	s.f.Sync()
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
}
