package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/evote/pkg/party"
	"github.com/user/evote/pkg/protocol"
	"github.com/user/evote/pkg/trace"
)

var (
	cockpitPort    int
	cockpitVoters  int
	cockpitOptions int
	cockpitDelayMs int
	cockpitTmux    bool
	cockpitRunning atomic.Bool
)

var cockpitCmd = &cobra.Command{
	Use:   "cockpit",
	Short: "Watch the cryptography execute live in the browser (typeset math)",
	Long: "Runs the multi-party election and streams every cryptographic operation " +
		"— sampling, ElGamal encryption, Fiat-Shamir challenges, the Bayer-Groth " +
		"shuffle, Ed25519 signatures, X25519 key agreement — to a browser page that " +
		"renders each as typeset mathematics with the real runtime values, the instant " +
		"it runs. Open the printed URL.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if cockpitVoters < 1 || cockpitVoters > 200 {
			return fmt.Errorf("--voters must be in [1, 200]")
		}
		if cockpitOptions < 1 || cockpitOptions > 200 {
			return fmt.Errorf("--options must be in [1, 200]")
		}
		if cockpitTmux {
			return runCockpitTmux()
		}
		return runCockpit()
	},
}

func init() {
	cockpitCmd.Flags().IntVar(&cockpitPort, "port", 8090, "HTTP port (browser mode)")
	cockpitCmd.Flags().IntVar(&cockpitVoters, "voters", 3, "Number of voters")
	cockpitCmd.Flags().IntVar(&cockpitOptions, "options", 3, "Number of voting options")
	cockpitCmd.Flags().IntVar(&cockpitDelayMs, "delay", 350, "Milliseconds between events (pacing so it's watchable)")
	cockpitCmd.Flags().BoolVar(&cockpitTmux, "tmux", false, "Terminal mode: one tmux pane per stakeholder instead of the browser")
	rootCmd.AddCommand(cockpitCmd)
}

func runCockpit() error {
	mux := http.NewServeMux()

	// The cockpit page + assets are embedded under web/ (see serve.go's webContent).
	webFS, err := fs.Sub(webContent, "web")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(webFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			data, err := fs.ReadFile(webFS, "cockpit.html")
			if err != nil {
				http.Error(w, "cockpit.html not found", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	// SSE stream: on connect, run one ceremony and stream its crypto events.
	mux.HandleFunc("/events", cockpitEventsHandler)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cockpitPort),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	url := fmt.Sprintf("http://localhost:%d/", cockpitPort)
	fmt.Println("========================================")
	fmt.Println(" Swiss Post E-Voting — Live Crypto Cockpit")
	fmt.Println("========================================")
	fmt.Printf(" Open %s in your browser.\n", url)
	fmt.Printf(" Voters: %d, Options: %d, pacing: %dms/event\n", cockpitVoters, cockpitOptions, cockpitDelayMs)
	fmt.Println(" The election runs when the page connects; every crypto operation")
	fmt.Println(" is rendered as typeset math with its real live values.")
	return srv.ListenAndServe()
}

// cockpitEventsHandler streams one ceremony's crypto events as Server-Sent
// Events. It subscribes a buffered sink, runs the ceremony in a goroutine, and
// drains the buffer to the client with pacing so a human can follow along.
func cockpitEventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// The trace stream and its party/phase context are global, so only one
	// ceremony may run at a time (this is a single-viewer desktop tool).
	if !cockpitRunning.CompareAndSwap(false, true) {
		http.Error(w, "a ceremony is already streaming; reload after it finishes", http.StatusConflict)
		return
	}
	defer cockpitRunning.Store(false)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sink := trace.NewChanSink(8192)
	unsub := trace.Subscribe(sink)
	defer unsub()

	done := make(chan error, 1)
	go func() { done <- runCockpitCeremony() }()

	delay := time.Duration(cockpitDelayMs) * time.Millisecond
	send := func(eventType string, payload any) {
		b, _ := json.Marshal(payload)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, b)
		flusher.Flush()
	}

	for {
		select {
		case e := <-sink.C:
			send("op", e)
			if delay > 0 {
				time.Sleep(delay)
			}
		case err := <-done:
			// Drain any remaining buffered events before closing.
			for {
				select {
				case e := <-sink.C:
					send("op", e)
				default:
					msg := "complete"
					if err != nil {
						msg = "error: " + err.Error()
					}
					send("done", map[string]string{"status": msg})
					return
				}
			}
		case <-r.Context().Done():
			return
		}
	}
}

// runCockpitCeremony runs a full multi-party election (the same one netdemo
// runs), emitting trace events as it goes.
func runCockpitCeremony() error {
	cfg := protocol.DefaultConfig(cockpitVoters, cockpitOptions)
	c, err := party.NewCeremony(cfg, func(string, ...any) {})
	if err != nil {
		return err
	}
	if err := c.RunSetup(); err != nil {
		return err
	}
	if err := c.RunCards(); err != nil {
		return err
	}
	selections := make([][]int, cockpitVoters)
	for v := 0; v < cockpitVoters; v++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(cockpitOptions)))
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
	return c.RunVerify()
}
