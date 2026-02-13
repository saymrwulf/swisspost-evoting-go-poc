package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

//go:embed web
var webContent embed.FS

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the presentation web app on the local network",
	Run:   runServe,
}

func init() {
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "Port to serve on")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) {
	webFS, err := fs.Sub(webContent, "web")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	http.Handle("/", http.FileServer(http.FS(webFS)))

	fmt.Println()
	fmt.Println("  Swiss Post E-Voting Presentations")
	fmt.Println("  ==================================")
	fmt.Println()
	fmt.Println("  Available at:")
	fmt.Printf("    http://localhost:%d\n", servePort)

	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			fmt.Printf("    http://%s:%d\n", ipnet.IP.String(), servePort)
		}
	}

	fmt.Println()
	fmt.Println("  Open this URL on your iPad Pro to view the presentations.")
	fmt.Println("  Press Ctrl+C to stop the server.")
	fmt.Println()

	listenAddr := fmt.Sprintf("0.0.0.0:%d", servePort)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
