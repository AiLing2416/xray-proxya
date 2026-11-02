package pathd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type listenerFunc func(address, token string, idle time.Duration) (*Server, error)

var listenFunc listenerFunc = Listen

// RunCLI is the command-line entrypoint for the pathd ICMP companion daemon.
// args should be the argument slice excluding the executable name (e.g. os.Args[1:]).
// It returns an exit code suitable for os.Exit.
func RunCLI(args []string) int {
	return RunCLICustom(args, os.Stdout, os.Stderr, nil)
}

// RunCLICustom executes the pathd CLI with customizable I/O streams and an optional stop channel.
func RunCLICustom(args []string, stdout, stderr io.Writer, stopCh <-chan struct{}) int {
	if len(args) < 1 || args[0] != "serve" {
		fmt.Fprintln(stderr, "usage: xray-proxya-pathd serve --config /root/.config/xray-proxya/pathd.json")
		return 2
	}

	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)

	listen := flags.String("listen", DefaultListenAddress, "loopback listen address")
	token := flags.String("token", "", "PathLink authentication token")
	idle := flags.Duration("idle", 20*time.Second, "idle connection timeout")
	configPath := flags.String("config", "", "private pathd JSON configuration")

	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}

	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, "pathd config:", err)
			return 1
		}
		var file struct {
			Listen      string `json:"listen"`
			Token       string `json:"token"`
			IdleSeconds int    `json:"idle_seconds"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			fmt.Fprintln(stderr, "pathd config:", err)
			return 1
		}
		*listen, *token = file.Listen, file.Token
		if file.IdleSeconds > 0 {
			*idle = time.Duration(file.IdleSeconds) * time.Second
		}
	}

	server, err := listenFunc(*listen, *token, *idle)
	if err != nil {
		fmt.Fprintln(stderr, "pathd:", err)
		return 1
	}
	fmt.Fprintf(stdout, "pathd listening on %s\n", server.Addr())

	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.Serve(); err != nil {
			serverErrCh <- err
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)

	if stopCh != nil {
		select {
		case <-signals:
		case <-stopCh:
		case err := <-serverErrCh:
			if err != nil {
				fmt.Fprintln(stderr, "pathd:", err)
			}
		}
	} else {
		select {
		case <-signals:
		case err := <-serverErrCh:
			if err != nil {
				fmt.Fprintln(stderr, "pathd:", err)
			}
		}
	}

	_ = server.Close()
	return 0
}
