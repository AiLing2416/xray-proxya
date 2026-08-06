package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"xray-proxya/internal/pathd"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: xray-proxya-pathd serve --config /root/.config/xray-proxya/pathd.json")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := flags.String("listen", "127.0.0.1:39091", "loopback listen address")
	token := flags.String("token", "", "PathLink authentication token")
	idle := flags.Duration("idle", 20*time.Second, "idle connection timeout")
	configPath := flags.String("config", "", "private pathd JSON configuration")
	_ = flags.Parse(os.Args[2:])
	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pathd config:", err)
			os.Exit(1)
		}
		var file struct {
			Listen      string `json:"listen"`
			Token       string `json:"token"`
			IdleSeconds int    `json:"idle_seconds"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			fmt.Fprintln(os.Stderr, "pathd config:", err)
			os.Exit(1)
		}
		*listen, *token = file.Listen, file.Token
		if file.IdleSeconds > 0 {
			*idle = time.Duration(file.IdleSeconds) * time.Second
		}
	}
	server, err := pathd.Listen(*listen, *token, *idle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathd:", err)
		os.Exit(1)
	}
	fmt.Printf("pathd listening on %s\n", server.Addr())
	go func() {
		if err := server.Serve(); err != nil {
			fmt.Fprintln(os.Stderr, "pathd:", err)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	_ = server.Close()
}
