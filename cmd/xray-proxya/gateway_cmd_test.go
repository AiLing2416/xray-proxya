package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestGatewayCommandRejectsUnexpectedArguments(t *testing.T) {
	if err := gatewayCmd.Args(gatewayCmd, []string{"lan", "disable"}); err == nil {
		t.Fatal("gateway command accepted unexpected arguments")
	}
	if err := gatewayCmd.Args(gatewayCmd, nil); err != nil {
		t.Fatalf("gateway command rejected no arguments: %v", err)
	}
}

var _ cobra.PositionalArgs = gatewayCmd.Args
