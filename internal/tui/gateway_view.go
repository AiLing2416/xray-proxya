package tui

import (
	"fmt"
	"strings"
	"xray-proxya/internal/config"

	"github.com/charmbracelet/lipgloss"
)

func RenderGateway(cfg *config.UserConfig, width int) string {
	var b strings.Builder
	b.WriteString("Transparent Gateway Management\n")
	b.WriteString(strings.Repeat("─", 30))
	b.WriteString("\n\n")
	b.WriteString("This feature will be populated in subsequent tasks.\n\n")
	if cfg != nil {
		b.WriteString(fmt.Sprintf("Mode:          %s\n", cfg.Gateway.Mode))
		b.WriteString(fmt.Sprintf("Local Enabled: %t\n", cfg.Gateway.LocalEnabled))
		b.WriteString(fmt.Sprintf("LAN Enabled:   %t\n", cfg.Gateway.LANEnabled))
		b.WriteString(fmt.Sprintf("LAN Interface: %s\n", cfg.Gateway.LANInterface))
		b.WriteString(fmt.Sprintf("Relay Alias:   %s\n", cfg.Gateway.RelayAlias))
	}
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}
