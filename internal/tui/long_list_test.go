package tui

import (
	"fmt"
	"strings"
	"testing"
	"xray-proxya/internal/config"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func makeLongRelayConfig(count int) *config.UserConfig {
	outbounds := make([]config.CustomOutbound, 0, count)
	for i := 0; i < count; i++ {
		alias := fmt.Sprintf("🇭🇰-香港专线-%03d-超长节点名称测试-倍率1.5x", i+1)
		outbounds = append(outbounds, config.CustomOutbound{
			Alias:               alias,
			Enabled:             true,
			UserUUID:            fmt.Sprintf("uuid-%03d", i+1),
			AllowPrivateTargets: i%2 == 0,
			Config: map[string]interface{}{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": "203.0.113.10",
							"port":    443 + (i % 10),
						},
					},
				},
			},
		})
	}

	guests := make([]config.GuestConfig, 0, 50)
	for i := 0; i < 50; i++ {
		guests = append(guests, config.GuestConfig{
			Alias:        fmt.Sprintf("用户-%03d-测试账号", i+1),
			UUID:         fmt.Sprintf("guest-uuid-%03d", i+1),
			Enabled:      i%3 != 0,
			LimitBytes:   100 * 1000 * 1000 * 1000,
			UsedBytes:    int64(i) * 1024 * 1024 * 1024,
			ResetDay:     1,
			Endpoint:     "default",
			OutboundLink: outbounds[i%len(outbounds)].Alias,
		})
	}

	return &config.UserConfig{
		Role:            config.RoleServer,
		UUID:            "server-root-uuid-1234",
		APIInbound:      10085,
		CustomOutbounds: outbounds,
		Guests:          guests,
		Presets: []config.ModeInfo{
			{
				Mode:    config.ModeVLESSReality,
				Port:    443,
				Enabled: true,
				Settings: config.Settings{
					PublicKey: "test-public-key-1234567890abcdef",
					ShortID:   "0123456789abcdef",
				},
			},
		},
	}
}

func assertViewFitsTerminal(t *testing.T, view string, width, height int, label string) {
	t.Helper()
	lines := strings.Split(view, "\n")
	if len(lines) > height {
		t.Fatalf("%s: rendered %d lines, exceeds terminal height %d\n%s", label, len(lines), height, view)
	}
	for i, line := range lines {
		w := lipgloss.Width(line)
		if w > width {
			t.Fatalf("%s: line %d has visual width %d > terminal width %d: %q", label, i, w, width, line)
		}
	}
}

func TestLongRelayListBoundsAndPageUpDown(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	cfg := makeLongRelayConfig(120)

	m := Model{
		active:        cfg,
		staging:       cfg,
		currentTab:    tabRelays,
		width:         80,
		height:        24,
		cachedIP:      "198.51.100.88",
		relayResults:  make(map[string]relayTestMsg),
		relayTestMap:  make(map[string]string),
		relayInfoMap:  make(map[string]string),
		relaySpeedMap: make(map[string]string),
		relayViewMode: make(map[string]string),
		flash:         NewFlashManager(),
	}

	// 1. Initial page at 80x24
	view := m.View()
	assertViewFitsTerminal(t, view, 80, 24, "relays-80x24-page1")
	if !strings.Contains(view, "Page 1/") {
		t.Fatalf("expected page indicator on long relay list, got:\n%s", view)
	}
	if !strings.Contains(view, "001") {
		t.Fatalf("expected first relay to be visible on page 1, got:\n%s", view)
	}

	// 2. PageDown advances to next page and keeps cursor visible
	pageSize := m.tablePageSize()
	if pageSize < 1 {
		t.Fatalf("expected positive pageSize, got %d", pageSize)
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = updated.(Model)
	if m.cursor != pageSize {
		t.Fatalf("expected cursor after PgDn to be %d, got %d", pageSize, m.cursor)
	}
	view = m.View()
	assertViewFitsTerminal(t, view, 80, 24, "relays-80x24-page2")
	wantToken := fmt.Sprintf("%03d", m.cursor+1)
	if !strings.Contains(view, wantToken) {
		t.Fatalf("expected selected relay %s to be visible after PgDn, got:\n%s", wantToken, view)
	}
	if !strings.Contains(view, "Page 2/") {
		t.Fatalf("expected Page 2 indicator after PgDn, got:\n%s", view)
	}

	// 3. End jumps to last item, Home jumps back to first item
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	m = updated.(Model)
	if m.cursor != 119 {
		t.Fatalf("expected cursor 119 after End, got %d", m.cursor)
	}
	view = m.View()
	assertViewFitsTerminal(t, view, 80, 24, "relays-80x24-end")
	if !strings.Contains(view, "120") {
		t.Fatalf("expected last relay 120 visible after End, got:\n%s", view)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	m = updated.(Model)
	view = m.View()
	assertViewFitsTerminal(t, view, 80, 24, "relays-80x24-pgup")
	wantToken = fmt.Sprintf("%03d", m.cursor+1)
	if !strings.Contains(view, wantToken) {
		t.Fatalf("expected relay %s visible after PgUp, got:\n%s", wantToken, view)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyHome})
	m = updated.(Model)
	if m.cursor != 0 || m.listScroll != 0 {
		t.Fatalf("expected cursor=0 listScroll=0 after Home, got cursor=%d listScroll=%d", m.cursor, m.listScroll)
	}
}

func TestAllTabsFitVariousTerminalSizes(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	cfg := makeLongRelayConfig(80)

	stats := map[string]int64{
		"inbound>>>vless-reality>>>traffic>>>uplink": 1024 * 1024,
		"outbound>>>direct>>>traffic>>>downlink":     2048 * 1024,
	}
	for _, co := range cfg.CustomOutbounds {
		stats["user>>>relay-"+co.Alias+">>>traffic>>>uplink"] = 10000
	}
	for _, g := range cfg.Guests {
		stats["user>>>guest-"+g.Alias+">>>traffic>>>uplink"] = 5000
	}

	services := make([]ManagedServiceItem, 0, 20)
	for i := 0; i < 20; i++ {
		services = append(services, ManagedServiceItem{
			DisplayName: fmt.Sprintf("Service-%02d", i+1),
			UnitName:    fmt.Sprintf("xray-proxya-%02d.service", i+1),
			Active:      i%2 == 0,
			PID:         1000 + i,
			Status:      "Running",
			Enabled:     true,
			Description: "Long service description for narrow terminal overflow check",
		})
	}

	sizes := []struct{ w, h int }{
		{80, 24},
		{120, 32},
		{60, 16},
		{80, 10},
	}

	tabs := []sessionTab{tabStatus, tabService, tabPresets, tabRelays, tabGuests, tabGateway}
	for _, sz := range sizes {
		for _, tab := range tabs {
			m := Model{
				active:          cfg,
				staging:         cfg,
				currentTab:      tab,
				cursor:          5,
				width:           sz.w,
				height:          sz.h,
				cachedIP:        "198.51.100.88",
				lastStats:       stats,
				managedServices: services,
				relayResults:    make(map[string]relayTestMsg),
				relayTestMap:    make(map[string]string),
				relayInfoMap:    make(map[string]string),
				relaySpeedMap:   make(map[string]string),
				relayViewMode:   make(map[string]string),
				flash:           NewFlashManager(),
			}
			if tab == tabGateway {
				cfgCopy := *cfg
				cfgCopy.Role = config.RoleGateway
				m.active = &cfgCopy
				m.staging = &cfgCopy
			}
			view := m.View()
			assertViewFitsTerminal(t, view, sz.w, sz.h, fmt.Sprintf("tab=%d-%dx%d", tab, sz.w, sz.h))
		}
	}
}

func TestLongInfoSelectAndStatusScrollPageUpDown(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	cfg := makeLongRelayConfig(100)

	// 1. Guest relay selection menu with 100 long CJK/emoji relay aliases
	m := Model{
		active:        cfg,
		staging:       cfg,
		currentTab:    tabGuests,
		cursor:        0,
		width:         80,
		height:        24,
		cachedIP:      "198.51.100.88",
		relayResults:  make(map[string]relayTestMsg),
		relayTestMap:  make(map[string]string),
		relayInfoMap:  make(map[string]string),
		relaySpeedMap: make(map[string]string),
		relayViewMode: make(map[string]string),
		flash:         NewFlashManager(),
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	if !m.infoSelectMode || len(m.infoSelectChoices) != 102 {
		t.Fatalf("expected infoSelectMode with 102 choices, got mode=%v len=%d", m.infoSelectMode, len(m.infoSelectChoices))
	}
	assertViewFitsTerminal(t, m.View(), 80, 24, "guest-relay-select-80x24")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = updated.(Model)
	if m.infoSelectIdx == 0 {
		t.Fatalf("expected infoSelectIdx to advance on PgDn")
	}
	assertViewFitsTerminal(t, m.View(), 80, 24, "guest-relay-select-pgdn")

	// 2. Status tab PgDn / PgUp scrolling with many relay stats
	stats := map[string]int64{}
	for _, co := range cfg.CustomOutbounds {
		stats["user>>>relay-"+co.Alias+">>>traffic>>>uplink"] = 123456
	}
	m.infoSelectMode = false
	m.currentTab = tabStatus
	m.lastStats = stats
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = updated.(Model)
	if m.statusScroll == 0 {
		t.Fatalf("expected statusScroll > 0 after PgDn on long status stats")
	}
	assertViewFitsTerminal(t, m.View(), 80, 24, "status-scroll-pgdn")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyHome})
	m = updated.(Model)
	if m.statusScroll != 0 {
		t.Fatalf("expected statusScroll == 0 after Home, got %d", m.statusScroll)
	}
}

func TestEmojiNormalizationPreservesFlagsAndAvoidsOverlap(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)

	samples := []string{
		"🇭🇰➡️🇺🇸-香港中转美西-🚀",
		"🏳️‍🌈-彩虹专线-👨‍💻-开发者",
		"⚡高速-🛡️安全-⚠️流媒体-🔥",
		"🇯🇵🇸🇬🇰🇷🇹🇼-亚太解锁-🎬🎮",
		"👍🏼-推荐节点-💎VIP-🌟",
		"边界截断测试-🇭🇰🇯🇵🇺🇸🇸🇬🇬🇧🇩🇪",
	}

	outbounds := make([]config.CustomOutbound, 0, len(samples))
	for _, s := range samples {
		outbounds = append(outbounds, config.CustomOutbound{
			Alias:   s,
			Enabled: true,
			Config: map[string]interface{}{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{"address": "203.0.113.10", "port": 443},
					},
				},
			},
		})
	}
	cfg := &config.UserConfig{
		Role:            config.RoleServer,
		CustomOutbounds: outbounds,
	}

	// Ensure flags & plain emojis stay intact while VS16/ZWJ/skin-tone modifiers are normalized.
	for _, s := range samples {
		norm := normalizeDisplayText(s)
		if strings.ContainsAny(norm, "\u200d\ufe0f\u20e3") {
			t.Fatalf("expected ZWJ/VS16/keycap stripped from %q, got %q", s, norm)
		}
		for _, r := range norm {
			if isEmojiModifier(r) {
				t.Fatalf("expected skin-tone modifier stripped from %q, got %q", s, norm)
			}
		}
		// Verify every non-RI rune has matching GraphemeWidth and WcWidth.
		for _, r := range norm {
			if isRegionalIndicator(r) {
				continue
			}
			rs := string(r)
			if ansi.StringWidth(rs) != ansi.StringWidthWc(rs) {
				t.Fatalf("width mismatch for rune %U (%q) in %q: grapheme=%d wc=%d",
					r, rs, norm, ansi.StringWidth(rs), ansi.StringWidthWc(rs))
			}
		}
	}

	if !strings.Contains(normalizeDisplayText(samples[0]), "🇭🇰") || !strings.Contains(normalizeDisplayText(samples[0]), "🇺🇸") {
		t.Fatalf("expected flags preserved in %q", normalizeDisplayText(samples[0]))
	}
	if !strings.Contains(normalizeDisplayText(samples[3]), "🇯🇵🇸🇬🇰🇷🇹🇼") {
		t.Fatalf("expected flag sequence preserved in %q", normalizeDisplayText(samples[3]))
	}

	rendered := RenderRelaysWindow(cfg, cfg, 0, 100, nil, 15, 0)
	lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
	if len(lines) < 2+len(samples) {
		t.Fatalf("expected header + %d rows, got %d lines:\n%s", len(samples), len(lines), rendered)
	}
	expectedW := lipgloss.Width(lines[2])
	for i := 2; i < len(lines); i++ {
		if w := lipgloss.Width(lines[i]); w != expectedW {
			t.Fatalf("row %d visual width %d != row 0 width %d: %q", i-2, w, expectedW, lines[i])
		}
	}
}

