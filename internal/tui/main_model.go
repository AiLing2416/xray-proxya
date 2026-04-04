package tui

import (
	"strings"
	"time"
	"fmt"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"net/http"
	"xray-proxya/internal/config"
	"xray-proxya/internal/xray"
	"xray-proxya/pkg/utils"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/atotto/clipboard"
	"github.com/google/uuid"
	"golang.org/x/net/proxy"
)

type sessionTab int

const (
	tabStatus sessionTab = iota
	tabPresets
	tabRelays
)

type statsMsg struct {
	direct int64
	relay  int64
	active bool
	pid    int
}

type relayTestMsg struct {
	alias   string
	latency string
	udp     string
	dns     string
	ip      string
	country string
}

type Model struct {
	active       *config.UserConfig
	staging      *config.UserConfig
	currentTab   sessionTab
	cursor       int
	width        int
	height       int
	directStat   int64
	relayStat    int64
	coreActive   bool
	corePID      int
	relayResults map[string]relayTestMsg
	portBuffer   string
	cachedIP     string
	localIP      string
	useLocalIP   bool
	
	showFullScreenShare bool
	sharePageIndex      int
	showAddRelay bool
	textInput    textinput.Model
}

func tickStats(apiPort int) tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		active, pid := xray.GetXrayStatus()
		direct, relay, _ := xray.GetXrayStats(apiPort)
		return statsMsg{direct: direct, relay: relay, active: active, pid: pid}
	})
}

func (m Model) performApply() tea.Cmd {
	return func() tea.Msg {
		cfg := m.staging
		for i, mode := range cfg.ActiveModes {
			if mode.RegenFlag {
				cfg.ActiveModes[i].Path = xray.GetRandomPath()
				switch mode.Mode {
				case config.ModeVLESSReality, config.ModeVLESSVision:
					pk, pub, _ := xray.GenerateX25519()
					cfg.ActiveModes[i].Settings.PrivateKey, cfg.ActiveModes[i].Settings.PublicKey = pk, pub
					cfg.ActiveModes[i].Settings.ShortID = xray.GetRandomShortID()
					cfg.ActiveModes[i].SNI = config.GetRandomRealityDomain()
				case config.ModeVLESSXHTTP:
					enc, dec, _ := xray.GenerateMLKEM()
					cfg.ActiveModes[i].Settings.Password, cfg.ActiveModes[i].Settings.PrivateKey = enc, dec
				case config.ModeShadowsocksTCP:
					cfg.ActiveModes[i].Settings.Password = utils.GenerateRandomString(16)
				}
				cfg.ActiveModes[i].RegenFlag = false
			}
		}
		cfg.SaveEx(false)
		config.ClearStaging()
		
		xray.StopXray()
		time.Sleep(500 * time.Millisecond)

		home, _ := os.UserHomeDir()
		xrayDir := filepath.Join(home, ".config", "xray-proxya")
		jsonData, _ := xray.GenerateXrayJSON(cfg, nil)
		jsonPath := filepath.Join(xrayDir, "xray_config.json")
		os.WriteFile(jsonPath, jsonData, 0600)
		
		cmdX, _ := xray.StartXray(jsonPath)
		if cmdX != nil {
			os.WriteFile(filepath.Join(xrayDir, "xray.pid"), []byte(fmt.Sprintf("%d", cmdX.Process.Pid)), 0600)
		}
		return "applied"
	}
}

func runRelayTest(cfg *config.UserConfig, co config.CustomOutbound) tea.Cmd {
	return func() tea.Msg {
		res := relayTestMsg{alias: co.Alias, latency: "FAIL", udp: "FAIL", dns: "FAIL", ip: "Unknown", country: "XX"}
		testSocksPort, _ := xray.GetFreePort()
		apiPort, _ := xray.GetFreePort()
		overrides := map[string]int{"test-socks": testSocksPort, "api": apiPort}
		jsonData, err := xray.GenerateXrayJSON(cfg, overrides)
		if err != nil { return res }
		_, cleanup, err := xray.StartXrayTemp(jsonData)
		if err != nil { return res }
		defer cleanup()

		socksAddr := fmt.Sprintf("127.0.0.1:%d", testSocksPort)
		dialer, err := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: "test-" + co.Alias, Password: "test"}, proxy.Direct)
		if err != nil { return res }
		httpClient := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 5 * time.Second}

		// 1. TCP & GeoIP (Exit IP, Country)
		start := time.Now()
		req, _ := http.NewRequest("GET", "http://ip-api.com/json", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		resp, err := httpClient.Do(req)
		if err == nil {
			res.latency = fmt.Sprintf("%dms", time.Since(start).Milliseconds())
			defer resp.Body.Close()
			var geo struct {
				Query       string `json:"query"`
				CountryCode string `json:"countryCode"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&geo); err == nil {
				res.ip = geo.Query
				res.country = geo.CountryCode
			}
		}

		// 2. DNS Test (Try resolve a domain via proxy)
		dnsStart := time.Now()
		conn, err := dialer.Dial("tcp", "8.8.8.8:53")
		if err == nil {
			res.dns = fmt.Sprintf("OK(%dms)", time.Since(dnsStart).Milliseconds())
			conn.Close()
		}

		// 3. UDP Test
		duration, err := xray.TestUDP(socksAddr, "test-"+co.Alias, "test")
		if err == nil { res.udp = fmt.Sprintf("OK(%dms)", duration.Milliseconds()) }
		
		return res
	}
}

func InitialModel() Model {
	active, _ := config.LoadConfig()
	staging, _ := config.LoadConfigEx(true)
	if staging == nil { staging = active }
	ti := textinput.New()
	ti.Placeholder = "Paste link..."
	ti.Focus()
	ti.Width = 60
	return Model{
		active:       active,
		staging:      staging,
		currentTab:   tabPresets,
		width:        80,
		height:       24,
		relayResults: make(map[string]relayTestMsg),
		cachedIP:     utils.GetSmartIP(false),
		localIP:      utils.GetLocalIP(),
		textInput:    ti,
	}
}

func (m Model) Init() tea.Cmd {
	if m.active != nil { return tickStats(m.active.APIInbound) }
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.active == nil { m.active, _ = config.LoadConfig() }
	switch msg := msg.(type) {
	case string:
		if msg == "applied" { m.active, _ = config.LoadConfig(); m.staging, _ = config.LoadConfig() }
	case statsMsg:
		m.directStat, m.relayStat, m.coreActive, m.corePID = msg.direct, msg.relay, msg.active, msg.pid
		return m, tickStats(m.active.APIInbound)
	case relayTestMsg: m.relayResults[msg.alias] = msg
	case tea.WindowSizeMsg: m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		s := msg.String()
		if m.showAddRelay {
			switch s {
			case "esc": m.showAddRelay = false; return m, nil
			case "enter":
				link := m.textInput.Value()
				if link != "" {
					out, err := xray.ParseProxyLink(link)
					if err == nil {
						alias := "relay-" + utils.GenerateRandomString(3)
						newCO := config.CustomOutbound{Alias: alias, Enabled: true, UserUUID: uuid.New().String(), Config: out}
						m.staging.CustomOutbounds = append(m.staging.CustomOutbounds, newCO)
						m.staging.SaveEx(true)
						m.showAddRelay = false; m.textInput.Reset()
						m.relayResults[alias] = relayTestMsg{alias: alias, latency: "Wait..", udp: "--", ip: "--"}
						return m, runRelayTest(m.staging, newCO)
					}
				}
				m.showAddRelay = false; m.textInput.Reset(); return m, nil
			}
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			return m, cmd
		}
		if m.showFullScreenShare {
			switch s {
			case "q", "esc", "s", "S": m.showFullScreenShare = false
			case "l", "L": m.useLocalIP = !m.useLocalIP
			case "left", "h": if m.sharePageIndex > 0 { m.sharePageIndex-- }
			case "right", "space": m.sharePageIndex++ 
			case "c", "C":
				pages := m.getSharePages()
				if m.sharePageIndex < len(pages) {
					clipboard.WriteAll(pages[m.sharePageIndex])
				}
			}
			return m, nil
		}
		switch s {
		case "ctrl+c", "q": return m, tea.Quit
		case "tab": m.currentTab, m.cursor, m.portBuffer = (m.currentTab + 1) % 3, 0, ""
		case "up", "k": if m.cursor > 0 { m.cursor-- }; m.portBuffer = ""
		case "down", "j":
			max := 0
			if m.staging != nil {
				if m.currentTab == tabPresets { max = len(m.staging.ActiveModes) - 1 }
				if m.currentTab == tabRelays { max = len(m.staging.CustomOutbounds) - 1 }
			}
			if m.cursor < max { m.cursor++ }; m.portBuffer = ""
		case "u", "U":
			config.ClearStaging(); m.active, _ = config.LoadConfig(); m.staging, _ = config.LoadConfig()
			m.relayResults = make(map[string]relayTestMsg)
		case "a", "A": return m, m.performApply()
		case "l", "L": m.useLocalIP = !m.useLocalIP
		case "c", "C":
			var linkPub, linkLoc string
			if m.currentTab == tabPresets && m.staging != nil && m.cursor < len(m.staging.ActiveModes) {
				m1 := m.staging.ActiveModes[m.cursor]
				tempCfg := *m.staging
				tempCfg.ActiveModes = []config.ModeInfo{m1}
				linkPub = xray.GenerateLinks(&tempCfg, m.cachedIP)[0]
				linkLoc = xray.GenerateLinks(&tempCfg, m.localIP)[0]
			} else if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				relay := m.staging.CustomOutbounds[m.cursor]
				linkPub = xray.GenerateRelayLinks(m.staging, m.cachedIP, relay)[0]
				linkLoc = xray.GenerateRelayLinks(m.staging, m.localIP, relay)[0]
			}
			if linkPub != "" {
				clipboard.WriteAll(linkPub) // Try clipboard first
				script := fmt.Sprintf(`
					link_pub='%s'; link_loc='%s'; current='PUBLIC'
					[ "%t" == "true" ] && current='LOCAL'
					while true; do
						clear; echo "=== RAW COPY MODE ==="; echo "Current IP Mode: $current"
						echo "------------------------------------------------------------"
						if [ "$current" == "PUBLIC" ]; then echo "$link_pub"; else echo "$link_loc"; fi
						echo "------------------------------------------------------------"
						echo "[L] Switch IP    [C] Copy to Clipboard    [Q/ESC] Return"
						read -n 1 -s key
						case "$key" in
							l|L) [ "$current" == "PUBLIC" ] && current='LOCAL' || current='PUBLIC' ;;
							c|C) if [ "$current" == "PUBLIC" ]; then echo -n "$link_pub" | xclip -sel clip 2>/dev/null || echo -n "$link_pub" | pbcopy 2>/dev/null; else echo -n "$link_loc" | xclip -sel clip 2>/dev/null || echo -n "$link_loc" | pbcopy 2>/dev/null; fi ;;
							q|Q|$'\e') exit 0 ;;
						esac
					done`, linkPub, linkLoc, m.useLocalIP)
				cmd := exec.Command("bash", "-c", script)
				return m, tea.ExecProcess(cmd, func(err error) tea.Msg { return nil })
			}
		case "+", "=":
			if m.currentTab == tabRelays && s == "+" { m.showAddRelay = true; m.textInput.Focus(); return m, nil }
			if m.currentTab == tabPresets && m.staging != nil { m.staging.ActiveModes[m.cursor].Enabled = true; m.staging.SaveEx(true) }
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) { 
				m.staging.CustomOutbounds[m.cursor].Enabled = true; m.staging.SaveEx(true) 
			}
		case "-":
			if m.currentTab == tabPresets && m.staging != nil { m.staging.ActiveModes[m.cursor].Enabled = false; m.staging.SaveEx(true) }
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) { 
				m.staging.CustomOutbounds[m.cursor].Enabled = false; m.staging.SaveEx(true) 
			}
		case "d", "D":
			if m.currentTab == tabRelays && m.staging != nil && len(m.staging.CustomOutbounds) > 0 {
				idx := m.cursor
				m.staging.CustomOutbounds = append(m.staging.CustomOutbounds[:idx], m.staging.CustomOutbounds[idx+1:]...)
				m.staging.SaveEx(true)
				if m.cursor >= len(m.staging.CustomOutbounds) { m.cursor = len(m.staging.CustomOutbounds) - 1 }
				if m.cursor < 0 { m.cursor = 0 }
			}
		case "t", "T":
			if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
				co := m.staging.CustomOutbounds[m.cursor]
				m.relayResults[co.Alias] = relayTestMsg{alias: co.Alias, latency: "Wait..", udp: "--", ip: "--"}
				return m, runRelayTest(m.staging, co)
			}
		case "r", "R":
			if m.currentTab == tabPresets && m.staging != nil && m.cursor < len(m.staging.ActiveModes) {
				m.staging.ActiveModes[m.cursor].RegenFlag = !m.staging.ActiveModes[m.cursor].RegenFlag
				m.staging.SaveEx(true)
			}
		case "backspace":
			if m.currentTab == tabPresets && len(m.portBuffer) > 0 {
				m.portBuffer = m.portBuffer[:len(m.portBuffer)-1]
				var port int; fmt.Sscanf(m.portBuffer, "%d", &port)
				m.staging.ActiveModes[m.cursor].Port = port; m.staging.SaveEx(true)
			}
		case "delete":
			if m.currentTab == tabPresets { m.portBuffer, m.staging.ActiveModes[m.cursor].Port = "", 0; m.staging.SaveEx(true) }
		case "s", "S": m.showFullScreenShare, m.sharePageIndex = true, 0
		default:
			if m.currentTab == tabPresets && s >= "0" && s <= "9" {
				if len(m.portBuffer) >= 5 { m.portBuffer = "" }
				m.portBuffer += s
				var port int; fmt.Sscanf(m.portBuffer, "%d", &port)
				m.staging.ActiveModes[m.cursor].Port = port; m.staging.SaveEx(true)
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.staging == nil { return "Error: No config found." }
	if m.showAddRelay {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			lipgloss.NewStyle().Padding(1, 2).BorderStyle(lipgloss.NormalBorder()).
				Render("ADD CUSTOM RELAY\n\n"+m.textInput.View()+"\n\n[Enter] Confirm  [Esc] Cancel"))
	}
	if m.showFullScreenShare { return m.renderFullScreenShare() }

	// 1. Calculate Heights
	footerHeight := 2 // TopBorder(1) + Text(1)
	
	detailContent := ""
	ip := m.cachedIP
	if m.useLocalIP { ip = m.localIP }
	if m.currentTab == tabPresets && m.staging != nil && m.cursor < len(m.staging.ActiveModes) {
		idx := m.cursor
		m1 := m.staging.ActiveModes[idx]
		isMod := m1.RegenFlag
		if !isMod && m.active != nil && idx < len(m.active.ActiveModes) {
			a := m.active.ActiveModes[idx]
			if m1.Port != a.Port || m1.Path != a.Path || m1.SNI != a.SNI || m1.Enabled != a.Enabled { isMod = true }
		}
		if isMod {
			detailContent = "⚠️ [A] Apply changes to see link."
		} else {
			tempCfg := *m.staging
			tempCfg.ActiveModes = []config.ModeInfo{m1}
			links := xray.GenerateLinks(&tempCfg, ip)
			if len(links) > 0 { detailContent = links[0] } // RAW
		}
	} else if m.currentTab == tabRelays && m.staging != nil && m.cursor < len(m.staging.CustomOutbounds) {
		relay := m.staging.CustomOutbounds[m.cursor]
		links := xray.GenerateRelayLinks(m.staging, ip, relay)
		if len(links) > 0 { detailContent = links[0] } // RAW
	}

	rawLines := 0
	if detailContent != "" { rawLines = strings.Count(detailContent, "\n") + 1 }
	
	detailMinHeight := m.height / 4
	if detailMinHeight < 4 { detailMinHeight = 4 }
	
	detailHeight := rawLines + 1 // +1 for separator line
	if detailHeight < detailMinHeight { detailHeight = detailMinHeight }

	mainHeight := m.height - detailHeight - footerHeight
	if mainHeight < 5 { 
		mainHeight = 5
		detailHeight = m.height - mainHeight - footerHeight
	}

	// 2. Render Components
	sidebar := renderSidebar(m.currentTab, mainHeight)
	cWidth := m.width - 12
	var content string
	switch m.currentTab {
	case tabPresets: content = RenderPresets(m.active, m.staging, m.cursor, cWidth)
	case tabStatus: content = RenderStatus(m.active, m.directStat, m.relayStat, m.coreActive, m.corePID)
	case tabRelays: content = RenderRelays(m.active, m.staging, m.cursor, cWidth, m.relayResults)
	}

	// Important: mainArea must NOT have internal newlines at the end
	mainArea := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, lipgloss.NewStyle().Height(mainHeight).MaxHeight(mainHeight).Render(content))
	
	var detailSb strings.Builder
	detailSb.WriteString(strings.Repeat("─", m.width)) // Row 1
	if detailContent != "" { detailSb.WriteString("\n" + detailContent) } // Row 2+
	// Pad with newlines to reach exact detailHeight
	currentDetailLines := 1
	if detailContent != "" { currentDetailLines = 1 + strings.Count(detailContent, "\n") + 1 }
	for i := currentDetailLines; i < detailHeight; i++ { detailSb.WriteString("\n") }
	
	footer := renderFooter(m.currentTab, m.width)

	// Combine components without ANY extra \n between them. 
	// Each component must have exactly its calculated height.
	return mainArea + "\n" + detailSb.String() + "\n" + footer
}

func (m Model) getSharePages() []string {
	var pages []string
	ip := m.cachedIP
	if m.useLocalIP { ip = m.localIP }

	// Page 1: Presets
	var regularSb strings.Builder
	regularSb.WriteString("\n [1/3] REGULAR PRESETS \n" + strings.Repeat("═", m.width) + "\n\n")
	for _, m1 := range m.staging.ActiveModes {
		if !m1.Enabled || m1.Mode == config.ModeVLESSXHTTP { continue }
		tempCfg := *m.staging
		tempCfg.ActiveModes = []config.ModeInfo{m1}
		links := xray.GenerateLinks(&tempCfg, ip)
		if len(links) > 0 {
			regularSb.WriteString(fmt.Sprintf("%s:\n%s\n\n", m1.Mode, links[0]))
		}
	}
	pages = append(pages, regularSb.String())

	// Page 2: Quantum
	var kemSb strings.Builder
	kemSb.WriteString("\n [2/3] QUANTUM KEM768 \n" + strings.Repeat("═", m.width) + "\n\n")
	for _, m1 := range m.staging.ActiveModes {
		if m1.Enabled && m1.Mode == config.ModeVLESSXHTTP {
			tempCfg := *m.staging
			tempCfg.ActiveModes = []config.ModeInfo{m1}
			links := xray.GenerateLinks(&tempCfg, ip)
			if len(links) > 0 {
				kemSb.WriteString("VLESS-XHTTP-KEM768:\n" + links[0] + "\n\n")
			}
		}
	}
	pages = append(pages, kemSb.String())

	// Page 3: Relays
	var relaySb strings.Builder
	relaySb.WriteString("\n [3/3] CUSTOM RELAYS \n" + strings.Repeat("═", m.width) + "\n\n")
	for _, relay := range m.staging.CustomOutbounds {
		if !relay.Enabled { continue }
		links := xray.GenerateRelayLinks(m.staging, ip, relay)
		if len(links) > 0 {
			relaySb.WriteString(fmt.Sprintf("RELAY [%s]:\n%s\n\n", relay.Alias, links[0]))
		}
	}
	pages = append(pages, relaySb.String())
	return pages
}

func (m Model) renderFullScreenShare() string {
	pages := m.getSharePages()
	if m.sharePageIndex >= len(pages) { m.sharePageIndex = 0 }
	footer := "\n" + strings.Repeat("─", m.width) + "\n[L] Toggle IP    [C] Copy Page    [Left/Right] Switch Page    [ESC/Q] Back"
	return pages[m.sharePageIndex] + footer
}

func renderFooter(tab sessionTab, width int) string {
	var keys []string
	keys = append(keys, "[Tab]Switch", "[Q]Quit", "[A]Apply")
	if tab == tabPresets {
		keys = append(keys, "[+/-]On/Off", "[0-9]Port", "[L]IP-Mode", "[R]Regen", "[U]Undo", "[C]Copy", "[S]Share")
	} else if tab == tabRelays {
		keys = append(keys, "[+]Add", "[+/-]On/Off", "[T]Test", "[D]Del", "[U]Undo")
	}
	s := strings.Join(keys, "  ")
	return lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderTop(true).Width(width).MaxHeight(2).Render(s)
}

func renderSidebar(current sessionTab, height int) string {
	var b strings.Builder
	items := []string{"STATUS", "PRESETS", "RELAYS"}
	for i, item := range items {
		line := " " + item + " "
		if sessionTab(i) == current {
			b.WriteString(lipgloss.NewStyle().Reverse(true).Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return lipgloss.NewStyle().Width(11).Height(height).MaxHeight(height).BorderStyle(lipgloss.NormalBorder()).BorderRight(true).Render(b.String())
}
