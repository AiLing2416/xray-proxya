package relayinfo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func sampleResultSimple() *InfoResult {
	return &InfoResult{
		Alias:  "hk-01",
		Mode:   ModeSimple,
		Family: IPFamilyIPv4,
		Profile: LandingProfile{
			IP:          "103.21.244.15",
			IPv4:        "103.21.244.15",
			IPv6:        "2400:cb00::1",
			ASN:         "AS13335",
			ASNType:     "DataCenter",
			Org:         "Cloudflare, Inc.",
			Country:     "Hong Kong",
			CountryCode: "HK",
			City:        "Central",
			Privacy:     "Clear",
		},
		Streaming: StreamingUnlock{
			Netflix: UnlockItem{Status: StatusFull, Region: "HK"},
			Disney:  UnlockItem{Status: StatusYes, Region: "HK"},
			TikTok:  UnlockItem{Status: StatusYes, Region: "HK"},
		},
		General: GeneralUnlock{
			Google: UnlockItem{Status: StatusYes, Region: "HK"},
			OpenAI: UnlockItem{Status: StatusYes},
			Claude: UnlockItem{Status: StatusYes},
		},
	}
}

func TestRenderTerminalSingleSimple(t *testing.T) {
	res := sampleResultSimple()
	out := RenderTerminal([]*InfoResult{res})

	expected := strings.TrimSpace(`
Exit IP   : IPv4: 103.21.244.15 | IPv6: 2400:cb00::1
Geo / ASN : Central, Hong Kong [HK] | AS13335 (Cloudflare, Inc.) [DataCenter/Clear]
Streaming : Netflix: 🟢 HK | Disney+: 🟢 HK | TikTok: 🟢 HK
AI / Web  : Google: 🟢 HK | OpenAI: 🟢 Yes | Claude: 🟢 Yes
`)

	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.TrimSpace(out), expected)
	}

	// Verify NO alias header
	if strings.Contains(out, "[hk-01]") {
		t.Fatalf("single node output should not contain alias header: %s", out)
	}

	// Verify NO timezone line in simple mode
	if strings.Contains(out, "Timezone") {
		t.Fatalf("simple mode output should not contain timezone line: %s", out)
	}
}

func TestRenderTerminalSingleFull(t *testing.T) {
	res := sampleResultSimple()
	res.Mode = ModeFull
	res.Profile.Timezone = "Asia/Hong_Kong"
	res.Profile.LocalTime = "2026-09-01 14:15:30"

	out := RenderTerminal([]*InfoResult{res})

	expected := strings.TrimSpace(`
Exit IP   : IPv4: 103.21.244.15 | IPv6: 2400:cb00::1
Geo / ASN : Central, Hong Kong [HK] | AS13335 (Cloudflare, Inc.) [DataCenter/Clear]
Timezone  : Asia/Hong_Kong (Local Time: 2026-09-01 14:15:30)
Streaming : Netflix: 🟢 HK | Disney+: 🟢 HK | TikTok: 🟢 HK
AI / Web  : Google: 🟢 HK | OpenAI: 🟢 Yes | Claude: 🟢 Yes
`)

	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.TrimSpace(out), expected)
	}
}

func TestRenderTerminalMultipleNodes(t *testing.T) {
	r1 := sampleResultSimple()
	r2 := &InfoResult{
		Alias:  "jp-02",
		Mode:   ModeSimple,
		Family: IPFamilyIPv4,
		Profile: LandingProfile{
			IPv4:        "133.242.18.99",
			ASN:         "AS9370",
			ASNType:     "ISP",
			Org:         "SAKURA Internet Inc.",
			Country:     "Japan",
			CountryCode: "JP",
			City:        "Tokyo",
			Privacy:     "Clear",
		},
		Streaming: StreamingUnlock{
			Netflix: UnlockItem{Status: StatusOriginals, Region: "JP"},
			Disney:  UnlockItem{Status: StatusNo},
			TikTok:  UnlockItem{Status: StatusYes, Region: "JP"},
		},
		General: GeneralUnlock{
			Google: UnlockItem{Status: StatusYes, Region: "JP"},
			OpenAI: UnlockItem{Status: StatusYes},
			Claude: UnlockItem{Status: StatusNo},
		},
	}

	out := RenderTerminal([]*InfoResult{r1, r2})

	expected := strings.TrimSpace(`
[hk-01]
Exit IP   : IPv4: 103.21.244.15 | IPv6: 2400:cb00::1
Geo / ASN : Central, Hong Kong [HK] | AS13335 (Cloudflare, Inc.) [DataCenter/Clear]
Streaming : Netflix: 🟢 HK | Disney+: 🟢 HK | TikTok: 🟢 HK
AI / Web  : Google: 🟢 HK | OpenAI: 🟢 Yes | Claude: 🟢 Yes

[jp-02]
Exit IP   : IPv4: 133.242.18.99 | IPv6: N/A
Geo / ASN : Tokyo, Japan [JP] | AS9370 (SAKURA Internet Inc.) [ISP/Clear]
Streaming : Netflix: 🟡 Originals (JP) | Disney+: 🚫 No | TikTok: 🟢 JP
AI / Web  : Google: 🟢 JP | OpenAI: 🟢 Yes | Claude: 🚫 No
`)

	if strings.TrimSpace(out) != expected {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.TrimSpace(out), expected)
	}
}

func TestJSONOmitTimezoneInSimpleMode(t *testing.T) {
	res := sampleResultSimple()
	jsonStr, err := RenderJSON(res)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	if strings.Contains(jsonStr, "timezone") {
		t.Fatalf("JSON in simple mode should not contain timezone: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "local_time") {
		t.Fatalf("JSON in simple mode should not contain local_time: %s", jsonStr)
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	profile := m["profile"].(map[string]interface{})
	if _, ok := profile["timezone"]; ok {
		t.Fatalf("profile should not have timezone field in simple mode")
	}
	if _, ok := profile["local_time"]; ok {
		t.Fatalf("profile should not have local_time field in simple mode")
	}

	if m["family"] != "ipv4" {
		t.Fatalf("family = %v, want ipv4", m["family"])
	}
}

func TestJSONIncludeTimezoneInFullMode(t *testing.T) {
	res := sampleResultSimple()
	res.Mode = ModeFull
	res.Profile.Timezone = "Asia/Hong_Kong"
	res.Profile.LocalTime = "2026-09-01 14:15:30"

	jsonStr, err := RenderJSON(res)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	if !strings.Contains(jsonStr, `"timezone": "Asia/Hong_Kong"`) {
		t.Fatalf("JSON in full mode should contain timezone: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"local_time": "2026-09-01 14:15:30"`) {
		t.Fatalf("JSON in full mode should contain local_time: %s", jsonStr)
	}
}

func TestRenderError(t *testing.T) {
	res := &InfoResult{
		Alias: "hk-dead",
		Error: "connection refused",
	}
	out := RenderTerminal([]*InfoResult{res})
	if !strings.Contains(out, "FAIL: connection refused") {
		t.Fatalf("unexpected error output: %s", out)
	}
}

func TestResolveTargetAddress(t *testing.T) {
	ctx := context.Background()

	// 1. Natural mode passes host through
	got, err := resolveTargetAddress(ctx, nil, "netflix.com:443", IPFamilyNatural)
	if err != nil || got != "netflix.com:443" {
		t.Fatalf("natural mode: got %q, err %v", got, err)
	}

	// 2. IP literal passes through
	got, err = resolveTargetAddress(ctx, nil, "1.2.3.4:443", IPFamilyIPv4)
	if err != nil || got != "1.2.3.4:443" {
		t.Fatalf("ip literal: got %q, err %v", got, err)
	}

	got, err = resolveTargetAddress(ctx, nil, "[2001:db8::1]:443", IPFamilyIPv6)
	if err != nil || got != "[2001:db8::1]:443" {
		t.Fatalf("ipv6 literal: got %q, err %v", got, err)
	}
}
