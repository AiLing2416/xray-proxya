package relayinfo

import (
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
	out := RenderTerminalStyled([]*InfoResult{res}, false)

	if !strings.Contains(out, "[hk-01]") {
		t.Fatalf("expected alias header: %s", out)
	}
	if !strings.Contains(out, "Exit IP   : IPv4: 103.21.244.15 | IPv6: 2400:cb00::1") {
		t.Fatalf("missing exit IP: %s", out)
	}
	if !strings.Contains(out, "Geo / ASN : Central, Hong Kong [HK] | AS13335 (Cloudflare, Inc.) [DataCenter/Clear]") {
		t.Fatalf("missing geo/asn: %s", out)
	}
	if !strings.Contains(out, "Streaming : Netflix: HK | Disney+: HK | TikTok: HK") {
		t.Fatalf("missing streaming: %s", out)
	}
	if !strings.Contains(out, "AI / Web  : Google: HK | OpenAI: Yes | Claude: Yes") {
		t.Fatalf("missing ai/web: %s", out)
	}
	if strings.Contains(out, "Timezone") {
		t.Fatalf("simple mode output should not contain timezone line: %s", out)
	}
}

func TestRenderTerminalSingleFull(t *testing.T) {
	res := sampleResultSimple()
	res.Mode = ModeFull
	res.Profile.Timezone = "Asia/Hong_Kong"
	res.Profile.LocalTime = "2026-09-01 14:15:30"

	out := RenderTerminalStyled([]*InfoResult{res}, false)

	if !strings.Contains(out, "Timezone  : Asia/Hong_Kong (Local Time: 2026-09-01 14:15:30)") {
		t.Fatalf("missing timezone in full mode: %s", out)
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

	out := RenderTerminalStyled([]*InfoResult{r1, r2}, false)

	if !strings.Contains(out, "ALIAS") || !strings.Contains(out, "LOCATION") || !strings.Contains(out, "NETFLIX") {
		t.Fatalf("missing table headers: %s", out)
	}
	if !strings.Contains(out, "hk-01") || !strings.Contains(out, "Central, Hong Kong [HK]") {
		t.Fatalf("missing hk-01 row: %s", out)
	}
	if !strings.Contains(out, "jp-02") || !strings.Contains(out, "Tokyo, Japan [JP]") {
		t.Fatalf("missing jp-02 row: %s", out)
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
	if m["alias"] != "hk-01" {
		t.Fatalf("alias mismatch: %v", m["alias"])
	}
}

func TestFormatDoneSummary(t *testing.T) {
	r := sampleResultSimple()
	s := FormatDoneSummary(r)
	if !strings.Contains(s, "Done: HK | Netflix: HK | AI: Yes") {
		t.Errorf("unexpected summary: %s", s)
	}

	rFail := &InfoResult{Alias: "us-01", Error: "timeout"}
	sFail := FormatDoneSummary(rFail)
	if sFail != "Failed: timeout" {
		t.Errorf("unexpected fail summary: %s", sFail)
	}
}
