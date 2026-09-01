package relayinfo

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderTerminal formats relay info results for terminal display.
func RenderTerminal(results []*InfoResult) string {
	if len(results) == 0 {
		return ""
	}

	if len(results) == 1 {
		return renderSingleResult(results[0]) + "\n"
	}

	var blocks []string
	for _, r := range results {
		block := fmt.Sprintf("[%s]\n%s", r.Alias, renderSingleResult(r))
		blocks = append(blocks, block)
	}
	return strings.Join(blocks, "\n\n") + "\n"
}

func renderSingleResult(r *InfoResult) string {
	if r == nil {
		return ""
	}
	if r.Error != "" {
		return fmt.Sprintf("FAIL: %s", r.Error)
	}

	var lines []string

	// 1. Exit IP
	v4 := r.Profile.IPv4
	v6 := r.Profile.IPv6

	switch r.Family {
	case IPFamilyIPv4:
		if v4 == "" {
			v4 = "FAIL"
		}
		if v6 == "" {
			v6 = "N/A"
		}
	case IPFamilyIPv6:
		if v4 == "" {
			v4 = "N/A"
		}
		if v6 == "" {
			v6 = "FAIL"
		}
	default:
		if v4 == "" {
			v4 = "FAIL"
		}
		if v6 == "" {
			v6 = "N/A"
		}
	}
	lines = append(lines, fmt.Sprintf("Exit IP   : IPv4: %s | IPv6: %s", v4, v6))

	// 2. Geo / ASN
	loc := formatLocation(r.Profile)
	asnOrg := formatASNOrg(r.Profile)
	typeRisk := formatTypeRisk(r.Profile)
	lines = append(lines, fmt.Sprintf("Geo / ASN : %s | %s [%s]", loc, asnOrg, typeRisk))

	// 3. Timezone (Only in ModeFull)
	if r.Mode == ModeFull {
		tz := r.Profile.Timezone
		if tz == "" {
			tz = "UTC"
		}
		lt := r.Profile.LocalTime
		if lt == "" {
			lt = "N/A"
		}
		lines = append(lines, fmt.Sprintf("Timezone  : %s (Local Time: %s)", tz, lt))
	}

	// 4. Streaming
	nf := formatUnlock(r.Streaming.Netflix, "Yes")
	ds := formatUnlock(r.Streaming.Disney, "Yes")
	tk := formatUnlock(r.Streaming.TikTok, "Yes")
	lines = append(lines, fmt.Sprintf("Streaming : Netflix: %s | Disney+: %s | TikTok: %s", nf, ds, tk))

	// 5. AI / Web
	gg := formatUnlock(r.General.Google, "Yes")
	oa := formatUnlock(r.General.OpenAI, "Yes")
	cl := formatUnlock(r.General.Claude, "Yes")
	lines = append(lines, fmt.Sprintf("AI / Web  : Google: %s | OpenAI: %s | Claude: %s", gg, oa, cl))

	return strings.Join(lines, "\n")
}

func formatLocation(p LandingProfile) string {
	var parts []string
	if p.City != "" && p.City != "N/A" {
		parts = append(parts, p.City)
	}
	if p.Region != "" && p.Region != "N/A" && p.Region != p.City {
		parts = append(parts, p.Region)
	}
	if p.Country != "" && p.Country != "N/A" {
		parts = append(parts, p.Country)
	}

	loc := strings.Join(parts, ", ")
	if loc == "" {
		loc = "N/A"
	}
	if p.CountryCode != "" {
		loc = fmt.Sprintf("%s [%s]", loc, p.CountryCode)
	}
	return loc
}

func formatASNOrg(p LandingProfile) string {
	asn := strings.TrimSpace(p.ASN)
	if asn == "" {
		asn = "N/A"
	}
	org := strings.TrimSpace(p.Org)
	if org == "" || org == "N/A" || org == asn {
		return asn
	}
	if strings.HasPrefix(org, asn) {
		return org
	}
	return fmt.Sprintf("%s (%s)", asn, org)
}

func formatTypeRisk(p LandingProfile) string {
	t := p.ASNType
	if t == "" {
		t = "N/A"
	}
	priv := p.Privacy
	if priv == "" {
		priv = "N/A"
	}
	return fmt.Sprintf("%s/%s", t, priv)
}

func formatUnlock(item UnlockItem, fallback string) string {
	switch item.Status {
	case StatusFull:
		if item.Region != "" {
			return fmt.Sprintf("🟢 %s", item.Region)
		}
		return "🟢 Full"
	case StatusOriginals:
		if item.Region != "" {
			return fmt.Sprintf("🟡 Originals (%s)", item.Region)
		}
		return "🟡 Originals"
	case StatusYes:
		if item.Region != "" {
			return fmt.Sprintf("🟢 %s", item.Region)
		}
		return fmt.Sprintf("🟢 %s", fallback)
	case StatusNo:
		return "🚫 No"
	case StatusNoIPv6:
		return "⚪ No IPv6"
	case StatusNoIPv4:
		return "⚪ No IPv4"
	case StatusError:
		return "🔴 Fail"
	default:
		return "⚪ N/A"
	}
}

// RenderJSON serializes the info results into formatted JSON.
func RenderJSON(results interface{}) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
