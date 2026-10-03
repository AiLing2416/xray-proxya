package relayinfo

import (
	"encoding/json"
	"fmt"
	"strings"
	"xray-proxya/internal/ui"
)

// RenderTerminal formats relay info results for terminal display.
func RenderTerminal(results []*InfoResult) string {
	return RenderTerminalStyled(results, ui.IsColorEnabled())
}

// RenderTerminalStyled formats relay info results with explicit color control.
func RenderTerminalStyled(results []*InfoResult, colorEnabled bool) string {
	if len(results) == 0 {
		return ""
	}
	if len(results) == 1 {
		return RenderSingleCardStyled(results[0], colorEnabled)
	}
	return RenderTableStyled(results, colorEnabled)
}

// RenderSingleCard formats a single node's info as an aligned card.
func RenderSingleCard(r *InfoResult) string {
	return RenderSingleCardStyled(r, ui.IsColorEnabled())
}

// RenderSingleCardStyled formats a single node's info with explicit color control.
func RenderSingleCardStyled(r *InfoResult, colorEnabled bool) string {
	if r == nil {
		return ""
	}
	if r.Error != "" {
		return fmt.Sprintf("[%s]\n  %s\n", r.Alias, ui.Red("FAIL: "+r.Error, colorEnabled))
	}

	var sb strings.Builder
	aliasHeader := r.Alias
	if aliasHeader != "" {
		sb.WriteString(fmt.Sprintf("[%s]\n", aliasHeader))
	}

	// 1. Exit IP
	v4 := r.Profile.IPv4
	v6 := r.Profile.IPv6

	switch r.Family {
	case IPFamilyIPv4:
		if v4 == "" {
			v4 = ui.Red("FAIL", colorEnabled)
		}
		if v6 == "" {
			v6 = ui.Gray("N/A", colorEnabled)
		}
	case IPFamilyIPv6:
		if v4 == "" {
			v4 = ui.Gray("N/A", colorEnabled)
		}
		if v6 == "" {
			v6 = ui.Red("FAIL", colorEnabled)
		}
	default:
		if v4 == "" {
			v4 = ui.Red("FAIL", colorEnabled)
		}
		if v6 == "" {
			v6 = ui.Gray("N/A", colorEnabled)
		}
	}
	sb.WriteString(fmt.Sprintf("Exit IP   : IPv4: %s | IPv6: %s\n", v4, v6))

	// 2. Geo / ASN
	loc := formatLocation(r.Profile)
	asnOrg := formatASNOrg(r.Profile)
	typeRisk := formatTypeRisk(r.Profile)
	sb.WriteString(fmt.Sprintf("Geo / ASN : %s | %s [%s]\n", loc, asnOrg, typeRisk))

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
		sb.WriteString(fmt.Sprintf("Timezone  : %s (Local Time: %s)\n", tz, lt))
	}

	// 4. Streaming
	nf := formatUnlockCard(r.Streaming.Netflix, "Yes", colorEnabled)
	ds := formatUnlockCard(r.Streaming.Disney, "Yes", colorEnabled)
	tk := formatUnlockCard(r.Streaming.TikTok, "Yes", colorEnabled)
	sb.WriteString(fmt.Sprintf("Streaming : Netflix: %s | Disney+: %s | TikTok: %s\n", nf, ds, tk))

	// 5. AI / Web
	gg := formatUnlockCard(r.General.Google, "Yes", colorEnabled)
	oa := formatUnlockCard(r.General.OpenAI, "Yes", colorEnabled)
	cl := formatUnlockCard(r.General.Claude, "Yes", colorEnabled)
	sb.WriteString(fmt.Sprintf("AI / Web  : Google: %s | OpenAI: %s | Claude: %s\n", gg, oa, cl))

	return sb.String()
}

// RenderTable formats multiple relay info results into a Style 3 Minimalist Clean table.
func RenderTable(results []*InfoResult) string {
	return RenderTableStyled(results, ui.IsColorEnabled())
}

// RenderTableStyled formats multiple relay info results into a table with explicit color control.
func RenderTableStyled(results []*InfoResult, colorEnabled bool) string {
	if len(results) == 0 {
		return ""
	}

	table := ui.NewTable("ALIAS", "LOCATION", "ASN / ORG", "NETFLIX", "DISNEY+", "CHATGPT", "CLAUDE")
	table.SetAlignment(3, ui.AlignCenter)
	table.SetAlignment(4, ui.AlignCenter)
	table.SetAlignment(5, ui.AlignCenter)
	table.SetAlignment(6, ui.AlignCenter)

	for _, r := range results {
		if r == nil {
			continue
		}

		if r.Error != "" {
			failText := "FAIL: " + r.Error
			if colorEnabled {
				failText = ui.Red("FAIL: ", true) + r.Error
			}
			table.AddSpannedRow(failText, r.Alias)
			continue
		}

		loc := formatLocation(r.Profile)
		asnOrg := formatASNOrg(r.Profile)
		nf := formatUnlockTable(r.Streaming.Netflix, colorEnabled)
		ds := formatUnlockTable(r.Streaming.Disney, colorEnabled)
		oa := formatUnlockTable(r.General.OpenAI, colorEnabled)
		cl := formatUnlockTable(r.General.Claude, colorEnabled)

		table.AddRow(r.Alias, loc, asnOrg, nf, ds, oa, cl)
	}

	return table.Render()
}

// FormatDoneSummary returns a 1-line summary suitable for in-place completion locking.
func FormatDoneSummary(r *InfoResult) string {
	if r == nil {
		return "Done"
	}
	if r.Error != "" {
		return "Failed: " + r.Error
	}

	loc := r.Profile.CountryCode
	if loc == "" {
		loc = r.Profile.Country
	}
	if loc == "" {
		loc = "OK"
	}

	var parts []string
	parts = append(parts, loc)

	if r.Streaming.Netflix.Status == StatusFull || r.Streaming.Netflix.Status == StatusYes {
		if r.Streaming.Netflix.Region != "" {
			parts = append(parts, fmt.Sprintf("Netflix: %s", r.Streaming.Netflix.Region))
		} else {
			parts = append(parts, "Netflix: Yes")
		}
	} else if r.Streaming.Netflix.Status == StatusOriginals {
		parts = append(parts, "Netflix: Originals")
	}

	if r.General.OpenAI.Status == StatusYes {
		parts = append(parts, "AI: Yes")
	}

	return "Done: " + strings.Join(parts, " | ")
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

func formatUnlockCard(item UnlockItem, fallback string, colorEnabled bool) string {
	switch item.Status {
	case StatusFull:
		if item.Region != "" {
			return ui.Green(item.Region, colorEnabled)
		}
		return ui.Green("Full", colorEnabled)
	case StatusOriginals:
		if item.Region != "" {
			return ui.Yellow(fmt.Sprintf("Originals (%s)", item.Region), colorEnabled)
		}
		return ui.Yellow("Originals", colorEnabled)
	case StatusYes:
		if item.Region != "" {
			return ui.Green(item.Region, colorEnabled)
		}
		return ui.Green(fallback, colorEnabled)
	case StatusNo:
		return ui.Red("No", colorEnabled)
	case StatusNoIPv6:
		return ui.Gray("No IPv6", colorEnabled)
	case StatusNoIPv4:
		return ui.Gray("No IPv4", colorEnabled)
	case StatusError:
		return ui.Red("Fail", colorEnabled)
	default:
		return ui.Gray("N/A", colorEnabled)
	}
}

func formatUnlockTable(item UnlockItem, colorEnabled bool) string {
	switch item.Status {
	case StatusFull:
		if item.Region != "" {
			return ui.Green(item.Region, colorEnabled)
		}
		return ui.Green("Yes", colorEnabled)
	case StatusOriginals:
		if item.Region != "" {
			return ui.Yellow(item.Region+"*", colorEnabled)
		}
		return ui.Yellow("Orig", colorEnabled)
	case StatusYes:
		if item.Region != "" {
			return ui.Green(item.Region, colorEnabled)
		}
		return ui.Green("Yes", colorEnabled)
	case StatusNo:
		return ui.Red("No", colorEnabled)
	case StatusNoIPv6, StatusNoIPv4:
		return ui.Gray("-", colorEnabled)
	case StatusError:
		return ui.Red("FAIL", colorEnabled)
	default:
		return ui.Gray("N/A", colorEnabled)
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
