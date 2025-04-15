package sniffer

import (
	"fmt"
	"sort"

	"github.com/charmbracelet/lipgloss"
)

var (
	barWidth = 30
)

func renderStats(total int, rate float64) string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("10")).
		Render(fmt.Sprintf("📦 Packets: %d | ⚡ Rate: %.2f bytes/s", total, rate))
}

func renderChart(s *Stats) string {
	total := float64(s.Total)
	if total == 0 {
		return "No traffic yet."
	}

	return fmt.Sprintf("Protocol Usage\n%s\n%s\n%s\n%s",
		renderBar("TCP", float64(s.TCP)/total),
		renderBar("UDP", float64(s.UDP)/total),
		renderBar("ICMP", float64(s.ICMP)/total),
		renderBar("Other", float64(s.Other)/total),
	)
}

func renderBar(label string, percent float64) string {
	count := int(percent * float64(barWidth))
	bar := lipgloss.NewStyle().
		Foreground(lipgloss.Color("4")).
		Render("█")
	empty := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		Render("░")

	return fmt.Sprintf("%-6s [%s%s] %5.1f%%", label+":",
		strRepeat(bar, count),
		strRepeat(empty, barWidth-count),
		percent*100,
	)
}

func renderLogs(entries []packetEntry) string {
	logBlock := "🧾 Recent Packets\n"
	for _, e := range entries {
		logBlock += fmt.Sprintf("[%s] %s | %s → %s (%d bytes)\n", e.Timestamp, e.Protocol, e.Src, e.Dst, e.Length)
	}
	return logBlock
}

func renderCountries(countries map[string]CountryInfo) string {
	if len(countries) == 0 {
		return ""
	}

	countryStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("14")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("14")).
		Padding(0, 1)

	countryCount := make(map[string]int)
	countryDetails := make(map[string]CountryInfo)

	for _, info := range countries {
		if info.ISO != "" && info.ISO != "XX" && info.ISO != "LO" {
			countryCount[info.ISO]++
			countryDetails[info.ISO] = info
		}
	}

	type countryStat struct {
		ISO   string
		Info  CountryInfo
		Count int
	}

	var stats []countryStat
	for iso, count := range countryCount {
		stats = append(stats, countryStat{
			ISO:   iso,
			Info:  countryDetails[iso],
			Count: count,
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	content := "🌎 Countries Detected:\n"
	displayCount := 0

	for _, stat := range stats {
		if stat.Info.Name != "" && stat.Info.Name != "Unknown" && stat.Info.Name != "Local Network" {
			content += fmt.Sprintf("- %s %s (%d connections)\n",
				stat.Info.Flag, stat.Info.Name, stat.Count)
			displayCount++
		}

		if displayCount >= 5 {
			break
		}
	}

	if displayCount == 0 {
		return ""
	}

	return countryStyle.Render(content)
}

func strRepeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
