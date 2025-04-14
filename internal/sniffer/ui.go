package sniffer

import (
	"fmt"
	"log"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type packetEntry struct {
	Timestamp string
	Protocol  string
	Src       string
	Dst       string
	Length    int
}

type model struct {
	width         int
	height        int
	stats         *Stats
	prevBytes     int
	bytesRate     float64
	lastUpdate    time.Time
	anomalyAlerts []string
	quitting      bool
}

type updateMsg struct{}

func StartUI(interfaceName, filter string) {
	stats = &Stats{
		recent: make([]packetEntry, 0, 10),
	}

	m := model{
		stats:      stats,
		prevBytes:  0,
		bytesRate:  0,
		lastUpdate: time.Now(),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())

	go startSniffing(interfaceName, filter)

	if err := p.Start(); err != nil {
		fmt.Println("error starting UI:", err)
	}
}

func startSniffing(interfaceName, filter string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error opening device: %v", err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("failed to apply filter: %v", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		processPacketForUI(packet)
	}
}

func processPacketForUI(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	timestamp := packet.Metadata().Timestamp.Format("15:04:05")
	length := packet.Metadata().Length

	var protocol, src, dst string
	var dstPort int

	if networkLayer == nil {
		protocol = "Other"
		src = "unknown"
		dst = "unknown"
	} else {
		src = networkLayer.NetworkFlow().Src().String()
		dst = networkLayer.NetworkFlow().Dst().String()

		if transportLayer == nil {
			protocol = "Other"
		} else {
			protocol = transportLayer.LayerType().String()

			if tcpLayer, ok := transportLayer.(*layers.TCP); ok {
				dstPort = int(tcpLayer.DstPort)
			} else if udpLayer, ok := transportLayer.(*layers.UDP); ok {
				dstPort = int(udpLayer.DstPort)
			}

			detector.Track(src, dstPort)
		}
	}

	stats.Lock()
	defer stats.Unlock()

	stats.Total++
	stats.Bytes += length

	switch protocol {
	case "TCP":
		stats.TCP++
	case "UDP":
		stats.UDP++
	case "ICMPv4", "ICMPv6":
		stats.ICMP++
	default:
		stats.Other++
	}

	entry := packetEntry{
		Timestamp: timestamp,
		Protocol:  protocol,
		Src:       src,
		Dst:       dst,
		Length:    length,
	}

	if len(stats.recent) >= 10 {
		stats.recent = stats.recent[1:]
	}
	stats.recent = append(stats.recent, entry)
}

func (m model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg {
		return updateMsg{}
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

	case updateMsg:
		now := time.Now()
		duration := now.Sub(m.lastUpdate).Seconds()

		stats.Lock()
		currentBytes := stats.Bytes
		stats.Unlock()

		if duration > 0 {
			m.bytesRate = float64(currentBytes-m.prevBytes) / duration
		}

		m.anomalyAlerts = GetActiveAlerts()
		m.prevBytes = currentBytes
		m.lastUpdate = now

		return m, tea.Tick(time.Second, func(_ time.Time) tea.Msg {
			return updateMsg{}
		})
	}

	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	stats.Lock()
	total := stats.Total
	recentPackets := make([]packetEntry, len(stats.recent))
	copy(recentPackets, stats.recent)
	statsCopy := &Stats{
		Total: stats.Total,
		TCP:   stats.TCP,
		UDP:   stats.UDP,
		ICMP:  stats.ICMP,
		Other: stats.Other,
		Bytes: stats.Bytes,
	}
	stats.Unlock()

	alertViews := ""
	if len(m.anomalyAlerts) > 0 {
		alertStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("9")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("9")).
			Padding(0, 1)

		alerts := "🚨 Security Alerts:\n"
		for _, alert := range m.anomalyAlerts {
			alerts += "- " + alert + "\n"
		}
		alertViews = alertStyle.Render(alerts)
	}

	return lipgloss.JoinVertical(
		lipgloss.Left,
		renderStats(total, m.bytesRate),
		renderChart(statsCopy),
		alertViews,
		renderLogs(recentPackets),
	)
}
