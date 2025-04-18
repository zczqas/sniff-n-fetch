package sniffer

import (
	"fmt"
	"log"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var packetSaver *PacketSaver

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
	ipDomains     map[string]string
	ipCountries   map[string]CountryInfo
	savedPackets  int
	saveFile      string
	quitting      bool
}

type updateMsg struct{}

func StartUI(interfaceName, filter, saveFile string, maxPackets int) {
	// Initialize GeoIP
	if err := InitGeoIP(); err != nil {
		log.Printf("warning: GeoIP initialization failed: %v", err)
	}
	defer CloseGeoIP()

	stats = &Stats{
		recent: make([]packetEntry, 0, 10),
	}

	m := model{
		stats:       stats,
		prevBytes:   0,
		bytesRate:   0,
		lastUpdate:  time.Now(),
		ipDomains:   make(map[string]string),
		ipCountries: make(map[string]CountryInfo),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())

	go startSniffing(interfaceName, filter, saveFile, maxPackets)

	if err := p.Start(); err != nil {
		fmt.Println("error starting UI:", err)
	}
}

func startSniffing(interfaceName, filter, saveFile string, maxPackets int) {
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

	if saveFile != "" {
		packetSaver, err = NewPacketSaver(saveFile, 65536, maxPackets)
		if err != nil {
			log.Fatalf("failed to create packet saver: %v", err)
		}
		defer packetSaver.Close()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		processPacketForUI(packet)

		if packetSaver != nil {
			if err := packetSaver.SavePacket(packet); err != nil {
				log.Printf("error saving packet: %v", err)
			}
		}
	}
}

func processPacketForUI(packet gopacket.Packet) {
	timestamp, protocol, src, dst, length := extractPacketInfo(packet, true)

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
	m.ipDomains = make(map[string]string)
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

		stats.Lock()
		for _, packet := range stats.recent {
			if packet.Src != "" && packet.Src != "unknown" {
				if _, exists := m.ipDomains[packet.Src]; !exists {
					domain := LookupDomain(packet.Src)
					if domain != "unknown" && domain != "local" {
						m.ipDomains[packet.Src] = domain
					} else {
						m.ipDomains[packet.Src] = domain
					}
				}

				if _, exists := m.ipCountries[packet.Src]; !exists {
					country := LookupCountry(packet.Src)
					m.ipCountries[packet.Src] = country
				}
			}

			if packet.Dst != "" && packet.Dst != "unknown" {
				if _, exists := m.ipCountries[packet.Dst]; !exists {
					country := LookupCountry(packet.Dst)
					m.ipCountries[packet.Dst] = country
				}
			}
		}
		stats.Unlock()

		if packetSaver != nil {
			m.savedPackets, m.saveFile = packetSaver.GetStats()
		}

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

	alertsView := ""
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
		alertsView = alertStyle.Render(alerts)
	}

	saveView := ""
	if m.saveFile != "" {
		saveStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("5")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("5")).
			Padding(0, 1)

		saveInfo := fmt.Sprintf("💾 Saving Packets: %d packets saved to %s",
			m.savedPackets, m.saveFile)
		saveView = saveStyle.Render(saveInfo)
	}

	domainInfoView := renderDomainInfo(m.ipDomains)
	countryInfoView := renderCountries(m.ipCountries)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		renderStats(total, m.bytesRate),
		renderChart(statsCopy),
		saveView,
		alertsView,
		countryInfoView,
		domainInfoView,
		renderLogs(recentPackets),
	)
}

func renderDomainInfo(ipDomains map[string]string) string {
	if len(ipDomains) == 0 {
		return ""
	}

	domainStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(0, 1)

	content := "🔍 Domain Resolutions:\n"
	count := 0
	for ip, domain := range ipDomains {
		if domain != "unknown" && domain != "local" {
			content += fmt.Sprintf("- %s: %s\n", ip, domain)
			count++
		}
		if count >= 5 {
			break
		}
	}

	return domainStyle.Render(content)
}
