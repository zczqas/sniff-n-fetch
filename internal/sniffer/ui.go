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

type packetEntry struct {
	Timestamp string
	Protocol  string
	Src       string
	Dst       string
	Length    int
}

type model struct {
	width       int
	height      int
	ticker      *time.Ticker
	stats       *Stats
	recentPkts  []packetEntry
	prevBytes   int
	lastUpdated time.Time
	quitting    bool
}

func StartUI(interffaceName, filter string) {
	stats = &Stats{}
	m := model{
		stats:       stats,
		ticker:      time.NewTicker(1 * time.Second),
		recentPkts:  make([]packetEntry, 0, 5),
		lastUpdated: time.Now(),
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	go startSniffing(interffaceName, filter)
	if err := p.Start(); err != nil {
		fmt.Println("error starting UI:", err)
	}
}

func startSniffing(interfaceName, filter string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error opening devices: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("starting packet capture with UI...")

	for packet := range packetSource.Packets() {
		now := time.Now()
		network := packet.NetworkLayer()
		transport := packet.TransportLayer()
		length := packet.Metadata().Length

		var proto, src, dst string
		if network != nil && transport != nil {
			src = network.NetworkFlow().Src().String()
			dst = network.NetworkFlow().Dst().String()
			proto = transport.LayerType().String()
		} else {
			proto = "Other"
		}

		stats.Update(proto)

		entry := packetEntry{
			Timestamp: now.Format("15:04:05"),
			Protocol:  proto,
			Src:       src,
			Dst:       dst,
			Length:    length,
		}

		stats.AddRecent(entry)
	}
}

func (m model) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type tickMsg time.Time

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}
	case tickMsg:
		m.lastUpdated = time.Time(msg)
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	m.stats.Lock()
	defer m.stats.Unlock()

	rate := float64(m.stats.Bytes-m.prevBytes) / time.Since(m.lastUpdated).Seconds()
	m.prevBytes = m.stats.Bytes

	return lipgloss.JoinVertical(
		lipgloss.Left,
		renderStats(m.stats.Total, rate),
		renderChart(m.stats),
		renderLogs(m.stats.GetRecent()),
	)
}
