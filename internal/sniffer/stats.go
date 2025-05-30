package sniffer

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Stats struct {
	Total  int
	TCP    int
	UDP    int
	ICMP   int
	Other  int
	Bytes  int
	recent []packetEntry
	sync.Mutex
}

var stats = &Stats{}

func (s *Stats) Update(proto string) {
	s.Lock()
	defer s.Unlock()

	s.Total++

	switch proto {
	case "TCP":
		s.TCP++
	case "UDP":
		s.UDP++
	case "ICMPv4", "ICMPv6":
		s.ICMP++
	default:
		s.Other++
	}
}

func (s *Stats) AddPacket(entry packetEntry) {
	s.Lock()
	defer s.Unlock()

	if len(s.recent) >= 10 {
		s.recent = s.recent[1:]
	}
	s.recent = append(s.recent, entry)
}

func (s *Stats) GetRecent() []packetEntry {
	s.Lock()
	defer s.Unlock()

	// return a copy to avoid race conditions
	copied := make([]packetEntry, len(s.recent))
	copy(copied, s.recent)
	return copied
}

func (s *Stats) PrintRateAndPieChart(prevBytes int, interval time.Duration) int {
	s.Lock()
	defer s.Unlock()

	rate := float64(s.Bytes-prevBytes) / interval.Seconds()
	fmt.Printf("\nStats | Total: %d | Rate: %.2f bytes/sec\n", s.Total, rate)

	total := float64(s.Total)
	if total == 0 {
		fmt.Println("no packets yet.")
		return s.Bytes
	}

	tcpPacket := float64(s.TCP) / total * 100
	udpPacket := float64(s.UDP) / total * 100
	icmpPacket := float64(s.ICMP) / total * 100
	otherPacket := float64(s.Other) / total * 100

	printPie("TCP", tcpPacket)
	printPie("UDP", udpPacket)
	printPie("ICMP", icmpPacket)
	printPie("Other", otherPacket)

	return s.Bytes
}

func printPie(label string, percent float64) {
	bars := int(percent / 2)
	barLine := strings.Repeat("█", bars)
	fmt.Printf("%-6s [%-50s] %5.1f%%\n", label+":", barLine, percent)
}
