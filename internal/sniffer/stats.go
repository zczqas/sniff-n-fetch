package sniffer

import (
	"fmt"
	"sync"
)

type Stats struct {
	Total int
	TCP   int
	UDP   int
	ICMP  int
	Other int
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

func (s *Stats) Print() {
	s.Lock()
	defer s.Unlock()

	fmt.Printf("\n--- Packet Stats (since start) ---\n")
	fmt.Printf("Total: %d | TCP: %d | UDP: %d | ICMP: %d | Other: %d\n",
		s.Total, s.TCP, s.UDP, s.ICMP, s.Other)
}
