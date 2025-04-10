package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Start(interfaceName, filter string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error opening device: %v", err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("failed to apply filter: %v", err)
		}
		fmt.Println("applied BPF filter:", filter)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("starting packet capture...")
	stats = &Stats{}

	// Start stats display in a goroutine
	go func() {
		prevBytes := 0
		interval := 5 * time.Second

		for {
			time.Sleep(interval)
			prevBytes = stats.PrintRateAndPieChart(prevBytes, interval)
		}
	}()

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	timestamp := packet.Metadata().Timestamp.Format(time.RFC3339)
	length := packet.Metadata().Length

	var protocol, src, dst string

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
		}
	}

	stats.Lock()
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
	stats.Unlock()

	entry := packetEntry{
		Timestamp: timestamp,
		Protocol:  protocol,
		Src:       src,
		Dst:       dst,
		Length:    length,
	}

	stats.AddPacket(entry)

	fmt.Printf("[%s] %s | %s -> %s | LEN: %d\n", timestamp, protocol, src, dst, length)
}
