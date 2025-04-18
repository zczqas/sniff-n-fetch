package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func Start(interfaceName, filter, saveFile string, maxPackets int) {
	// Initialize GeoIP
	if err := InitGeoIP(); err != nil {
		log.Printf("warning: GeoIP initialization failed: %v", err)
	}
	defer CloseGeoIP()

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

	var saver *PacketSaver
	if saveFile != "" {
		saver, err = NewPacketSaver(saveFile, 65536, maxPackets)
		if err != nil {
			log.Fatalf("failed to create packet saver: %v", err)
		}
		defer saver.Close()

		fmt.Printf("Saving packets to %s (max packets: %d)\n",
			saveFile,
			maxPackets,
		)
	}

	// Start stats display in a goroutine
	go func() {
		prevBytes := 0
		interval := 5 * time.Second

		for {
			time.Sleep(interval)
			prevBytes = stats.PrintRateAndPieChart(prevBytes, interval)

			if saver != nil {
				count, _ := saver.GetStats()
				fmt.Printf("Saved packets: %d\n", count)
			}
		}
	}()

	for packet := range packetSource.Packets() {
		processPacket(packet)

		if saver != nil {
			if err := saver.SavePacket(packet); err != nil {
				log.Printf("error saving packet: %v", err)
			}
		}
	}
}

func extractPacketInfo(packet gopacket.Packet, shortTimestamp bool) (string, string, string, string, int) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	var timestamp string
	if shortTimestamp {
		timestamp = packet.Metadata().Timestamp.Format("15:04:05")
	} else {
		timestamp = packet.Metadata().Timestamp.Format(time.RFC3339)
	}

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

	return timestamp, protocol, src, dst, length
}

func processPacket(packet gopacket.Packet) {
	timestamp, protocol, src, dst, length := extractPacketInfo(packet, false)

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
