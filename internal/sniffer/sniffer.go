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
		log.Fatalf("error opening devices: %v", err)
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

	go func() {
		for {
			time.Sleep(5 * time.Second)
			stats.Print()
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

	if networkLayer == nil || transportLayer == nil {
		stats.Update("Other")
		fmt.Println("[unknown] pakcet with missing layer")
		return
	}

	src, dst := networkLayer.NetworkFlow().Endpoints()
	protocol := transportLayer.LayerType().String()

	stats.Update(protocol)

	length := packet.Metadata().Length
	fmt.Printf("[%s] %s | %s -> %s | LEN: %d\n", timestamp, protocol, src, dst, length)

	// if app := packet.ApplicationLayer(); app != nil {
	// 	fmt.Println("Payload:", string(app.Payload()))
	// }
}
