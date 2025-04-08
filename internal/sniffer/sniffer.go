package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Start(interfaceName string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening devices: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("starting packet capture...")

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	timestamp := packet.Metadata().Timestamp.Format(time.RFC3339)

	if networkLayer != nil && transportLayer != nil {
		src, dst := networkLayer.NetworkFlow().Endpoints()
		proto := transportLayer.LayerType().String()
		fmt.Printf("[%s] %s | %s -> %s\n", timestamp, proto, src, dst)
	} else {
		fmt.Println("unknown packet format")
	}
}
