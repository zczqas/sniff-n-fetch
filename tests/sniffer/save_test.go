package sniffer_test

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

func TestPackageSaving(t *testing.T) {
	testFile := "test_packets.pcap"

	os.Remove(testFile)

	saver, err := sniffer.NewPacketSaver(testFile, 65536, 2)
	if err != nil {
		t.Fatalf("Failed to create packet saver: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{8, 8, 8, 8},
	}

	tcpLayer := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	err = gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)
	if err != nil {
		t.Fatalf("Failed to serialize packets: %v", err)
	}

	packet := gopacket.NewPacket(
		buffer.Bytes(),
		layers.LayerTypeIPv4,
		gopacket.Default,
	)

	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}

	err = saver.SavePacket(packet)
	if err != nil {
		t.Fatalf("Failed to save packet: %v", err)
	}

	err = saver.SavePacket(packet)
	if err != nil {
		t.Fatalf("Failed to save second packet: %v", err)
	}

	count, filename := saver.GetStats()
	if count != 2 {
		t.Fatalf("Expected 2 packets, got %d", count)
	}
	if filename != testFile {
		t.Fatalf("Expected filename %s, got %s", testFile, filename)
	}

	err = saver.Close()
	if err != nil {
		t.Fatalf("Failed to close packet saver: %v", err)
	}

	f, err := os.Open(testFile)
	if err != nil {
		t.Fatalf("Failed to open saved pcap file: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		t.Fatalf("Failed to create pcap reader: %v", err)
	}

	packetCount := 0
	for {
		_, _, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		packetCount++
	}

	f.Close()

	if packetCount != 2 {
		t.Fatalf("Expected 2 packets in saved file, got %d", packetCount)
	}

	// Small delay to ensure file handles are fully released
	time.Sleep(100 * time.Millisecond)

	err = os.Remove(testFile)
	if err != nil {
		t.Fatalf("Failed to remove test file: %v", err)
	}
}
