package sniffer

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type PacketSaver struct {
	handle     *pcap.Handle
	dumper     *pcapgo.Writer
	file       *os.File
	filename   string
	count      int
	maxPackets int
	mu         sync.Mutex
}

func NewPacketSaver(filename string, snapLen int, maxPackets int) (*PacketSaver, error) {
	dir := filepath.Dir(filename)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory for pcap file: %w", err)
		}
	}

	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(uint32(snapLen), layers.LinkTypeEthernet)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to write pcap header: %w", err)
	}

	return &PacketSaver{
		file:       f,
		dumper:     w,
		filename:   filename,
		maxPackets: maxPackets,
	}, nil
}

func (ps *PacketSaver) SavePacket(packet gopacket.Packet) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.file == nil || ps.dumper == nil {
		return errors.New("packet saver is not initialized or already closed")
	}

	if ps.maxPackets > 0 && ps.count >= ps.maxPackets {
		return nil
	}

	err := ps.dumper.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	if err != nil {
		return fmt.Errorf("failed to write packet to pcap file: %w", err)
	}

	ps.count++

	shouldClose := ps.maxPackets > 0 && ps.count >= ps.maxPackets
	if shouldClose {
		if ps.file != nil {
			_ = ps.file.Close()
			ps.file = nil
			ps.dumper = nil
		}
		log.Printf("Reached max packet count (%d). Saved tp %s", ps.maxPackets, ps.filename)
	}

	return nil
}

func (ps *PacketSaver) Close() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.file == nil {
		return nil

	}

	err := ps.file.Close()
	ps.file = nil
	ps.dumper = nil

	return err
}

func (ps *PacketSaver) GetStats() (int, string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	return ps.count, ps.filename
}
