package sniffer

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func ListInterfaces() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	fmt.Println("Available Interfaces: ")
	for i, device := range devices {
		fmt.Printf("[%d] %s (%s)\n", i, device.Name, device.Description)
	}

	return nil
}
