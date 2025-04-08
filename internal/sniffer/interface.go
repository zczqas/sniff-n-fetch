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
	for _, device := range devices {
		fmt.Printf("- %s (%s)\n", device.Name, device.Description)
	}

	return nil
}
