package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

var interfaceName string
var filter string
var useUI bool
var saveFile string
var maxPackets int

var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Start sniffing packets on a network interface",
	Run: func(cmd *cobra.Command, args []string) {
		if useUI {
			sniffer.StartUI(interfaceName, filter, saveFile, maxPackets)
		} else {
			sniffer.Start(interfaceName, filter, saveFile, maxPackets)
		}
	},
}

func init() {
	sniffCmd.Flags().StringVarP(
		&interfaceName,
		"interface",
		"i",
		"eth0",
		"Interface to sniff on",
	)
	sniffCmd.Flags().StringVarP(
		&filter,
		"filter",
		"f",
		"",
		"BPF filter (e.g. 'tcp and port 80')",
	)
	sniffCmd.Flags().BoolVar(
		&useUI,
		"ui",
		false,
		"Display live terminal UI",
	)
	sniffCmd.Flags().StringVar(
		&saveFile,
		"save",
		"",
		"Save captured packets to a pcap file",
	)
	sniffCmd.Flags().IntVar(
		&maxPackets,
		"max-packets",
		0,
		"Maximum number of packets to capture (0 for unlimited)",
	)
	rootCmd.AddCommand(sniffCmd)
}
