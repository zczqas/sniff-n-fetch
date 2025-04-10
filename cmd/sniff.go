package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

var interfaceName string
var filter string
var useUI bool

var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Start sniffing packets on a network interface",
	Run: func(cmd *cobra.Command, args []string) {
		if useUI {
			sniffer.StartUI(interfaceName, filter)
		} else {
			sniffer.Start(interfaceName, filter)
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
	rootCmd.AddCommand(sniffCmd)
}
