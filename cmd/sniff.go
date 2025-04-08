package cmd

import (
	"github.com/spf13/cobra"
	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

var interfaceName string
var filter string

var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Start sniffing packets on a network interface",
	Run: func(cmd *cobra.Command, args []string) {
		sniffer.Start(interfaceName, filter)
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
	rootCmd.AddCommand(sniffCmd)
}
