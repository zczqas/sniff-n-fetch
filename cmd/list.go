package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

var listCmd = &cobra.Command{
	Use:   "list-interfaces",
	Short: "List all available network interfaces",
	Run: func(cmd *cobra.Command, args []string) {
		if err := sniffer.ListInterfaces(); err != nil {
			fmt.Println("error listing interfaces:", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
