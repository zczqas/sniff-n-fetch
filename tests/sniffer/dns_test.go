package sniffer_test

import (
	"net"
	"testing"

	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

func TestLookupDomain(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "Local IP",
			ip:       "192.168.1.1",
			expected: "local",
		},
		{
			name:     "Loopback IP",
			ip:       "127.0.0.1",
			expected: "local",
		},
		{
			name:     "Private IP Range 10.0.0.0/8",
			ip:       "10.0.0.1",
			expected: "local",
		},
		{
			name:     "Private IP Range 172.16.0.0/12",
			ip:       "172.16.0.1",
			expected: "local",
		},
		{
			name:     "Link Local IP",
			ip:       "169.254.0.1",
			expected: "local",
		},
		{
			name:     "Invalid IP",
			ip:       "invalid.ip",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffer.LookupDomain(tt.ip)
			if result != tt.expected {
				t.Errorf("LookupDomain(%q) = %q, want %q", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Public IP",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "Private IP 192.168.1.1",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Private IP 10.0.0.1",
			ip:       "10.0.0.1",
			expected: true,
		},
		{
			name:     "Private IP 172.16.0.1",
			ip:       "172.16.0.1",
			expected: true,
		},
		{
			name:     "Loopback IP",
			ip:       "127.0.0.1",
			expected: true,
		},
		{
			name:     "Link Local IP",
			ip:       "169.254.0.1",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := sniffer.IsPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
