package sniffer_test

import (
	"testing"

	"github.com/zczqas/sniff-n-fetch/internal/sniffer"
)

func TestLookupCountry(t *testing.T) {
	if err := sniffer.InitGeoIP(); err != nil {
		t.Skipf("Skipping test: GeoIP initialization failed: %v", err)
	}
	defer sniffer.CloseGeoIP()

	tests := []struct {
		name         string
		ip           string
		expectedISO  string
		expectedName string
		expectedFlag string
	}{
		{
			name:         "Google DNS",
			ip:           "8.8.8.8",
			expectedISO:  "US",
			expectedName: "United States",
			expectedFlag: "🇺🇸",
		},
		{
			name:         "Local IP",
			ip:           "192.168.1.1",
			expectedISO:  "LO",
			expectedName: "Local Network",
			expectedFlag: "🏠",
		},
		{
			name:         "Invalid IP",
			ip:           "invalid.ip",
			expectedISO:  "XX",
			expectedName: "Invalid IP",
			expectedFlag: "🏴",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country := sniffer.LookupCountry(tt.ip)
			if country.ISO != tt.expectedISO {
				t.Errorf("LookupCountry(%q) ISO = %q, want %q", tt.ip, country.ISO, tt.expectedISO)
			}
			if country.Name != tt.expectedName {
				t.Errorf("LookupCountry(%q) Name = %q, want %q", tt.ip, country.Name, tt.expectedName)
			}
			if country.Flag != tt.expectedFlag {
				t.Errorf("LookupCountry(%q) Flag = %q, want %q", tt.ip, country.Flag, tt.expectedFlag)
			}
		})
	}
}

func TestCleanIPString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IP with port",
			input:    "192.168.1.1:80",
			expected: "192.168.1.1",
		},
		{
			name:     "IP without port",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 with port",
			input:    "[2001:db8::1]:80",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 without port",
			input:    "2001:db8::1",
			expected: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffer.CleanIPString(tt.input)
			if result != tt.expected {
				t.Errorf("cleanIPString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetEmojiFlag(t *testing.T) {
	tests := []struct {
		name     string
		isoCode  string
		expected string
	}{
		{
			name:     "Valid ISO code",
			isoCode:  "US",
			expected: "🇺🇸",
		},
		{
			name:     "Empty ISO code",
			isoCode:  "",
			expected: "🏴",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sniffer.GetEmojiFlag(tt.isoCode)
			if result != tt.expected {
				t.Errorf("getEmojiFlag(%q) = %q, want %q", tt.isoCode, result, tt.expected)
			}
		})
	}
}
