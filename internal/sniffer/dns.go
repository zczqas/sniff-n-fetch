package sniffer

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	dnsCache      = make(map[string]string)
	dnsCacheMutex sync.Mutex
)

func LookupDomain(ipStr string) string {
	ipParts := strings.Split(ipStr, ":")
	ipStr = ipParts[0]

	ip := net.ParseIP(ipStr)
	if ip != nil && IsPrivateIP(ip) {
		return "local"
	}

	dnsCacheMutex.Lock()
	if domain, found := dnsCache[ipStr]; found {
		dnsCacheMutex.Unlock()
		country := LookupCountry(ipStr)
		if country.ISO != "XX" && country.ISO != "LO" {
			return fmt.Sprintf("%s (%s %s)", domain, country.Flag, country.Name)
		}
		return domain
	}
	dnsCacheMutex.Unlock()

	domain := "unknown"
	resultChan := make(chan string, 1)

	go func() {
		names, err := net.LookupAddr(ipStr)
		if err == nil && len(names) > 0 {
			domain = strings.TrimSuffix(names[0], ".")
		}
		resultChan <- domain
	}()

	select {
	case domain = <-resultChan:
		dnsCacheMutex.Lock()
		dnsCache[ipStr] = domain
		dnsCacheMutex.Unlock()
		country := LookupCountry(ipStr)
		if country.ISO != "XX" && country.ISO != "LO" {
			return fmt.Sprintf("%s (%s %s)", domain, country.Flag, country.Name)
		}
	case <-time.After(500 * time.Millisecond):
	}

	return domain
}

func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true // 10.0.0.0/8
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true // 172.16.0.0/12
		case ip4[0] == 192 && ip4[1] == 168:
			return true // 192.168.0.0/16
		case ip4[0] == 127:
			return true // 127.0.0.0/8 (localhost)
		case ip4[0] == 169 && ip4[1] == 254:
			return true // 169.254.0.0/16 (link-local)
		}
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}
