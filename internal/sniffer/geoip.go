package sniffer

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDB       *geoip2.Reader
	geoDBMutex  sync.Mutex
	countryInfo = map[string]CountryInfo{}
)

type CountryInfo struct {
	Name string
	ISO  string
	Flag string
}

func InitGeoIP() error {
	dbPath := "GeoLite2-Country.mmdb"

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		err = downloadGeoIPDB(dbPath)
		if err != nil {
			return err
		}
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return err
	}

	geoDBMutex.Lock()
	geoDB = db
	geoDBMutex.Unlock()

	return nil
}

func downloadGeoIPDB(path string) error {
	// In a real app, you'd use MaxMind's API with your license key
	url := "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func LookupCountry(ipStr string) CountryInfo {
	geoDBMutex.Lock()
	defer geoDBMutex.Unlock()

	if geoDB == nil {
		return CountryInfo{Name: "Unknown", ISO: "XX", Flag: "🏴"}
	}

	ip := net.ParseIP(CleanIPString(ipStr))
	if ip == nil {
		return CountryInfo{Name: "Invalid IP", ISO: "XX", Flag: "🏴"}
	}

	if IsPrivateIP(ip) {
		return CountryInfo{Name: "Local Network", ISO: "LO", Flag: "🏠"}
	}

	if info, found := countryInfo[ipStr]; found {
		return info
	}

	record, err := geoDB.Country(ip)
	if err != nil {
		return CountryInfo{Name: "Unknown", ISO: "XX", Flag: "🏴"}
	}

	country := CountryInfo{
		Name: record.Country.Names["en"],
		ISO:  record.Country.IsoCode,
		Flag: GetEmojiFlag(record.Country.IsoCode),
	}

	countryInfo[ipStr] = country
	return country
}

func CleanIPString(ipStr string) string {
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		// If error, the IP likely doesn't have a port
		return ipStr
	}
	return host
}

func GetEmojiFlag(isoCode string) string {
	if isoCode == "" {
		return "🏴"
	}

	var result string
	for _, char := range isoCode {
		if char >= 'A' && char <= 'Z' {
			result += string(char + 127397)
		}
	}

	if result == "" {
		return "🏴"
	}

	return result
}

func CloseGeoIP() {
	geoDBMutex.Lock()
	defer geoDBMutex.Unlock()

	if geoDB != nil {
		geoDB.Close()
		geoDB = nil
	}
}
