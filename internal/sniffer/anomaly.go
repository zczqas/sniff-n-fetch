package sniffer

import (
	"fmt"
	"sync"
	"time"
)

type ipActivity struct {
	PacketCount int
	Ports       map[int]bool
	LastSeen    time.Time
}

type AnomalyDetector struct {
	mu       sync.Mutex
	activity map[string]*ipActivity
}

type AnomalyAlert struct {
	Message   string
	Timestamp time.Time
}

var detector = NewAnomalyDetector()
var activeAlerts = []AnomalyAlert{}
var alertsMutex sync.Mutex

func NewAnomalyDetector() *AnomalyDetector {
	d := &AnomalyDetector{
		activity: make(map[string]*ipActivity),
	}
	go d.cleanupLoop()
	return d
}

func (d *AnomalyDetector) Track(srcIP string, dstPort int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	act, exists := d.activity[srcIP]
	if !exists {
		act = &ipActivity{
			Ports: make(map[int]bool),
		}
		d.activity[srcIP] = act
	}

	act.PacketCount++
	act.Ports[dstPort] = true
	act.LastSeen = time.Now()

	if act.PacketCount > 100 && act.PacketCount%100 == 0 {
		message := fmt.Sprintf("Flood detected from %s (packets: %d)", srcIP, act.PacketCount)
		fmt.Printf("🚨 %s\n", message)
		AddAlert(message)
	}

	if len(act.Ports) > 50 && len(act.Ports)%10 == 0 {
		message := fmt.Sprintf("Port scan detected from %s (ports: %d)", srcIP, len(act.Ports))
		fmt.Printf("🕵️ %s\n", message)
		AddAlert(message)
	}
}

func (d *AnomalyDetector) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		d.mu.Lock()

		now := time.Now()
		for ip, act := range d.activity {
			if now.Sub(act.LastSeen) > 30*time.Second {
				delete(d.activity, ip)
			}
		}
		d.mu.Unlock()
	}
}

func GetActiveAlerts() []string {
	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	result := []string{}
	now := time.Now()
	newAlerts := []AnomalyAlert{}

	for _, alert := range activeAlerts {
		if now.Sub(alert.Timestamp) < 30*time.Second {
			result = append(result, alert.Message)
			newAlerts = append(newAlerts, alert)
		}
	}

	activeAlerts = newAlerts

	return result
}

func AddAlert(message string) {
	alertsMutex.Lock()
	defer alertsMutex.Unlock()

	activeAlerts = append(activeAlerts, AnomalyAlert{
		Message:   message,
		Timestamp: time.Now(),
	})
}
