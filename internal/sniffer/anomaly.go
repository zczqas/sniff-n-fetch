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

var detector = NewAnomalyDetector()

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

	if act.PacketCount > 100 {
		fmt.Printf("🚨 Flood detected from %s (packets: %d)\n", srcIP, act.PacketCount)
	}

	if len(act.Ports) > 50 {
		fmt.Printf("🕵️ Port scan detected from %s (ports: %d)\n", srcIP, len(act.Ports))
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
