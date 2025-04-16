# Sniff-n-Fetch

A network packet sniffer built in Go with real-time analysis capabilities.

## Features

- **Live Packet Capture**: Monitor network traffic in real-time
- **Protocol Analysis**: Identify and categorize TCP, UDP, ICMP, and other protocols
- **Terminal UI**: Interactive display with traffic statistics and visualizations
- **Geographical IP Tracking**: View country information for detected IPs
- **Domain Resolution**: Automatic DNS lookups for connected hosts
- **Anomaly Detection**: Identify potential security threats like port scans and flood attacks
- **BPF Filtering**: Apply Berkeley Packet Filter expressions to focus on specific traffic

## Installation

### Prerequisites

- Go 1.21 or higher
- libpcap development files

#### Ubuntu/Debian
```sh
sudo apt-get install libpcap-dev
```

#### macOS
```sh
brew install libpcap
```

#### Windows
For Windows, you need [Npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/) installed.

### Building from Source

1. Clone the repository
```sh
git clone https://github.com/zczqas/sniff-n-fetch.git
cd sniff-n-fetch
```

2. Build the application
```sh
make build
```

## Usage

### Listing Available Network Interfaces

```sh
./bin/sniffer list-interfaces
```

### Capturing Packets

Basic packet capture on a specific interface:

```sh
./bin/sniffer sniff -i <interface_name>
```

Example:
```sh
# For Linux
./bin/sniffer sniff -i eth0

# For Windows
./bin/sniffer sniff -i "\Device\NPF_{8BCB91DE-61A6-4E68-95A0-B72AC32B5C6D}"
```

### Applying Filters

Capture only specific traffic using BPF filter syntax:

```sh
./bin/sniffer sniff -i <interface_name> -f "<filter_expression>"
```

Examples:
```sh
# Capture only TCP traffic
./bin/sniffer sniff -i eth0 -f "tcp"

# Capture HTTP traffic
./bin/sniffer sniff -i eth0 -f "tcp port 80"

# Capture traffic to/from a specific IP
./bin/sniffer sniff -i eth0 -f "host 192.168.1.1"
```

### Interactive Terminal UI

Run with the interactive terminal UI for real-time visualizations:

```sh
./bin/sniffer sniff -i <interface_name> --ui
```

The UI provides:
- Live packet statistics
- Protocol distribution charts
- Recent packet logs
- Geographic origin of connections
- Domain name resolutions
- Security alerts for anomalous traffic

## Implementation Details

- Built with pure Go for cross-platform compatibility
- Uses [gopacket](https://github.com/google/gopacket) for packet capture and analysis
- Terminal UI powered by [bubbletea](https://github.com/charmbracelet/bubbletea) and [lipgloss](https://github.com/charmbracelet/lipgloss)
- Geographic IP data provided by MaxMind's GeoLite2 database
- Command-line interface built with [Cobra](https://github.com/spf13/cobra)

## Security Features

### Anomaly Detection

The sniffer includes built-in detection for common network threats:

- **Port Scanning**: Alerts when a single IP attempts to connect to many different ports
- **Flood Attacks**: Detects when a host sends an unusually high volume of packets


## Acknowledgments

- MaxMind for GeoLite2 data
- The GoPacket team for the packet capture library
- Charm for the terminal UI components