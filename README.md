# Radar - Network Device Scanner

A modern web-based network scanner built with Python and Flask that helps you discover and monitor devices on your network.

<img width="1195" height="898" alt="radar" src="https://github.com/user-attachments/assets/962edfed-2c60-48ab-bfa6-79d48c99ef66" />

## Features

- 🌐 **Network Discovery**: Automatically detects local networks or scan custom subnets
- 🎯 **Device Detection**: Discovers active devices using ping and port scanning
- 🔍 **Port Scanning**: Identifies open ports on discovered devices
- 🏷️ **Device Classification**: Attempts to classify device types based on open ports
- 📊 **Real-time Progress**: Live progress tracking during network scans
- 📱 **Responsive UI**: Modern, mobile-friendly web interface
- 🔄 **Auto-refresh**: Automatically updates device list

## Requirements

- Python 3.7 or higher
- Windows, macOS, or Linux
- Administrator/root privileges may be required for some network operations

## Installation

1. **Clone or download the project**
   ```
   cd d:\MyProject\radar
   ```

2. **Install required packages**
   ```
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```
   python app.py
   ```

4. **Open your web browser**
   Navigate to: http://localhost:5000

## Usage

### Basic Network Scan

1. Open the Radar web interface in your browser
2. Click "Start Scan" to automatically detect and scan your local networks
3. Watch the progress bar as Radar discovers devices
4. View discovered devices with their details

### Custom Network Scan

1. Click "Refresh Networks" to load available network interfaces
2. Select a specific network from the dropdown
3. Click "Start Scan" to scan only that network

### Device Information

For each discovered device, Radar displays:

- **IP Address**: The device's network address
- **Hostname**: Resolved hostname (if available)
- **Device Type**: Estimated device type based on open ports
- **Open Ports**: List of detected open network ports
- **Last Seen**: When the device was last detected
- **Status**: Current online status

## Device Type Detection

Radar attempts to identify device types based on open ports:

- **Linux/Unix Server**: SSH (port 22) detected
- **Windows Computer**: RDP (port 3389) or SMB (ports 139, 445) detected
- **Web Server**: HTTP (port 80) or HTTPS (port 443) detected
- **Network Device/Router**: Telnet (port 23) detected
- **VNC Server**: VNC (port 5900) detected

## Port Scanning

Radar scans these common ports by default:

- **22**: SSH (Secure Shell)
- **23**: Telnet
- **53**: DNS (Domain Name System)
- **80**: HTTP (Web Server)
- **135**: Microsoft RPC
- **139**: NetBIOS Session Service
- **443**: HTTPS (Secure Web Server)
- **445**: Microsoft SMB (File Sharing)
- **993**: IMAPS (Secure Email)
- **995**: POP3S (Secure Email)
- **1723**: PPTP VPN
- **3389**: RDP (Remote Desktop)
- **5900**: VNC (Remote Desktop)
- **8080**: HTTP Alternate

## Security Considerations

- **Network Permission**: Ensure you have permission to scan the target networks
- **Firewall Impact**: Some firewalls may detect port scanning as suspicious activity
- **Performance**: Large network scans may take several minutes to complete
- **Resource Usage**: Concurrent scanning uses multiple threads and network resources

## Troubleshooting

### Common Issues

1. **"Permission Denied" errors**
   - Run the application with administrator/root privileges
   - Check firewall settings

2. **No devices found**
   - Verify network connectivity
   - Try scanning a specific smaller subnet
   - Check if devices respond to ping

3. **Scan takes too long**
   - Use smaller network ranges
   - Some devices may have slow response times
   - Network congestion can affect scan speed

4. **Application won't start**
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - Check if port 5000 is available
   - Try running with: `python -m flask run`

### Performance Tips

- Scan smaller network ranges for faster results
- Close unnecessary network applications during scanning
- Use wired connections for more reliable results
- Scan during off-peak network hours

## Technical Details

### Architecture

- **Backend**: Python Flask web framework
- **Network Scanning**: Python sockets, subprocess (ping), threading
- **Frontend**: HTML5, CSS3, JavaScript (vanilla)
- **Concurrency**: ThreadPoolExecutor for parallel scanning

### Scanning Process

1. **Network Detection**: Uses `netifaces` to discover local network interfaces
2. **Host Discovery**: Ping sweep to find active hosts
3. **Port Scanning**: TCP connect scans on common ports
4. **Service Detection**: Hostname resolution and service identification
5. **Real-time Updates**: WebSocket-like polling for progress updates

## License

This project is open source. Feel free to modify and distribute according to your needs.

## Contributing

Contributions are welcome! Areas for improvement:

- Additional port scanning options
- Enhanced device fingerprinting
- Export functionality (CSV, JSON)
- Scheduled scanning
- Network mapping visualization
- SNMP device information gathering

## Author

**Roberto Raimondo** - IS Senior Systems Engineer II

A network surveillance application designed and developed for tactical network reconnaissance and device discovery operations.

## Version History


- **v1.0**: Initial release with basic network scanning and web UI
