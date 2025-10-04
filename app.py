#!/usr/bin/env python3
"""
Radar - Network Device Scanner
A web-based network scanner to discover devices on your network
"""

import socket
import threading
import ipaddress
import subprocess
import platform
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from flask import Flask, render_template, jsonify, request
import time

app = Flask(__name__)

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.scan_status = {'scanning': False, 'progress': 0, 'total': 0}
    
    def get_local_networks(self):
        """Get all local network interfaces and their subnets using Windows-compatible method"""
        networks = []
        try:
            if platform.system().lower() == "windows":
                # Use ipconfig on Windows
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                output = result.stdout
                
                # Parse IP addresses and subnet masks from ipconfig output
                ip_pattern = r'IPv4 Address[.\s]*: (\d+\.\d+\.\d+\.\d+)'
                mask_pattern = r'Subnet Mask[.\s]*: (\d+\.\d+\.\d+\.\d+)'
                
                ips = re.findall(ip_pattern, output)
                masks = re.findall(mask_pattern, output)
                
                for ip, mask in zip(ips, masks):
                    if ip != '127.0.0.1':  # Skip loopback
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                            networks.append(str(network))
                        except:
                            continue
            else:
                # Use ip command on Linux/Mac
                try:
                    result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
                    for line in result.stdout.split('\n'):
                        if 'src' in line and '/' in line:
                            parts = line.split()
                            for part in parts:
                                if '/' in part and not part.startswith('169.254'):  # Skip APIPA
                                    try:
                                        network = ipaddress.IPv4Network(part, strict=False)
                                        networks.append(str(network))
                                    except:
                                        continue
                except:
                    pass
            
            # Fallback: detect current IP and assume common subnet
            if not networks:
                try:
                    # Get local IP by connecting to a remote address
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    
                    # Assume /24 subnet for common home networks
                    if local_ip != '127.0.0.1':
                        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                        networks.append(str(network))
                except:
                    # Last resort: common private networks
                    networks = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']
                    
        except Exception as e:
            # Fallback to common networks
            networks = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']
        
        return list(set(networks))  # Remove duplicates
    
    def ping_host(self, ip):
        """Ping a single host to check if it's alive"""
        try:
            # Use appropriate ping command based on OS
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port, timeout=1):
        """Scan a single port on an IP address"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Try to resolve hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def scan_common_ports(self, ip):
        """Scan common ports on a host"""
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900, 8080]
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port, 0.5): port for port in common_ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except:
                    pass
        
        return sorted(open_ports)
    
    def scan_device(self, ip):
        """Scan a single device for information"""
        if self.ping_host(ip):
            hostname = self.get_hostname(ip)
            open_ports = self.scan_common_ports(ip)
            
            # Try to identify device type based on open ports
            device_type = self.identify_device_type(open_ports)
            
            device_info = {
                'ip': ip,
                'hostname': hostname or 'Unknown',
                'open_ports': open_ports,
                'device_type': device_type,
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'online'
            }
            
            return device_info
        return None
    
    def identify_device_type(self, open_ports):
        """Try to identify device type based on open ports"""
        if 22 in open_ports:
            return 'Linux/Unix Server'
        elif 3389 in open_ports:
            return 'Windows Computer'
        elif 80 in open_ports or 443 in open_ports:
            if 22 in open_ports:
                return 'Web Server (Linux)'
            elif 135 in open_ports:
                return 'Web Server (Windows)'
            else:
                return 'Web Server/Router'
        elif 23 in open_ports:
            return 'Network Device/Router'
        elif 139 in open_ports or 445 in open_ports:
            return 'Windows Computer'
        elif 5900 in open_ports:
            return 'VNC Server'
        else:
            return 'Unknown Device'
    
    def scan_network(self, network=None, callback=None):
        """Scan the entire network for devices"""
        self.scan_status['scanning'] = True
        self.scan_status['progress'] = 0
        self.devices = []
        
        try:
            if network is None:
                networks = self.get_local_networks()
            else:
                networks = [network]
            
            all_ips = []
            for net in networks:
                try:
                    network_obj = ipaddress.IPv4Network(net, strict=False)
                    # Skip network and broadcast addresses for larger networks
                    if network_obj.num_addresses > 2:
                        all_ips.extend([str(ip) for ip in list(network_obj.hosts())])
                    else:
                        all_ips.extend([str(ip) for ip in network_obj])
                except:
                    continue
            
            self.scan_status['total'] = len(all_ips)
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.scan_device, ip): ip for ip in all_ips}
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        device_info = future.result()
                        if device_info:
                            self.devices.append(device_info)
                            if callback:
                                callback(device_info)
                    except Exception as e:
                        pass
                    finally:
                        self.scan_status['progress'] += 1
        
        finally:
            self.scan_status['scanning'] = False
        
        return self.devices

# Global scanner instance
scanner = NetworkScanner()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan')
def scan():
    """Start network scan"""
    network = request.args.get('network', None)
    
    if scanner.scan_status['scanning']:
        return jsonify({'status': 'error', 'message': 'Scan already in progress'})
    
    # Start scan in background thread
    def background_scan():
        scanner.scan_network(network)
    
    threading.Thread(target=background_scan, daemon=True).start()
    
    return jsonify({'status': 'success', 'message': 'Scan started'})

@app.route('/status')
def status():
    """Get scan status"""
    return jsonify({
        'scanning': scanner.scan_status['scanning'],
        'progress': scanner.scan_status['progress'],
        'total': scanner.scan_status['total'],
        'devices': len(scanner.devices)
    })

@app.route('/devices')
def devices():
    """Get discovered devices"""
    return jsonify(scanner.devices)

@app.route('/networks')
def networks():
    """Get available networks"""
    return jsonify(scanner.get_local_networks())

if __name__ == '__main__':
    print("Starting Radar Network Scanner...")
    print("Open your web browser and go to: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)