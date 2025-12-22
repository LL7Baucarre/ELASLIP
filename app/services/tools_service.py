"""Tools service for WHOIS, Nmap, and other reconnaissance tools."""

import subprocess
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional


class ToolsService:
    """Service for network reconnaissance tools."""
    
    @staticmethod
    def whois_lookup(target: str) -> Dict:
        """
        Perform WHOIS lookup on domain or IP.
        
        Args:
            target: Domain name or IP address
            
        Returns:
            Dict with WHOIS information
        """
        try:
            result = subprocess.run(
                ['whois', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse common WHOIS fields
            output = result.stdout
            parsed = ToolsService._parse_whois(output)
            
            return {
                'success': True,
                'target': target,
                'raw_output': output,
                'parsed': parsed,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'target': target,
                'error': 'WHOIS lookup timed out'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'target': target,
                'error': 'whois command not found. Please install whois package.'
            }
        except Exception as e:
            return {
                'success': False,
                'target': target,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_whois(output: str) -> Dict:
        """Parse common WHOIS fields from output."""
        parsed = {}
        
        # Common patterns for both domain and IP WHOIS
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'(?:Registry Expiry Date|Expiration Date):\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'registrant_org': r'Registrant Organization:\s*(.+)',
            'registrant_country': r'Registrant Country:\s*(.+)',
            'admin_email': r'Admin Email:\s*(.+)',
            'tech_email': r'Tech Email:\s*(.+)',
            # IP WHOIS specific
            'netname': r'[Nn]etname:\s*(.+)',
            'netrange': r'NetRange:\s*(.+)',
            'cidr': r'CIDR:\s*(.+)',
            'origin_as': r'[Oo]rigin(?:AS)?:\s*(AS\d+)',
            'org_name': r'[Oo]rg(?:anization)?(?:-name)?:\s*(.+)',
            'country': r'[Cc]ountry:\s*(.+)',
            'descr': r'[Dd]escr:\s*(.+)',
        }
        
        for field, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                if field == 'name_servers':
                    parsed[field] = list(set(matches))
                else:
                    parsed[field] = matches[0].strip()
        
        return parsed
    
    @staticmethod
    @staticmethod
    def nmap_scan(target: str, scan_type: str = 'quick', ports: str = None, 
                  custom_args: str = None) -> Dict:
        """
        Perform Nmap scan on target.
        
        Args:
            target: IP address, hostname, or network range
            scan_type: Type of scan (quick, full, service, vuln, custom)
            ports: Custom port specification (e.g., "22,80,443" or "1-1000")
            custom_args: Custom nmap arguments for custom scan type
            
        Returns:
            Dict with scan results
        """
        scan_options = {
            'quick': ['-T4', '-F', '--open'],
            'full': ['-T4', '-p-', '--open'],
            'service': ['-sV', '-T4', '-F', '--open'],
            'vuln': ['-sV', '--script=vuln', '-T4', '-F'],
            'traceroute': ['-T4', '-F', '--traceroute', '--open'],
            'os': ['-O', '-T4', '-F', '--open'],
            'aggressive': ['-A', '-T4', '-F'],
            'custom': []
        }
        
        if scan_type == 'custom' and custom_args:
            # Parse custom arguments safely
            options = custom_args.split()
            # Remove dangerous options
            dangerous = ['-iL', '--script=', '-oN', '-oX', '-oG', '-oA', '-oS']
            options = [o for o in options if not any(d in o for d in dangerous)]
        else:
            options = scan_options.get(scan_type, scan_options['quick'])
        
        # Add custom ports if specified
        if ports:
            options = [o for o in options if not o.startswith('-p') and o != '-F']
            options.append(f'-p{ports}')
        
        try:
            # Use sudo for scans that require root (-O, -A, -sS, -sT, etc.)
            # Check if options contain root-requiring flags
            root_flags = ['-O', '-A', '-sS', '-sT', '-sM', '-sU', '-sA', '-sW', '-sN', '-sF', '-sX', '--script']
            needs_sudo = any(flag in str(options) for flag in root_flags)
            
            if needs_sudo:
                cmd = ['sudo', 'nmap'] + options + ['-oX', '-', target]
            else:
                cmd = ['nmap'] + options + ['-oX', '-', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )
            
            # Log for debugging
            import sys
            print(f"NMAP DEBUG: returncode={result.returncode}, stdout_len={len(result.stdout)}, stderr_len={len(result.stderr)}", file=sys.stderr)
            if result.stderr:
                print(f"NMAP STDERR: {result.stderr}", file=sys.stderr)
            
            # Parse XML output
            parsed = ToolsService._parse_nmap_xml(result.stdout)
            
            return {
                'success': True,
                'target': target,
                'scan_type': scan_type,
                'command': ' '.join(cmd),
                'raw_output': result.stdout,
                'parsed': parsed,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'target': target,
                'error': 'Nmap scan timed out (10 min limit)',
                'raw_output': ''
            }
        except FileNotFoundError:
            return {
                'success': False,
                'target': target,
                'error': 'nmap command not found. Please install nmap package.',
                'raw_output': ''
            }
        except Exception as e:
            return {
                'success': False,
                'target': target,
                'error': str(e),
                'raw_output': ''
            }
    
    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> Dict:
        """Parse Nmap XML output."""
        parsed = {
            'hosts': [],
            'scan_info': {},
            'run_stats': {}
        }
        
        try:
            root = ET.fromstring(xml_output)
            
            # Get scan info
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                parsed['scan_info'] = {
                    'type': scaninfo.get('type'),
                    'protocol': scaninfo.get('protocol'),
                    'numservices': scaninfo.get('numservices'),
                    'services': scaninfo.get('services')
                }
            
            # Get run stats
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                hosts_stats = runstats.find('hosts')
                if finished is not None:
                    parsed['run_stats'] = {
                        'elapsed': finished.get('elapsed'),
                        'summary': finished.get('summary'),
                        'end_time': finished.get('timestr')
                    }
                if hosts_stats is not None:
                    parsed['run_stats']['hosts_up'] = hosts_stats.get('up')
                    parsed['run_stats']['hosts_down'] = hosts_stats.get('down')
                    parsed['run_stats']['hosts_total'] = hosts_stats.get('total')
            
            # Parse each host
            for host in root.findall('host'):
                host_info = {
                    'status': 'unknown',
                    'ip': None,
                    'hostname': None,
                    'addresses': [],
                    'hostnames': [],
                    'ports': [],
                    'os': [],
                    'traceroute': []
                }
                
                # Status
                status = host.find('status')
                if status is not None:
                    host_info['status'] = status.get('state')
                
                # Addresses
                for addr in host.findall('address'):
                    addr_info = {
                        'addr': addr.get('addr'),
                        'addrtype': addr.get('addrtype'),
                        'vendor': addr.get('vendor')
                    }
                    host_info['addresses'].append(addr_info)
                    if addr.get('addrtype') == 'ipv4':
                        host_info['ip'] = addr.get('addr')
                
                # Hostnames
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall('hostname'):
                        hn = {
                            'name': hostname.get('name'),
                            'type': hostname.get('type')
                        }
                        host_info['hostnames'].append(hn)
                        if not host_info['hostname']:
                            host_info['hostname'] = hostname.get('name')
                
                # Ports
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    # Extra ports info
                    extraports = ports_elem.find('extraports')
                    if extraports is not None:
                        host_info['extraports'] = {
                            'state': extraports.get('state'),
                            'count': extraports.get('count')
                        }
                    
                    for port in ports_elem.findall('port'):
                        port_info = {
                            'port': int(port.get('portid')),
                            'protocol': port.get('protocol'),
                            'state': 'unknown',
                            'reason': None,
                            'service': None,
                            'version': None,
                            'product': None,
                            'scripts': []
                        }
                        
                        state = port.find('state')
                        if state is not None:
                            port_info['state'] = state.get('state')
                            port_info['reason'] = state.get('reason')
                        
                        service = port.find('service')
                        if service is not None:
                            port_info['service'] = service.get('name')
                            port_info['product'] = service.get('product')
                            port_info['version'] = service.get('version')
                            extrainfo = service.get('extrainfo')
                            if port_info['product'] and port_info['version']:
                                port_info['version'] = f"{port_info['product']} {port_info['version']}"
                            elif port_info['product']:
                                port_info['version'] = port_info['product']
                            if extrainfo:
                                port_info['version'] = f"{port_info['version'] or ''} ({extrainfo})".strip()
                        
                        # Scripts (for vuln scan)
                        for script in port.findall('script'):
                            port_info['scripts'].append({
                                'id': script.get('id'),
                                'output': script.get('output')
                            })
                        
                        host_info['ports'].append(port_info)
                
                # OS Detection
                os_elem = host.find('os')
                if os_elem is not None:
                    for osmatch in os_elem.findall('osmatch'):
                        host_info['os'].append({
                            'name': osmatch.get('name'),
                            'accuracy': osmatch.get('accuracy')
                        })
                
                # Traceroute
                trace_elem = host.find('trace')
                if trace_elem is not None:
                    for hop in trace_elem.findall('hop'):
                        host_info['traceroute'].append({
                            'ttl': int(hop.get('ttl', 0)),
                            'ip': hop.get('ipaddr'),
                            'hostname': hop.get('host'),
                            'rtt': hop.get('rtt')
                        })
                
                parsed['hosts'].append(host_info)
            
        except ET.ParseError as e:
            parsed['parse_error'] = str(e)
        
        return parsed
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30) -> Dict:
        """
        Perform traceroute to target.
        
        Args:
            target: IP address or hostname
            max_hops: Maximum number of hops (default 30)
            
        Returns:
            Dict with traceroute results
        """
        try:
            # Try ICMP traceroute first (works best in Docker with NET_RAW cap)
            result = subprocess.run(
                ['traceroute', '-I', '-n', '-m', str(max_hops), '-w', '2', target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # If ICMP fails (permission denied), try TCP
            if 'Operation not permitted' in result.stderr or result.returncode != 0:
                result = subprocess.run(
                    ['traceroute', '-T', '-n', '-m', str(max_hops), '-w', '2', target],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            
            # If TCP also fails, fall back to UDP (default, but usually blocked)
            if 'Operation not permitted' in result.stderr or (not result.stdout.strip() and result.returncode != 0):
                result = subprocess.run(
                    ['traceroute', '-n', '-m', str(max_hops), '-w', '2', target],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
            
            hops = ToolsService._parse_traceroute(result.stdout)
            
            return {
                'success': True,
                'target': target,
                'max_hops': max_hops,
                'raw_output': result.stdout,
                'parsed': {
                    'hops': hops
                },
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'target': target,
                'error': 'Traceroute timed out'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'target': target,
                'error': 'traceroute command not found. Please install traceroute package.'
            }
        except Exception as e:
            return {
                'success': False,
                'target': target,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_traceroute(output: str) -> List[Dict]:
        """Parse traceroute output."""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue
            
            # Parse hop number
            match = re.match(r'^\s*(\d+)\s+(.+)$', line)
            if match:
                hop_num = int(match.group(1))
                rest = match.group(2)
                
                # Check for * (timeout)
                if rest.strip() == '* * *':
                    hops.append({
                        'hop': hop_num,
                        'ip': None,
                        'hostname': None,
                        'rtt1': '*',
                        'rtt2': '*',
                        'rtt3': '*',
                        'timeout': True
                    })
                else:
                    # Try to parse hostname/IP and RTT
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', rest)
                    rtt_matches = re.findall(r'([\d.]+)\s*ms', rest)
                    hostname_match = re.match(r'([^\s(]+)', rest)
                    
                    ip = ip_match.group(1) if ip_match else None
                    hostname = hostname_match.group(1) if hostname_match else None
                    
                    # If hostname is an IP, set ip and clear hostname
                    if hostname and re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
                        ip = hostname
                        hostname = None
                    
                    hops.append({
                        'hop': hop_num,
                        'ip': ip,
                        'hostname': hostname if hostname != ip else None,
                        'rtt1': rtt_matches[0] + ' ms' if len(rtt_matches) > 0 else '*',
                        'rtt2': rtt_matches[1] + ' ms' if len(rtt_matches) > 1 else '*',
                        'rtt3': rtt_matches[2] + ' ms' if len(rtt_matches) > 2 else '*',
                        'timeout': False
                    })
        
        return hops
    
    @staticmethod
    def dig_lookup(target: str, record_type: str = 'A') -> Dict:
        """
        Perform DNS lookup using dig.
        
        Args:
            target: Domain name
            record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
            
        Returns:
            Dict with DNS records
        """
        valid_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'ANY']
        record_type = record_type.upper()
        
        if record_type not in valid_types:
            return {
                'success': False,
                'target': target,
                'error': f'Invalid record type. Use: {", ".join(valid_types)}'
            }
        
        try:
            result = subprocess.run(
                ['dig', '+noall', '+answer', '+authority', target, record_type],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            records = ToolsService._parse_dig(result.stdout)
            
            return {
                'success': True,
                'target': target,
                'record_type': record_type,
                'raw_output': result.stdout,
                'parsed': {
                    'records': records
                },
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'target': target,
                'error': 'dig command not found. Please install dnsutils package.'
            }
        except Exception as e:
            return {
                'success': False,
                'target': target,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_dig(output: str) -> List[Dict]:
        """Parse dig output."""
        records = []
        
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            parts = line.split()
            if len(parts) >= 5:
                records.append({
                    'name': parts[0],
                    'ttl': int(parts[1]) if parts[1].isdigit() else None,
                    'class': parts[2],
                    'type': parts[3],
                    'value': ' '.join(parts[4:])
                })
        
        return records
    
    @staticmethod
    def reverse_dns(ip: str) -> Dict:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address
            
        Returns:
            Dict with reverse DNS result
        """
        try:
            # Use Google's DNS server for reliable PTR lookups
            result = subprocess.run(
                ['dig', '-x', ip, '@8.8.8.8', '+noall', '+answer'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            raw_output = result.stdout.strip()
            hostnames = []
            
            # Parse dig output
            for line in raw_output.split('\n'):
                if line and not line.startswith(';'):
                    parts = line.split()
                    if len(parts) >= 5 and parts[3] == 'PTR':
                        hostname = parts[4].rstrip('.')
                        hostnames.append(hostname)
            
            # If dig didn't return results, try with full output for debugging
            if not hostnames:
                result_full = subprocess.run(
                    ['dig', '-x', ip, '@8.8.8.8'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                raw_output = result_full.stdout.strip()
                
                # Parse ANSWER section from full output
                in_answer = False
                for line in raw_output.split('\n'):
                    if ';; ANSWER SECTION:' in line:
                        in_answer = True
                        continue
                    if in_answer:
                        if line.startswith(';;') or not line.strip():
                            break
                        parts = line.split()
                        if len(parts) >= 5 and 'PTR' in parts:
                            ptr_idx = parts.index('PTR')
                            if len(parts) > ptr_idx + 1:
                                hostname = parts[ptr_idx + 1].rstrip('.')
                                hostnames.append(hostname)
            
            return {
                'success': True,
                'target': ip,
                'raw_output': raw_output if raw_output else 'No PTR record found for this IP',
                'parsed': {
                    'hostname': hostnames[0] if hostnames else None,
                    'hostnames': hostnames
                },
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except Exception as e:
            return {
                'success': False,
                'target': ip,
                'error': str(e)
            }

    @staticmethod
    def ping(target: str, count: int = 4) -> Dict:
        """
        Perform ICMP ping to target.
        
        Args:
            target: Domain name or IP address
            count: Number of ping packets to send (default: 4)
            
        Returns:
            Dict with ping statistics
        """
        try:
            # Use -c for Linux/Mac, -n for Windows
            import platform
            system = platform.system().lower()
            if 'windows' in system:
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            raw_output = output
            
            # Log for debugging
            import sys
            print(f"PING DEBUG: system={system}, output_len={len(output)}, returncode={result.returncode}", file=sys.stderr)
            print(f"PING OUTPUT:\n{output}", file=sys.stderr)
            
            # Check for actual connectivity - even if return code != 0, may have partial results
            packets_received = 0
            if 'windows' in system:
                received_match = re.search(r'Received = (\d+)', output)
                if received_match:
                    packets_received = int(received_match.group(1))
            else:
                received_match = re.search(r'(\d+) received', output)
                if received_match:
                    packets_received = int(received_match.group(1))
            
            # Consider success if at least one packet received
            success = result.returncode == 0 or packets_received > 0
            
            # Parse ping output
            parsed = ToolsService._parse_ping(output, system)
            
            return {
                'success': success,
                'target': target,
                'raw_output': raw_output,
                'parsed': parsed,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'target': target,
                'error': 'Ping request timed out',
                'raw_output': ''
            }
        except FileNotFoundError:
            return {
                'success': False,
                'target': target,
                'error': 'ping command not found',
                'raw_output': ''
            }
        except Exception as e:
            return {
                'success': False,
                'target': target,
                'error': str(e),
                'raw_output': ''
            }
    
    @staticmethod
    def _parse_ping(output: str, system: str) -> Dict:
        """Parse ping output for statistics."""
        parsed = {
            'packets_sent': 0,
            'packets_received': 0,
            'packet_loss': '0%',
            'min_rtt': None,
            'avg_rtt': None,
            'max_rtt': None,
            'mdev': None
        }
        
        if system == 'windows':
            # Windows ping format
            sent_match = re.search(r'Packets: Sent = (\d+)', output)
            if sent_match:
                parsed['packets_sent'] = int(sent_match.group(1))
            
            received_match = re.search(r'Received = (\d+)', output)
            if received_match:
                parsed['packets_received'] = int(received_match.group(1))
            
            loss_match = re.search(r'Lost = (\d+).*\((\d+)% loss\)', output)
            if loss_match:
                parsed['packet_loss'] = f"{loss_match.group(2)}%"
            
            # Windows RTT format
            rtt_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
            if rtt_match:
                parsed['min_rtt'] = f"{rtt_match.group(1)}ms"
                parsed['max_rtt'] = f"{rtt_match.group(2)}ms"
                parsed['avg_rtt'] = f"{rtt_match.group(3)}ms"
        else:
            # Linux/Mac ping format
            sent_match = re.search(r'(\d+) packets transmitted', output)
            if sent_match:
                parsed['packets_sent'] = int(sent_match.group(1))
            
            received_match = re.search(r'(\d+) received', output)
            if received_match:
                parsed['packets_received'] = int(received_match.group(1))
            
            loss_match = re.search(r'([\d.]+)% (?:packet loss|loss)', output)
            if loss_match:
                parsed['packet_loss'] = f"{float(loss_match.group(1)):.1f}%"
            
            # Linux/Mac RTT format
            rtt_match = re.search(r'min/avg/(?:max|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)', output)
            if rtt_match:
                parsed['min_rtt'] = f"{rtt_match.group(1)}ms"
                parsed['avg_rtt'] = f"{rtt_match.group(2)}ms"
                parsed['max_rtt'] = f"{rtt_match.group(3)}ms"
                
                # Get mdev if available
                mdev_match = re.search(r'min/avg/max/stddev = [\d.]+/[\d.]+/[\d.]+/([\d.]+)', output)
                if mdev_match:
                    parsed['mdev'] = f"{mdev_match.group(1)}ms"
        
        return parsed
