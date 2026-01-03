"""Tools service for WHOIS, Nmap, and other reconnaissance tools."""

import subprocess
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional
import ipaddress
import logging
logger = logging.getLogger(__name__)


class ToolsService:
    """Service for network reconnaissance tools."""
    
    @staticmethod
    def _validate_target(target: str) -> bool:
        """
        Validate target is a valid IP or hostname.
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not target or not isinstance(target, str):
            return False
        
        # Try to parse as IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Try to validate as hostname
        if len(target) > 255:
            return False
        
        # Allow alphanumeric, hyphens, dots, and underscores in hostname
        if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-_.]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-_]*[a-zA-Z0-9])?$', target):
            return True
        
        return False
    
    @staticmethod
    def _validate_ports(ports: str) -> bool:
        """
        Validate port specification.
        
        Args:
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            
        Returns:
            True if valid, False otherwise
        """
        if not ports or not isinstance(ports, str):
            return False
        
        # Allow only digits, commas, and hyphens
        if not re.match(r'^[0-9,\-]+$', ports):
            return False
        
        # Validate each port number
        parts = re.split(r'[,\-]', ports)
        for part in parts:
            if part and (not part.isdigit() or int(part) < 1 or int(part) > 65535):
                return False
        
        return True
    
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
        # Validate target
        if not ToolsService._validate_target(target):
            return {
                'success': False,
                'target': target,
                'error': 'Invalid target format'
            }
        
        # Validate ports if provided
        if ports and not ToolsService._validate_ports(ports):
            return {
                'success': False,
                'target': target,
                'error': 'Invalid port specification'
            }
        
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
                shell=False,
                timeout=600  # 10 minutes timeout
            )
            
            # Log for debugging
            logger.debug("NMAP DEBUG: returncode=%s, stdout_len=%d, stderr_len=%d", result.returncode, len(result.stdout), len(result.stderr))
            if result.stderr:
                logger.debug("NMAP STDERR: %s", result.stderr)
            
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
        # Validate target
        if not ToolsService._validate_target(target):
            return {
                'success': False,
                'target': target,
                'error': 'Invalid target format'
            }
        
        # Validate count
        if not isinstance(count, int) or count < 1 or count > 100:
            return {
                'success': False,
                'target': target,
                'error': 'Invalid packet count'
            }
        
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
                shell=False,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            raw_output = output
            
            # Log for debugging
            logger.debug("PING DEBUG: system=%s, output_len=%d, returncode=%s", system, len(output), result.returncode)
            logger.debug("PING OUTPUT:\n%s", output)
            
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
    
    @staticmethod
    def analyze_file(file_obj) -> Dict:
        """
        Analyze an uploaded file and extract details and metadata.
        
        Args:
            file_obj: Flask file object from request.files
            
        Returns:
            Dict with file details (hash, type, size, metadata, etc.)
        """
        import hashlib
        import mimetypes
        from pathlib import Path
        import struct
        from datetime import datetime
        
        if not file_obj or file_obj.filename == '':
            return {'success': False, 'error': 'No file provided'}
        
        try:
            # Read file content
            file_content = file_obj.read()
            file_obj.seek(0)  # Reset file pointer
            
            # Get file name and extension
            filename = file_obj.filename
            file_path = Path(filename)
            file_extension = file_path.suffix.lower()
            
            # Get MIME type
            mime_type, _ = mimetypes.guess_type(filename)
            if not mime_type:
                mime_type = 'application/octet-stream'
            
            # Calculate hashes
            md5_hash = hashlib.md5(file_content).hexdigest()
            sha1_hash = hashlib.sha1(file_content).hexdigest()
            sha256_hash = hashlib.sha256(file_content).hexdigest()
            
            # File size
            file_size = len(file_content)
            
            # Get file magic signature (first bytes)
            file_magic = file_content[:32].hex()
            
            # Additional analysis
            is_binary = any(byte > 127 for byte in file_content[:512])
            
            # Extract metadata
            metadata = {
                'file_entropy': ToolsService._calculate_entropy(file_content),
                'sections': ToolsService._analyze_sections(file_content, mime_type),
                'properties': {}
            }
            
            # Try to extract document metadata
            if mime_type.startswith('application/pdf'):
                metadata['properties'] = ToolsService._extract_pdf_metadata(file_content)
            elif 'officedocument' in mime_type or 'ms-word' in mime_type or 'spreadsheet' in mime_type:
                metadata['properties'] = ToolsService._extract_office_metadata(file_content)
            elif mime_type.startswith('image/'):
                metadata['properties'] = ToolsService._extract_image_metadata(file_content)
            
            return {
                'success': True,
                'filename': filename,
                'extension': file_extension,
                'size': file_size,
                'mime_type': mime_type,
                'is_binary': is_binary,
                'hashes': {
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash
                },
                'magic_signature': file_magic,
                'metadata': metadata
            }
            
        except Exception as e:
            logger.error(f'File analysis error: {str(e)}')
            return {'success': False, 'error': f'File analysis failed: {str(e)}'}
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of file content."""
        if not data:
            return 0.0
        
        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i]))
            if freq > 0:
                p = freq / len(data)
                entropy -= p * (p and __import__('math').log2(p) or 0)
        return round(entropy, 2)
    
    @staticmethod
    def _analyze_sections(data: bytes, mime_type: str) -> Dict:
        """Analyze file sections/structure."""
        sections = {
            'size_readable': ToolsService._format_size(len(data))
        }
        
        # PE executable detection
        if data.startswith(b'MZ'):
            sections['type'] = 'PE Executable'
            try:
                e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
                if e_lfanew < len(data) and data[e_lfanew:e_lfanew+2] == b'PE':
                    sections['pe_signature'] = 'Valid'
                    
                    # Determine specific PE type (DLL, EXE, SYS, etc.)
                    # Characteristics field is at offset e_lfanew + 0x16 (2 bytes, little-endian)
                    if e_lfanew + 0x18 < len(data):
                        characteristics = struct.unpack('<H', data[e_lfanew+0x16:e_lfanew+0x18])[0]
                        
                        # Check DLL flag (0x2000)
                        if characteristics & 0x2000:
                            sections['pe_type'] = 'DLL (Dynamic Link Library)'
                        # Check executable flag (0x0002)
                        elif characteristics & 0x0002:
                            sections['pe_type'] = 'EXE (Executable)'
                        # Check driver flag (system driver)
                        elif characteristics & 0x1000:
                            sections['pe_type'] = 'SYS (System Driver)'
                        else:
                            sections['pe_type'] = 'PE Object File'
                        
                        # Get machine type (CPU architecture)
                        if e_lfanew + 0x04 < len(data):
                            machine = struct.unpack('<H', data[e_lfanew:e_lfanew+0x02])[0]
                            machine_types = {
                                0x014c: 'i386 (32-bit Intel)',
                                0x8664: 'x64 (64-bit Intel)',
                                0x01c0: 'ARM',
                                0xaa64: 'ARM64',
                                0x0200: 'MIPS',
                                0x0ebc: '.NET Runtime'
                            }
                            sections['architecture'] = machine_types.get(machine, f'Unknown (0x{machine:04x})')
            except:
                pass
        
        # ELF detection
        elif data.startswith(b'\x7fELF'):
            sections['type'] = 'ELF Executable'
        
        # ZIP detection (DOCX, XLSX, JAR, etc.)
        elif data.startswith(b'PK\x03\x04'):
            sections['type'] = 'ZIP Archive'
        
        # PDF detection
        elif data.startswith(b'%PDF'):
            sections['type'] = 'PDF Document'
        
        return sections
    
    @staticmethod
    def _extract_pdf_metadata(data: bytes) -> Dict:
        """Extract metadata from PDF."""
        metadata = {}
        try:
            # Look for /Info dictionary in PDF
            info_start = data.find(b'/Info')
            if info_start > -1:
                info_section = data[info_start:info_start+500]
                
                # Extract common PDF metadata
                fields = {
                    '/Title': 'title',
                    '/Author': 'author',
                    '/Subject': 'subject',
                    '/Creator': 'creator',
                    '/Producer': 'producer',
                    '/CreationDate': 'creation_date',
                    '/ModDate': 'modification_date'
                }
                
                for pdf_field, key in fields.items():
                    pattern = pdf_field.encode() + b'[^)]*\\(([^)]*)\\)'
                    import re
                    match = re.search(pattern, info_section)
                    if match:
                        value = match.group(1).decode('utf-8', errors='ignore')
                        metadata[key] = value
        except:
            pass
        
        return metadata
    
    @staticmethod
    def _extract_office_metadata(data: bytes) -> Dict:
        """Extract metadata from Office documents."""
        metadata = {}
        try:
            import zipfile
            from io import BytesIO
            import xml.etree.ElementTree as ET
            
            # Office documents are ZIP files
            with zipfile.ZipFile(BytesIO(data)) as zf:
                # Try to read docProps/core.xml
                try:
                    with zf.open('docProps/core.xml') as f:
                        root = ET.fromstring(f.read())
                        ns = {
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'cp': 'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties',
                            'dcterms': 'http://purl.org/dc/terms/'
                        }
                        
                        # Extract common properties
                        for elem in root:
                            if 'title' in elem.tag.lower():
                                metadata['title'] = elem.text
                            elif 'creator' in elem.tag.lower():
                                metadata['creator'] = elem.text
                            elif 'subject' in elem.tag.lower():
                                metadata['subject'] = elem.text
                            elif 'created' in elem.tag.lower():
                                metadata['creation_date'] = elem.text
                            elif 'modified' in elem.tag.lower():
                                metadata['modification_date'] = elem.text
                except:
                    pass
                
                # Try docProps/app.xml for document statistics
                try:
                    with zf.open('docProps/app.xml') as f:
                        root = ET.fromstring(f.read())
                        for elem in root:
                            tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                            if tag_name in ['Pages', 'Words', 'Characters', 'Application']:
                                metadata[tag_name.lower()] = elem.text
                except:
                    pass
        except:
            pass
        
        return metadata
    
    @staticmethod
    def _extract_image_metadata(data: bytes) -> Dict:
        """Extract metadata from images."""
        metadata = {}
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            from io import BytesIO
            
            img = Image.open(BytesIO(data))
            
            # Basic image info
            metadata['format'] = img.format
            metadata['width'] = img.width
            metadata['height'] = img.height
            
            # Extract EXIF data if available
            exif_data = img._getexif() if hasattr(img, '_getexif') else None
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    try:
                        # Only include readable metadata
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='ignore')
                        metadata[tag_name] = str(value)[:100]  # Limit to 100 chars
                    except:
                        pass
        except:
            pass
        
        return metadata
    
    @staticmethod
    def _format_size(size: int) -> str:
        """Format byte size to human-readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f'{size:.2f} {unit}'
            size /= 1024.0
        return f'{size:.2f} TB'

    @staticmethod
    def analyze_dmarc_dkim(domain: str) -> Dict:
        """
        Analyze DMARC and DKIM records for a domain.
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dict with DMARC, DKIM, and SPF record analysis
        """
        try:
            analysis = {
                'success': True,
                'target': domain,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'dmarc': None,
                'dkim': None,
                'spf': None,
                'raw_output': {}
            }
            
            # Fetch DMARC record (_dmarc.domain)
            dmarc_result = subprocess.run(
                ['dig', f'_dmarc.{domain}', 'TXT', '+short', '@8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if dmarc_result.stdout.strip():
                dmarc_raw = dmarc_result.stdout.strip()
                analysis['raw_output']['dmarc'] = dmarc_raw
                analysis['dmarc'] = ToolsService._parse_dmarc_record(dmarc_raw)
            else:
                analysis['dmarc'] = {'found': False, 'message': 'No DMARC record found'}
            
            # Fetch SPF record (domain TXT)
            spf_result = subprocess.run(
                ['dig', domain, 'TXT', '+short', '@8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if spf_result.stdout.strip():
                spf_raw = spf_result.stdout.strip()
                analysis['raw_output']['spf'] = spf_raw
                analysis['spf'] = ToolsService._parse_spf_record(spf_raw)
            else:
                analysis['spf'] = {'found': False, 'message': 'No SPF record found'}
            
            # Try to find DKIM records (check common selectors)
            common_selectors = [
                'default',
                'selector1',
                'selector2',
                'k1',
                'k2',
                'google',
                'amazon',
                'mailgun',
                'sendgrid',
                'mandrill'
            ]
            
            dkim_records = {}
            for selector in common_selectors:
                dkim_query = f'{selector}._domainkey.{domain}'
                dkim_result = subprocess.run(
                    ['dig', dkim_query, 'TXT', '+short', '@8.8.8.8'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if dkim_result.stdout.strip():
                    dkim_raw = dkim_result.stdout.strip()
                    dkim_records[selector] = {
                        'found': True,
                        'raw': dkim_raw,
                        'parsed': ToolsService._parse_dkim_record(dkim_raw, selector)
                    }
            
            if dkim_records:
                analysis['dkim'] = dkim_records
            else:
                analysis['dkim'] = {'found': False, 'message': 'No DKIM records found'}
            
            # Calculate security score
            analysis['security_score'] = ToolsService._calculate_email_security_score(analysis)
            
            # Generate recommendations
            analysis['recommendations'] = ToolsService._generate_dmarc_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            return {
                'success': False,
                'target': domain,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_dmarc_record(raw_record: str) -> Dict:
        """Parse DMARC record and extract policy settings."""
        parsed = {
            'found': True,
            'raw': raw_record,
            'policy': None,
            'subdomain_policy': None,
            'alignment': {},
            'reporting': {},
            'forensics': {},
            'tags': {}
        }
        
        # Remove quotes
        clean_record = raw_record.replace('"', '')
        
        # Parse tags
        for tag_pair in clean_record.split(';'):
            tag_pair = tag_pair.strip()
            if '=' in tag_pair:
                key, value = tag_pair.split('=', 1)
                key = key.strip()
                value = value.strip()
                parsed['tags'][key] = value
                
                # Extract specific fields
                if key == 'p':
                    parsed['policy'] = value
                elif key == 'sp':
                    parsed['subdomain_policy'] = value
                elif key == 'adkim':
                    parsed['alignment']['dkim'] = value
                elif key == 'aspf':
                    parsed['alignment']['spf'] = value
                elif key == 'rua':
                    parsed['reporting']['aggregate'] = value
                elif key == 'ruf':
                    parsed['reporting']['forensics'] = value
                elif key == 'fo':
                    parsed['forensics']['options'] = value
                elif key == 'rf':
                    parsed['forensics']['format'] = value
                elif key == 'pct':
                    parsed['forensics']['percentage'] = int(value) if value.isdigit() else value
        
        return parsed
    
    @staticmethod
    def _parse_spf_record(raw_record: str) -> Dict:
        """Parse SPF record and extract mechanisms."""
        parsed = {
            'found': True,
            'raw': raw_record,
            'version': None,
            'mechanisms': [],
            'qualifiers': {}
        }
        
        # Remove quotes
        clean_record = raw_record.replace('"', '')
        
        # Extract version
        if clean_record.startswith('v=spf1'):
            parsed['version'] = 'SPFv1'
            mechanisms_str = clean_record[7:].strip()
        else:
            mechanisms_str = clean_record
        
        # Parse mechanisms
        for mechanism in mechanisms_str.split():
            mechanism = mechanism.strip()
            if mechanism:
                # Determine qualifier
                if mechanism.startswith('-'):
                    qualifier = 'fail'
                    mech = mechanism[1:]
                elif mechanism.startswith('+'):
                    qualifier = 'pass'
                    mech = mechanism[1:]
                elif mechanism.startswith('~'):
                    qualifier = 'softfail'
                    mech = mechanism[1:]
                elif mechanism.startswith('?'):
                    qualifier = 'neutral'
                    mech = mechanism[1:]
                else:
                    qualifier = 'pass'
                    mech = mechanism
                
                parsed['mechanisms'].append({
                    'mechanism': mech,
                    'qualifier': qualifier
                })
        
        return parsed
    
    @staticmethod
    def _parse_dkim_record(raw_record: str, selector: str) -> Dict:
        """Parse DKIM record and extract key information."""
        parsed = {
            'selector': selector,
            'found': True,
            'version': None,
            'algorithm': None,
            'key_type': None,
            'key_length': 0,
            'tags': {}
        }
        
        # Remove quotes
        clean_record = raw_record.replace('"', '')
        
        # Parse tags
        for tag_pair in clean_record.split(';'):
            tag_pair = tag_pair.strip()
            if '=' in tag_pair:
                key, value = tag_pair.split('=', 1)
                key = key.strip()
                value = value.strip()
                parsed['tags'][key] = value
                
                # Extract specific fields
                if key == 'v':
                    parsed['version'] = value
                elif key == 'k':
                    parsed['key_type'] = value
                elif key == 'a':
                    parsed['algorithm'] = value
                elif key == 'p':
                    # Calculate key length
                    try:
                        # Remove whitespace and estimate key size
                        key_data = value.replace(' ', '').replace('\n', '')
                        # Base64 encoded key, 4 chars = 3 bytes
                        parsed['key_length'] = (len(key_data) * 3) // 4
                    except:
                        pass
        
        return parsed
    
    @staticmethod
    def _calculate_email_security_score(analysis: Dict) -> Dict:
        """Calculate overall email security score."""
        score = {
            'total': 0,
            'max': 100,
            'details': {}
        }
        
        # DMARC: 40 points
        dmarc_score = 0
        if analysis.get('dmarc') and analysis['dmarc'].get('found'):
            policy = analysis['dmarc'].get('policy')
            if policy == 'reject':
                dmarc_score = 40
            elif policy == 'quarantine':
                dmarc_score = 30
            elif policy == 'none':
                dmarc_score = 10
        score['details']['dmarc'] = dmarc_score
        
        # SPF: 30 points
        spf_score = 0
        if analysis.get('spf') and analysis['spf'].get('found'):
            spf_score = 30
        score['details']['spf'] = spf_score
        
        # DKIM: 30 points
        dkim_score = 0
        if analysis.get('dkim'):
            if isinstance(analysis['dkim'], dict) and analysis['dkim'].get('found') is False:
                dkim_score = 0
            else:
                # Count DKIM records (more selectors = better)
                dkim_count = len([k for k, v in analysis['dkim'].items() if isinstance(v, dict) and v.get('found')])
                if dkim_count >= 2:
                    dkim_score = 30
                elif dkim_count >= 1:
                    dkim_score = 20
        score['details']['dkim'] = dkim_score
        
        score['total'] = dmarc_score + spf_score + dkim_score
        
        return score
    
    @staticmethod
    def _generate_dmarc_recommendations(analysis: Dict) -> List[str]:
        """Generate security recommendations based on DMARC analysis."""
        recommendations = []
        
        # DMARC recommendations
        if analysis.get('dmarc'):
            if not analysis['dmarc'].get('found'):
                recommendations.append('⚠️  Implement DMARC record to prevent email spoofing')
            else:
                policy = analysis['dmarc'].get('policy')
                if policy == 'none':
                    recommendations.append('⚠️  Upgrade DMARC policy from "none" to "quarantine" or "reject"')
                elif policy == 'quarantine':
                    recommendations.append('💡 Consider upgrading DMARC policy from "quarantine" to "reject" once fully deployed')
        
        # SPF recommendations
        if analysis.get('spf'):
            if not analysis['spf'].get('found'):
                recommendations.append('⚠️  Implement SPF record to prevent email spoofing')
            else:
                mechanisms = analysis['spf'].get('mechanisms', [])
                has_all = any(m['mechanism'] in ['all', '-all'] for m in mechanisms)
                if not has_all:
                    recommendations.append('⚠️  Add "all" or "-all" mechanism at the end of SPF record')
        
        # DKIM recommendations
        if analysis.get('dkim'):
            if isinstance(analysis['dkim'], dict) and analysis['dkim'].get('found') is False:
                recommendations.append('⚠️  Implement DKIM signing for email authentication')
            else:
                dkim_records = analysis['dkim']
                for selector, record in dkim_records.items():
                    if isinstance(record, dict) and record.get('parsed'):
                        key_length = record['parsed'].get('key_length', 0)
                        if key_length < 2048:
                            recommendations.append(f'⚠️  DKIM key for selector "{selector}" should be at least 2048 bits')
        
        # Alignment recommendations
        if analysis.get('dmarc') and analysis['dmarc'].get('found'):
            dmarc = analysis['dmarc']
            if dmarc.get('alignment', {}).get('dkim') != 'strict':
                recommendations.append('💡 Consider using strict DKIM alignment (adkim=s)')
            if dmarc.get('alignment', {}).get('spf') != 'strict':
                recommendations.append('💡 Consider using strict SPF alignment (aspf=s)')
        
        if not recommendations:
            recommendations.append('✅ Email authentication configuration looks good')
        
        return recommendations
