"""Service for GeoIP lookups."""

import os
import requests
from typing import Dict, Optional
from datetime import datetime


class GeoIPService:
    """Service for performing GeoIP lookups."""
    
    def __init__(self):
        self.geoip_provider = os.getenv('GEOIP_PROVIDER', 'ip-api')
        self.geoip_api_key = os.getenv('GEOIP_API_KEY', '')
    
    def lookup(self, ip_address: str) -> Dict:
        """
        Perform GeoIP lookup on an IP address.
        
        Args:
            ip_address: IP address to look up
        
        Returns:
            Dictionary with geolocation data
        
        Raises:
            ValueError: If IP is invalid or lookup fails
        """
        # Validate IP format
        if not self._is_valid_ip(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")
        
        if self.geoip_provider == 'ip-api':
            return self._lookup_ip_api(ip_address)
        elif self.geoip_provider == 'ipstack':
            return self._lookup_ipstack(ip_address)
        else:
            raise ValueError(f"Unknown GeoIP provider: {self.geoip_provider}")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _lookup_ip_api(self, ip_address: str) -> Dict:
        """Lookup using ip-api.com (free tier)."""
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == 'fail':
                raise ValueError(data.get('message', 'GeoIP lookup failed'))
            
            return {
                'ip': ip_address,
                'continent': data.get('continent'),
                'continent_code': data.get('continentCode'),
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'region': data.get('region'),
                'region_name': data.get('regionName'),
                'city': data.get('city'),
                'district': data.get('district'),
                'postal_code': data.get('zip'),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'timezone': data.get('timezone'),
                'utc_offset': data.get('offset'),
                'currency': data.get('currency'),
                'isp': data.get('isp'),
                'organization': data.get('org'),
                'asn': data.get('as'),
                'asn_name': data.get('asname'),
                'reverse_dns': data.get('reverse'),
                'is_mobile': data.get('mobile', False),
                'is_proxy': data.get('proxy', False),
                'is_hosting': data.get('hosting', False),
                'provider': 'ip-api.com',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except requests.RequestException as e:
            raise ValueError(f"GeoIP lookup failed: {str(e)}")
    
    def _lookup_ipstack(self, ip_address: str) -> Dict:
        """Lookup using ipstack.com."""
        if not self.geoip_api_key:
            raise ValueError("ipstack API key not configured")
        
        try:
            url = f"http://api.ipstack.com/{ip_address}?access_key={self.geoip_api_key}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('ip'):
                raise ValueError(data.get('error', {}).get('info', 'GeoIP lookup failed'))
            
            return {
                'ip': ip_address,
                'continent': data.get('continent_name'),
                'continent_code': data.get('continent_code'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'region': data.get('region_code'),
                'region_name': data.get('region_name'),
                'city': data.get('city'),
                'postal_code': data.get('zip'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('time_zone', {}).get('id'),
                'is_mobile': data.get('connection', {}).get('is_mobile', False),
                'is_proxy': data.get('security', {}).get('is_proxy', False),
                'provider': 'ipstack.com',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        except requests.RequestException as e:
            raise ValueError(f"GeoIP lookup failed: {str(e)}")
    
    def bulk_lookup(self, ip_addresses: list) -> Dict:
        """
        Perform bulk GeoIP lookups.
        
        Args:
            ip_addresses: List of IP addresses to look up
        
        Returns:
            Dictionary with results and failures
        """
        results = []
        failures = []
        
        for ip in ip_addresses:
            try:
                result = self.lookup(ip)
                results.append(result)
            except ValueError as e:
                failures.append({
                    'ip': ip,
                    'error': str(e)
                })
        
        return {
            'results': results,
            'failures': failures,
            'total': len(ip_addresses),
            'successful': len(results),
            'failed': len(failures)
        }
