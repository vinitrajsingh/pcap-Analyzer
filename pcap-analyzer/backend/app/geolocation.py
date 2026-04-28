"""
IP Geolocation module for PCAP Analyzer.
Maps IP addresses to geographic locations using MaxMind GeoLite2 database.
"""
import os
import sys
import ipaddress
from typing import Dict, List, Any, Optional
from collections import Counter
import pandas as pd

# Try to import geoip2, handle if not installed
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    print("geoip2 not installed. Run: pip install geoip2")

# Path to GeoLite2 database
GEOLITE_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City.mmdb')


class GeoLocationAnalyzer:
    #Analyze IP addresses and map them to geographic locations.
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or GEOLITE_DB_PATH
        self.reader = None
        self._init_reader()
        self._cache = {}  # Cache lookups to avoid repeated queries
    
    def _init_reader(self):
        if not GEOIP2_AVAILABLE:
            self.reader = None
            return
            
        try:
            if os.path.exists(self.db_path):
                self.reader = geoip2.database.Reader(self.db_path)
            else:
                self.reader = None
        except Exception as e:
            self.reader = None
    
    def is_available(self) -> bool:
        return self.reader is not None
    
    def _is_private_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or
                ip_obj.is_multicast or
                ip_obj.is_reserved or
                ip_obj.is_unspecified
            )
        except ValueError:
            return True  # Invalid IP, treat as private
    
    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]
        
        # Skip private/local IP addresses
        if self._is_private_ip(ip):
            result = {
                "ip": ip,
                "country": "Private/Local",
                "country_code": "XX",
                "city": "Local Network",
                "region": None,
                "latitude": None,
                "longitude": None,
                "timezone": None,
                "is_private": True
            }
            self._cache[ip] = result
            return result
        
        if not self.reader:
            return None
        
        try:
            response = self.reader.city(ip)
            result = {
                "ip": ip,
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "XX",
                "city": response.city.name or "Unknown",
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "latitude": float(response.location.latitude) if response.location.latitude else None,
                "longitude": float(response.location.longitude) if response.location.longitude else None,
                "timezone": response.location.time_zone,
                "is_private": False
            }
            self._cache[ip] = result
            return result
            
        except geoip2.errors.AddressNotFoundError:
            result = {
                "ip": ip,
                "country": "Unknown",
                "country_code": "XX",
                "city": "Unknown",
                "region": None,
                "latitude": None,
                "longitude": None,
                "timezone": None,
                "is_private": False
            }
            self._cache[ip] = result
            return result
            
        except Exception as e:
            return None
    
    def analyze_dataframe(self, df: pd.DataFrame) -> Dict[str, Any]:
        
        if df.empty:
            return self._empty_result()
        
        # Collect unique source IPs
        src_ips = set()
        if 'src_ip' in df.columns:
            src_series = df['src_ip'].dropna().astype(str)
            src_series = src_series[src_series != 'None']
            src_series = src_series[src_series != 'nan']
            src_series = src_series[src_series != '']
            src_ips = set(src_series.unique())
        
        # Collect unique destination IPs
        dst_ips = set()
        if 'dst_ip' in df.columns:
            dst_series = df['dst_ip'].dropna().astype(str)
            dst_series = dst_series[dst_series != 'None']
            dst_series = dst_series[dst_series != 'nan']
            dst_series = dst_series[dst_series != '']
            dst_ips = set(dst_series.unique())
        
        all_ips = src_ips | dst_ips
        
        # Look up each IP
        ip_locations = {}
        for ip in all_ips:
            location = self.lookup_ip(ip)
            if location:
                ip_locations[ip] = location
        
        # Generate statistics
        return self._generate_statistics(df, ip_locations, src_ips, dst_ips)
    
    def _generate_statistics(self, df: pd.DataFrame, ip_locations: Dict, 
                            src_ips: set, dst_ips: set) -> Dict[str, Any]:
        # Generate geolocation statistics from IP locations.
        
        # Country and city counters
        country_counter = Counter()
        city_counter = Counter()
        
        # Separate source and destination map points
        src_map_points = []
        dst_map_points = []
        
        for ip, loc in ip_locations.items():
            # Skip private IPs for country/city stats
            if not loc.get('is_private', False):
                country = loc.get('country', 'Unknown')
                if country and country != 'Unknown':
                    country_counter[country] += 1
                
                city = loc.get('city', 'Unknown')
                country_code = loc.get('country_code', 'XX')
                if city and city != 'Unknown':
                    city_counter[f"{city}, {country_code}"] += 1
            
            # Add to map points if has coordinates
            if loc.get('latitude') is not None and loc.get('longitude') is not None:
                point = {
                    "ip": ip,
                    "lat": loc['latitude'],
                    "lon": loc['longitude'],
                    "country": loc.get('country', 'Unknown'),
                    "country_code": loc.get('country_code', 'XX'),
                    "city": loc.get('city', 'Unknown'),
                    "is_private": loc.get('is_private', False)
                }
                
                if ip in src_ips:
                    src_map_points.append({**point, "type": "source"})
                if ip in dst_ips:
                    dst_map_points.append({**point, "type": "destination"})
        
        # Count packets per country (traffic volume)
        country_traffic = Counter()
        if 'src_ip' in df.columns:
            for ip in df['src_ip'].dropna().astype(str):
                if ip in ip_locations and not ip_locations[ip].get('is_private', False):
                    country = ip_locations[ip].get('country', 'Unknown')
                    if country != 'Unknown':
                        country_traffic[country] += 1
        
        if 'dst_ip' in df.columns:
            for ip in df['dst_ip'].dropna().astype(str):
                if ip in ip_locations and not ip_locations[ip].get('is_private', False):
                    country = ip_locations[ip].get('country', 'Unknown')
                    if country != 'Unknown':
                        country_traffic[country] += 1
        
        # Generate connection lines (src -> dst with coordinates)
        connection_lines = self._generate_connection_lines(df, ip_locations)
        
        # Count private vs public IPs
        private_count = sum(1 for loc in ip_locations.values() if loc.get('is_private', False))
        public_count = len(ip_locations) - private_count
        
        return {
            "total_unique_ips": len(ip_locations),
            "public_ips": public_count,
            "private_ips": private_count,
            "total_countries": len(country_counter),
            "total_cities": len(city_counter),
            "country_distribution": [
                {"country": country, "unique_ips": count}
                for country, count in country_counter.most_common(20)
            ],
            "city_distribution": [
                {"city": city, "unique_ips": count}
                for city, count in city_counter.most_common(20)
            ],
            "country_traffic": [
                {"country": country, "packets": count}
                for country, count in country_traffic.most_common(20)
            ],
            "src_map_points": src_map_points,
            "dst_map_points": dst_map_points,
            "all_map_points": src_map_points + dst_map_points,
            "connection_lines": connection_lines,
            "ip_details": {ip: loc for ip, loc in list(ip_locations.items())[:100]}  # Limit to 100
        }
    
    def _generate_connection_lines(self, df: pd.DataFrame, ip_locations: Dict) -> List[Dict]:
        
        lines = []
        
        if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            return lines
        
        try:
            # Get unique connection pairs with packet counts
            df_conn = df[['src_ip', 'dst_ip']].copy()
            df_conn['src_ip'] = df_conn['src_ip'].astype(str)
            df_conn['dst_ip'] = df_conn['dst_ip'].astype(str)
            
            # Filter out invalid values
            df_conn = df_conn[df_conn['src_ip'] != 'None']
            df_conn = df_conn[df_conn['dst_ip'] != 'None']
            df_conn = df_conn[df_conn['src_ip'] != 'nan']
            df_conn = df_conn[df_conn['dst_ip'] != 'nan']
            
            if len(df_conn) == 0:
                return lines
            
            connection_pairs = df_conn.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
            connection_pairs = connection_pairs.sort_values('count', ascending=False).head(100)
            
            for _, row in connection_pairs.iterrows():
                src_ip = row['src_ip']
                dst_ip = row['dst_ip']
                
                src_loc = ip_locations.get(src_ip)
                dst_loc = ip_locations.get(dst_ip)
                
                # Only add line if both have valid coordinates
                if (src_loc and dst_loc and 
                    src_loc.get('latitude') is not None and 
                    src_loc.get('longitude') is not None and
                    dst_loc.get('latitude') is not None and 
                    dst_loc.get('longitude') is not None):
                    
                    # Skip if same location (would be a dot, not a line)
                    if (src_loc['latitude'] == dst_loc['latitude'] and 
                        src_loc['longitude'] == dst_loc['longitude']):
                        continue
                    
                    lines.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_lat": src_loc['latitude'],
                        "src_lon": src_loc['longitude'],
                        "src_country": src_loc.get('country', 'Unknown'),
                        "src_city": src_loc.get('city', 'Unknown'),
                        "dst_lat": dst_loc['latitude'],
                        "dst_lon": dst_loc['longitude'],
                        "dst_country": dst_loc.get('country', 'Unknown'),
                        "dst_city": dst_loc.get('city', 'Unknown'),
                        "packet_count": int(row['count'])
                    })
            
            return lines
            
        except Exception as e:
            return []
    
    def _empty_result(self) -> Dict[str, Any]:
        return {
            "total_unique_ips": 0,
            "public_ips": 0,
            "private_ips": 0,
            "total_countries": 0,
            "total_cities": 0,
            "country_distribution": [],
            "city_distribution": [],
            "country_traffic": [],
            "src_map_points": [],
            "dst_map_points": [],
            "all_map_points": [],
            "connection_lines": [],
            "ip_details": {}
        }
    
    def close(self):
        if self.reader:
            self.reader.close()
            self.reader = None


def analyze_geolocation(df: pd.DataFrame, db_path: str = None) -> Dict[str, Any]:

    import sys
    try:
        analyzer = GeoLocationAnalyzer(db_path)
        
        if not analyzer.is_available():
            return {
                "available": False,
                "error": "GeoLite2 database not available. Please download GeoLite2-City.mmdb from MaxMind and place it in backend/data/ folder.",
                "download_url": "https://www.maxmind.com/en/geolite2/signup",
                **analyzer._empty_result()
            }
        
        result = analyzer.analyze_dataframe(df)
        result["available"] = True
        result["error"] = None
        
        analyzer.close()
        return result
        
    except Exception as e:
        return {
            "available": False,
            "error": str(e),
            "total_unique_ips": 0,
            "public_ips": 0,
            "private_ips": 0,
            "total_countries": 0,
            "total_cities": 0,
            "country_distribution": [],
            "city_distribution": [],
            "country_traffic": [],
            "src_map_points": [],
            "dst_map_points": [],
            "all_map_points": [],
            "connection_lines": [],
            "ip_details": {}
        }
