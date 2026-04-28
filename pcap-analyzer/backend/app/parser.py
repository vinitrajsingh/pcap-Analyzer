import pandas as pd
import numpy as np
import subprocess
import json
import shutil
import sys
from typing import Optional, Callable, Dict, List, Any
from datetime import datetime
from pathlib import Path


class PCAPParser:
    # TCP Flag bit positions
    TCP_FLAGS = {
        0x001: 'FIN',
        0x002: 'SYN',
        0x004: 'RST',
        0x008: 'PSH',
        0x010: 'ACK',
        0x020: 'URG',
        0x040: 'ECE',
        0x080: 'CWR',
    }
    
    def __init__(self, filepath: str, debug: bool = False):
        
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        self.packets_data: List[Dict[str, Any]] = []
        self.debug = debug
        self._error_count = 0
        self._max_errors_to_log = 10
        self._first_packet_timestamp = None  # Store first packet's absolute timestamp for relative time conversion
    
    def _log_debug(self, message: str):
        if self.debug:
            print(f"[DEBUG] {message}", file=sys.stderr)
    
    def _log_error(self, message: str):
        self._error_count += 1
        if self._error_count <= self._max_errors_to_log:
            print(f"[WARNING] {message}", file=sys.stderr)
        elif self._error_count == self._max_errors_to_log + 1:
            print(f"[WARNING] Suppressing further error messages...", file=sys.stderr)
    
    def _find_tshark(self) -> str:
        # Try PATH first
        tshark_path = shutil.which('tshark')
        if tshark_path:
            self._log_debug(f"Found tshark in PATH: {tshark_path}")
            return tshark_path
        
        # Try common Windows installation paths
        import os
        common_paths = [
            r'C:\Program Files\Wireshark\tshark.exe',
            r'C:\Program Files (x86)\Wireshark\tshark.exe',
            os.path.expanduser(r'~\AppData\Local\Programs\Wireshark\tshark.exe'),
            '/usr/bin/tshark',
            '/usr/local/bin/tshark',
            '/opt/homebrew/bin/tshark',
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                self._log_debug(f"Found tshark at: {path}")
                return path
        
        # Try running tshark directly
        try:
            result = subprocess.run(
                ['tshark', '-v'],
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                self._log_debug("tshark accessible via direct command")
                return 'tshark'
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        
        raise RuntimeError(
            "tshark is required but not found. "
            "Please install Wireshark from https://www.wireshark.org/"
        )
    
    def _parse_tcp_flags(self, flags_value: Any) -> Optional[str]:
       
        if flags_value is None:
            return None
        
        try:
            # Handle hex string (e.g., "0x0010")
            if isinstance(flags_value, str):
                if flags_value.startswith('0x'):
                    flags_int = int(flags_value, 16)
                else:
                    flags_int = int(flags_value)
            else:
                flags_int = int(flags_value)
            
            # Decode flags
            flag_names = []
            for bit, name in self.TCP_FLAGS.items():
                if flags_int & bit:
                    flag_names.append(name)
            
            return ','.join(flag_names) if flag_names else None
            
        except (ValueError, TypeError):
            return None
    
    def parse(self, progress_callback: Optional[Callable[[int], None]] = None) -> pd.DataFrame:
       
        tshark_path = self._find_tshark()
        self.packets_data = []
        packet_count = 0
        
        try:
            # Use tshark subprocess to extract packet data as JSON
            tshark_cmd = [
                tshark_path,
                '-r', str(self.filepath),
                '-T', 'json',
            ]
            
            self._log_debug(f"Running: {' '.join(tshark_cmd)}")
            
            result = subprocess.run(
                tshark_cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False
            )
            
            if result.returncode != 0:
                error_msg = result.stderr or "Unknown tshark error"
                raise ValueError(f"Failed to parse PCAP file: {error_msg}")
            
            if not result.stdout:
                raise ValueError("PCAP file contains no packets or is empty")
            
            # Parse JSON output
            try:
                tshark_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse tshark JSON output: {str(e)}")
            
            if not tshark_data:
                raise ValueError("PCAP file contains no valid packets")
            
            # DEBUG: Print first packet structure to understand tshark JSON format
            # Always print on first run to help diagnose timestamp issues
            if tshark_data and len(tshark_data) > 0:
                import json as json_module
                print("\n" + "="*80, file=sys.stderr)
                print("FIRST PACKET JSON STRUCTURE (TIMESTAMP DEBUG)", file=sys.stderr)
                print("="*80, file=sys.stderr)
                first_packet = tshark_data[0]
                
                # Print entire structure (not truncated) to see all timestamp fields
                debug_output = json_module.dumps(first_packet, indent=2)
                print(debug_output, file=sys.stderr)
                
                # Also print specific timestamp-related fields we're looking for
                print("\n" + "-"*80, file=sys.stderr)
                print("TIMESTAMP FIELD SEARCH:", file=sys.stderr)
                print("-"*80, file=sys.stderr)
                source = first_packet.get('_source', {})
                layers = source.get('layers', {})
                frame_obj = layers.get('frame', {})
                
                print(f"frame object type: {type(frame_obj)}", file=sys.stderr)
                if isinstance(frame_obj, dict):
                    print(f"frame object keys: {list(frame_obj.keys())[:20]}", file=sys.stderr)
                    for key in frame_obj.keys():
                        if 'time' in key.lower():
                            print(f"  Found time field: {key} = {frame_obj.get(key)}", file=sys.stderr)
                
                # Check flat structure
                for key in layers.keys():
                    if 'time' in key.lower():
                        print(f"  Found time field in layers: {key} = {layers.get(key)}", file=sys.stderr)
                
                print("="*80 + "\n", file=sys.stderr)
            
            self._log_debug(f"Parsing {len(tshark_data)} packets...")
            
            # Extract packet information
            for idx, packet_json in enumerate(tshark_data):
                try:
                    packet_info = self._extract_from_tshark_json(packet_json, packet_index=idx)
                    if packet_info:
                        # Store first packet's absolute timestamp for relative time conversion
                        if self._first_packet_timestamp is None and packet_info.get('timestamp'):
                            self._first_packet_timestamp = packet_info['timestamp']
                        
                        self.packets_data.append(packet_info)
                        packet_count += 1
                        
                        if progress_callback and packet_count % 1000 == 0:
                            progress_callback(packet_count)
                except Exception as e:
                    self._log_error(f"Error extracting packet {idx + 1}: {e}")
                    continue
            
            if len(self.packets_data) == 0:
                raise ValueError("PCAP file contains no valid packets")
            
            self._log_debug(f"Successfully parsed {len(self.packets_data)} packets")
            
            # Convert to DataFrame
            df = pd.DataFrame(self.packets_data)
            
            # Post-process timestamps: if we used relative times, convert them
            if 'timestamp' in df.columns and self._first_packet_timestamp is not None:
                # Check if we have any relative timestamps (values < 1000000000 are likely relative)
                # Absolute timestamps are typically > 1000000000 (year 2001+)
                timestamps = df['timestamp'].dropna()
                if len(timestamps) > 0:
                    min_ts = timestamps.min()
                    # If minimum timestamp is small (< year 2001), likely relative times
                    if min_ts < 1000000000:
                        # Convert relative to absolute using first packet's timestamp
                        # Find the first non-null timestamp
                        first_abs_ts = None
                        for idx, ts in df['timestamp'].items():
                            if pd.notna(ts) and ts >= 1000000000:
                                first_abs_ts = ts
                                break
                        
                        if first_abs_ts:
                            # Convert all relative timestamps
                            df.loc[df['timestamp'] < 1000000000, 'timestamp'] = (
                                first_abs_ts + df.loc[df['timestamp'] < 1000000000, 'timestamp']
                            )
            
            # Convert timestamp to datetime
            if 'timestamp' in df.columns:
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
            
            # Ensure proper data types
            df = self._set_dtypes(df)
            
            return df
            
        except subprocess.TimeoutExpired:
            raise ValueError("PCAP file parsing timed out. File may be too large.")
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")
        except RuntimeError:
            raise
        except Exception as e:
            error_msg = str(e)
            if "tshark" in error_msg.lower() or "wireshark" in error_msg.lower():
                raise RuntimeError(
                    "tshark is required but not found. "
                    "Please install Wireshark from https://www.wireshark.org/"
                )
            raise ValueError(f"Invalid or corrupted PCAP file: {error_msg}")
    
    def _extract_value(self, value: Any) -> Any:
        
        if value is None:
            return None
        
        # Handle list (tshark sometimes wraps values in lists)
        if isinstance(value, list):
            if len(value) > 0:
                # Recursive call to handle nested structures
                return self._extract_value(value[0])
            return None
        
        # Handle dict with nested value
        if isinstance(value, dict):
            # Some fields have 'value' key
            if 'value' in value:
                return value['value']
            # Some fields have the value as first dict value
            if len(value) == 1:
                return list(value.values())[0]
            # Return None for complex dicts (not a simple value wrapper)
            return None
        
        # Return scalar value as-is
        return value
    
    def _get_layer_field(self, layers: Dict, layer_name: str, field_name: str, default=None) -> Any:
        
        # Strategy 1: layer_obj[layer_name.field_name]
        layer_obj = layers.get(layer_name, {})
        if layer_obj:
            full_field = f"{layer_name}.{field_name}"
            value = self._extract_value(layer_obj.get(full_field))
            if value is not None:
                return value
            
            # Strategy 2: layer_obj[field_name]
            value = self._extract_value(layer_obj.get(field_name))
            if value is not None:
                return value
        
        # Strategy 3: layers[layer_name.field_name] (flat structure)
        flat_field = f"{layer_name}.{field_name}"
        value = self._extract_value(layers.get(flat_field))
        if value is not None:
            return value
        
        return default
    
    def _extract_from_tshark_json(self, packet_json: Dict[str, Any], packet_index: int = 0) -> Optional[Dict[str, Any]]:
       
        packet_info: Dict[str, Any] = {
            'timestamp': None,
            'length': None,
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'tcp_flags_raw': None,
            'seq_num': None,
            'ack_num': None,
            'ttl': None,
            'ip_version': None,
        }
        
        try:
            source = packet_json.get('_source', {})
            layers = source.get('layers', {})
            
            # ===== FRAME LAYER (Timestamp, Length, Protocol) =====
            
            # Extract timestamp - try multiple strategies
            # NOTE: tshark may return datetime strings (ISO 8601) instead of epoch numbers
            timestamp = None
            frame_obj = layers.get('frame', {})
            
            def parse_timestamp_value(value):
                if value is None:
                    return None
                
                # Extract value if it's wrapped
                raw_value = self._extract_value(value)
                if raw_value is None:
                    return None
                
                # Try parsing as float (epoch timestamp)
                try:
                    return float(raw_value)
                except (ValueError, TypeError):
                    pass
                
                # Try parsing as ISO 8601 datetime string
                if isinstance(raw_value, str):
                    try:
                        # Parse ISO 8601 format: "2026-01-23T18:16:04.150217000Z"
                        from datetime import datetime as dt
                        # Remove 'Z' and parse
                        dt_str = raw_value.replace('Z', '+00:00')
                        dt_obj = dt.fromisoformat(dt_str)
                        # Convert to Unix timestamp
                        return dt_obj.timestamp()
                    except (ValueError, TypeError, AttributeError):
                        # Try alternative formats
                        try:
                            # Try without timezone
                            dt_obj = dt.fromisoformat(raw_value.replace('Z', ''))
                            return dt_obj.timestamp()
                        except:
                            pass
                
                return None
            
            # Strategy 1: frame.time_epoch (may be ISO string or epoch number)
            if isinstance(frame_obj, dict):
                timestamp = parse_timestamp_value(frame_obj.get('frame.time_epoch'))
                if not timestamp:
                    timestamp = parse_timestamp_value(frame_obj.get('frame_time_epoch'))
            
            # Strategy 2: frame.time or frame.time_utc (ISO datetime strings)
            if not timestamp and isinstance(frame_obj, dict):
                timestamp = parse_timestamp_value(frame_obj.get('frame.time'))
                if not timestamp:
                    timestamp = parse_timestamp_value(frame_obj.get('frame.time_utc'))
            
            # Strategy 3: flat structure
            if not timestamp:
                timestamp = parse_timestamp_value(layers.get('frame.time_epoch'))
                if not timestamp:
                    timestamp = parse_timestamp_value(layers.get('frame.time'))
            
            # Strategy 4: Try all time-related fields in frame object
            if not timestamp and isinstance(frame_obj, dict):
                for key in frame_obj.keys():
                    key_lower = key.lower()
                    if 'time' in key_lower and ('epoch' in key_lower or 'utc' in key_lower or key == 'frame.time'):
                        value = parse_timestamp_value(frame_obj.get(key))
                        if value:
                            timestamp = value
                            break
            
            # Strategy 5: Try frame.time_relative and convert if needed
            if not timestamp and isinstance(frame_obj, dict):
                time_relative = self._extract_value(frame_obj.get('frame.time_relative'))
                if not time_relative:
                    time_relative = self._extract_value(frame_obj.get('frame_time_relative'))
                if not time_relative:
                    time_relative = self._extract_value(frame_obj.get('time_relative'))
                
                if time_relative:
                    try:
                        rel_time = float(time_relative)
                        if self._first_packet_timestamp is not None:
                            timestamp = self._first_packet_timestamp + rel_time
                        else:
                            # Store relative time, will be converted after first packet
                            timestamp = rel_time
                    except (ValueError, TypeError):
                        pass
            
            # Strategy 6: Check all layers for time fields
            if not timestamp:
                for layer_name, layer_data in layers.items():
                    if isinstance(layer_data, dict):
                        for key in layer_data.keys():
                            if 'time' in key.lower() and ('epoch' in key.lower() or 'utc' in key.lower()):
                                value = parse_timestamp_value(layer_data.get(key))
                                if value:
                                    timestamp = value
                                    break
                        if timestamp:
                            break
            
            # Strategy 7: check in _source directly
            if not timestamp:
                source_timestamp = parse_timestamp_value(source.get('timestamp'))
                if source_timestamp:
                    timestamp = source_timestamp
            
            # Strategy 8: Check packet_json root level
            if not timestamp:
                root_timestamp = parse_timestamp_value(packet_json.get('timestamp'))
                if root_timestamp:
                    timestamp = root_timestamp
            
            # Store timestamp
            if timestamp:
                packet_info['timestamp'] = float(timestamp)
            else:
                # Log warning for first few packets if timestamp not found
                if packet_index < 3:
                    self._log_error(f"Could not extract timestamp from packet {packet_index + 1}")
            
            # Extract packet length
            frame_len = self._get_layer_field(layers, 'frame', 'len')
            if frame_len:
                try:
                    packet_info['length'] = int(frame_len)
                except (ValueError, TypeError):
                    pass
            
            # Extract protocol (highest layer)
            frame_protocols = self._get_layer_field(layers, 'frame', 'protocols')
            if frame_protocols:
                protocols = str(frame_protocols).split(':')
                # Get highest layer protocol
                packet_info['protocol'] = protocols[-1].upper() if protocols else 'UNKNOWN'
            
            # ===== IP LAYER (IPv4 or IPv6) =====
            
            # Try IPv4 first
            ip_src = self._get_layer_field(layers, 'ip', 'src')
            ip_dst = self._get_layer_field(layers, 'ip', 'dst')
            
            if ip_src and ip_dst:
                packet_info['src_ip'] = str(ip_src)
                packet_info['dst_ip'] = str(ip_dst)
                packet_info['ip_version'] = 4
                
                # TTL for IPv4
                ip_ttl = self._get_layer_field(layers, 'ip', 'ttl')
                if ip_ttl:
                    try:
                        packet_info['ttl'] = int(ip_ttl)
                    except (ValueError, TypeError):
                        pass
            else:
                # Try IPv6
                ipv6_src = self._get_layer_field(layers, 'ipv6', 'src')
                ipv6_dst = self._get_layer_field(layers, 'ipv6', 'dst')
                
                # Also try alternative field names
                if not ipv6_src:
                    ipv6_src = self._get_layer_field(layers, 'ipv6', 'src_host')
                if not ipv6_dst:
                    ipv6_dst = self._get_layer_field(layers, 'ipv6', 'dst_host')
                
                if ipv6_src and ipv6_dst:
                    packet_info['src_ip'] = str(ipv6_src)
                    packet_info['dst_ip'] = str(ipv6_dst)
                    packet_info['ip_version'] = 6
                    
                    # Hop limit for IPv6 (equivalent to TTL)
                    hop_limit = self._get_layer_field(layers, 'ipv6', 'hlim')
                    if not hop_limit:
                        hop_limit = self._get_layer_field(layers, 'ipv6', 'hop_limit')
                    if not hop_limit:
                        # Try nested structure
                        ipv6_obj = layers.get('ipv6', {})
                        hop_limit = self._extract_value(ipv6_obj.get('ipv6.hlim'))
                    
                    if hop_limit:
                        try:
                            packet_info['ttl'] = int(hop_limit)
                        except (ValueError, TypeError):
                            pass
            
            # ===== TCP LAYER =====
            
            tcp_srcport = self._get_layer_field(layers, 'tcp', 'srcport')
            tcp_dstport = self._get_layer_field(layers, 'tcp', 'dstport')
            
            if tcp_srcport and tcp_dstport:
                try:
                    packet_info['src_port'] = int(tcp_srcport)
                    packet_info['dst_port'] = int(tcp_dstport)
                except (ValueError, TypeError):
                    pass
                
                # TCP Flags - extract and parse to readable format
                tcp_flags_raw = self._get_layer_field(layers, 'tcp', 'flags')
                if tcp_flags_raw:
                    packet_info['tcp_flags_raw'] = tcp_flags_raw
                    packet_info['tcp_flags'] = self._parse_tcp_flags(tcp_flags_raw)
                
                # Sequence number
                tcp_seq = self._get_layer_field(layers, 'tcp', 'seq')
                if not tcp_seq:
                    tcp_seq = self._get_layer_field(layers, 'tcp', 'seq_raw')
                if tcp_seq:
                    try:
                        packet_info['seq_num'] = int(tcp_seq)
                    except (ValueError, TypeError):
                        pass
                
                # Acknowledgment number
                tcp_ack = self._get_layer_field(layers, 'tcp', 'ack')
                if not tcp_ack:
                    tcp_ack = self._get_layer_field(layers, 'tcp', 'ack_raw')
                if tcp_ack:
                    try:
                        packet_info['ack_num'] = int(tcp_ack)
                    except (ValueError, TypeError):
                        pass
            
            # ===== UDP LAYER =====
            
            if not packet_info['src_port']:
                udp_srcport = self._get_layer_field(layers, 'udp', 'srcport')
                udp_dstport = self._get_layer_field(layers, 'udp', 'dstport')
                
                if udp_srcport and udp_dstport:
                    try:
                        packet_info['src_port'] = int(udp_srcport)
                        packet_info['dst_port'] = int(udp_dstport)
                    except (ValueError, TypeError):
                        pass
            
            # ===== QUIC LAYER (uses UDP ports) =====
            
            if not packet_info['src_port'] and 'quic' in layers:
                # QUIC uses UDP, try to get ports from UDP layer again
                udp_srcport = self._get_layer_field(layers, 'udp', 'srcport')
                udp_dstport = self._get_layer_field(layers, 'udp', 'dstport')
                
                if udp_srcport and udp_dstport:
                    try:
                        packet_info['src_port'] = int(udp_srcport)
                        packet_info['dst_port'] = int(udp_dstport)
                    except (ValueError, TypeError):
                        pass
            
            return packet_info
            
        except Exception as e:
            self._log_error(f"Error parsing packet: {e}")
            return None
    
    def _set_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        
        # Integer columns (nullable)
        int_cols = ['length', 'src_port', 'dst_port', 'seq_num', 'ack_num', 'ttl', 'ip_version']
        for col in int_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')
        
        # Float columns
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        
        # String columns
        str_cols = ['protocol', 'src_ip', 'dst_ip', 'tcp_flags']
        for col in str_cols:
            if col in df.columns:
                df[col] = df[col].astype(str).replace('None', None).replace('nan', None)
        
        return df
    
    def get_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        
        if df.empty:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "capture_duration": 0.0,
                "packets_per_second": 0.0,
                "bytes_per_second": 0.0,
                "start_time": None,
                "end_time": None,
                "unique_src_ips": 0,
                "unique_dst_ips": 0,
                "protocols_found": [],
                "protocol_counts": {},
                "top_talkers": {
                    "src_ips": [],
                    "dst_ips": []
                },
                "tcp_flags_summary": {}
            }
        
        # Basic counts
        total_packets = len(df)
        total_bytes = int(df['length'].sum()) if 'length' in df.columns else 0
        
        # Time calculations
        capture_duration = 0.0
        packets_per_second = 0.0
        bytes_per_second = 0.0
        start_datetime = None
        end_datetime = None
        
        if 'timestamp' in df.columns:
            valid_timestamps = df['timestamp'].dropna()
            if len(valid_timestamps) > 0:
                start_time = valid_timestamps.min()
                end_time = valid_timestamps.max()
                capture_duration = float(end_time - start_time) if end_time > start_time else 0.0
                
                if capture_duration > 0:
                    packets_per_second = round(total_packets / capture_duration, 2)
                    bytes_per_second = round(total_bytes / capture_duration, 2)
                
                try:
                    start_datetime = datetime.fromtimestamp(start_time)
                    end_datetime = datetime.fromtimestamp(end_time)
                except (ValueError, OSError):
                    pass
        
        # IP counts
        unique_src_ips = int(df['src_ip'].nunique()) if 'src_ip' in df.columns else 0
        unique_dst_ips = int(df['dst_ip'].nunique()) if 'dst_ip' in df.columns else 0
        
        # Protocol distribution
        protocols_found = []
        if 'protocol' in df.columns:
            protocols_found = df['protocol'].dropna().unique().tolist()
            protocols_found = [p for p in protocols_found if p and p != 'None']
        
        # Protocol counts using value_counts()
        protocol_counts = {}
        if 'protocol' in df.columns:
            protocol_series = df['protocol'].dropna()
            # Filter out None and 'None' values
            protocol_series = protocol_series[protocol_series.astype(str) != 'None']
            if len(protocol_series) > 0:
                counts = protocol_series.value_counts()
                # Convert to dict with JSON-serializable types
                protocol_counts = {
                    str(protocol): int(count) 
                    for protocol, count in counts.items()
                }
        
        # Top talkers: Top 5 source IPs by packet count
        top_src_ips = []
        if 'src_ip' in df.columns:
            src_ip_series = df['src_ip'].dropna()
            # Filter out None and 'None' values
            src_ip_series = src_ip_series[src_ip_series.astype(str) != 'None']
            if len(src_ip_series) > 0:
                src_counts = src_ip_series.value_counts().head(5)
                # Convert to list of [ip, count] pairs, JSON-serializable
                top_src_ips = [
                    [str(ip), int(count)] 
                    for ip, count in src_counts.items()
                ]
        
        # Top talkers: Top 5 destination IPs by packet count
        top_dst_ips = []
        if 'dst_ip' in df.columns:
            dst_ip_series = df['dst_ip'].dropna()
            # Filter out None and 'None' values
            dst_ip_series = dst_ip_series[dst_ip_series.astype(str) != 'None']
            if len(dst_ip_series) > 0:
                dst_counts = dst_ip_series.value_counts().head(5)
                # Convert to list of [ip, count] pairs, JSON-serializable
                top_dst_ips = [
                    [str(ip), int(count)] 
                    for ip, count in dst_counts.items()
                ]
        
        # TCP flags summary
        tcp_flags_summary = {}
        if 'tcp_flags' in df.columns:
            tcp_df = df[df['tcp_flags'].notna() & (df['tcp_flags'] != 'None')]
            if len(tcp_df) > 0:
                # Count individual flags
                all_flags = ','.join(tcp_df['tcp_flags'].dropna().astype(str)).split(',')
                for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']:
                    tcp_flags_summary[flag] = all_flags.count(flag)
        
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "capture_duration": round(capture_duration, 2),
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "start_time": start_datetime.strftime("%Y-%m-%d %H:%M:%S") if start_datetime else None,
            "end_time": end_datetime.strftime("%Y-%m-%d %H:%M:%S") if end_datetime else None,
            "unique_src_ips": unique_src_ips,
            "unique_dst_ips": unique_dst_ips,
            "protocols_found": sorted(protocols_found),
            "protocol_counts": protocol_counts,
            "top_talkers": {
                "src_ips": top_src_ips,
                "dst_ips": top_dst_ips
            },
            "tcp_flags_summary": tcp_flags_summary
        }


def parse_pcap(filepath: str, progress_callback: Optional[Callable[[int], None]] = None) -> pd.DataFrame:
    parser = PCAPParser(filepath)
    return parser.parse(progress_callback=progress_callback)