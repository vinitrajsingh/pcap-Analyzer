import pandas as pd
import numpy as np
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

# Common port to service name mapping
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt"
}


def calculate_severity(rate: float) -> str:
    if rate < 0.01:
        return "low"
    elif rate < 0.05:
        return "medium"
    elif rate < 0.10:
        return "high"
    else:
        return "critical"


def safe_scalar(value: Any) -> Any:
   
    if value is None:
        return None
    if isinstance(value, pd.Series):
        if len(value) == 0:
            return None
        return value.iloc[0]
    if isinstance(value, np.ndarray):
        if len(value) == 0:
            return None
        return value.item() if value.size == 1 else value[0]
    return value


def is_na_scalar(value: Any) -> bool:
   
    scalar_val = safe_scalar(value)
    if scalar_val is None:
        return True
    try:
        return pd.isna(scalar_val)
    except (ValueError, TypeError):
        return False


def _to_json_serializable(value: Any) -> Any:
    if value is None:
        return None
    
    # Handle pandas NA types
    if isinstance(value, pd._libs.missing.NAType):
        return None
    
    # Check for NaN/NaT - must handle scalar only
    if isinstance(value, float) and np.isnan(value):
        return None
    
    if isinstance(value, (np.integer, np.int64, np.int32)):
        return int(value)
    if isinstance(value, (np.floating, np.float64, np.float32)):
        if np.isnan(value):
            return None
        return float(value)
    if isinstance(value, np.bool_):
        return bool(value)
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return None
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_to_json_serializable(item) for item in value]
    if isinstance(value, dict):
        return {k: _to_json_serializable(v) for k, v in value.items()}
    if isinstance(value, pd.Series):
        return [_to_json_serializable(item) for item in value.tolist()]
    if isinstance(value, np.ndarray):
        return [_to_json_serializable(item) for item in value.tolist()]
    return value


class TrafficAnalyzer:
    
    def __init__(self, df: pd.DataFrame):
        self.df = df.copy() if not df.empty else pd.DataFrame()
    
    def get_summary(self) -> Dict[str, Any]:
        if self.df.empty:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "duration": 0.0,
                "packets_per_sec": 0.0,
                "bytes_per_sec": 0.0
            }
        
        total_packets = len(self.df)
        total_bytes = int(self.df['length'].sum()) if 'length' in self.df.columns else 0
        
        duration = 0.0
        packets_per_sec = 0.0
        bytes_per_sec = 0.0
        
        if 'timestamp' in self.df.columns:
            valid_timestamps = self.df['timestamp'].dropna()
            if len(valid_timestamps) > 0:
                start_time = float(valid_timestamps.min())
                end_time = float(valid_timestamps.max())
                duration = end_time - start_time if end_time > start_time else 0.0
                
                if duration > 0:
                    packets_per_sec = round(total_packets / duration, 2)
                    bytes_per_sec = round(total_bytes / duration, 2)
        
        return _to_json_serializable({
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": round(duration, 2),
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec
        })
    
    def get_protocol_distribution(self) -> Dict[str, Dict[str, Any]]:
        if self.df.empty or 'protocol' not in self.df.columns:
            return {}
        
        # Convert to string and filter
        protocol_series = self.df['protocol'].astype(str)
        protocol_series = protocol_series[protocol_series != 'None']
        protocol_series = protocol_series[protocol_series != 'nan']
        protocol_series = protocol_series[protocol_series != '']
        
        if len(protocol_series) == 0:
            return {}
        
        total = len(protocol_series)
        counts = protocol_series.value_counts()
        
        result = {}
        for protocol, count in counts.items():
            protocol_str = str(protocol).upper()
            percentage = round((int(count) / total) * 100, 2)
            result[protocol_str] = {
                "count": int(count),
                "percentage": percentage
            }
        
        return _to_json_serializable(result)
    
    def get_top_talkers(self, n: int = 10) -> Dict[str, Dict[str, List]]:
        result = {
            "by_packets": {"src": [], "dst": []},
            "by_bytes": {"src": [], "dst": []}
        }
        
        if self.df.empty:
            return result
        
        # Top source IPs by packet count
        if 'src_ip' in self.df.columns:
            try:
                src_series = self.df['src_ip'].astype(str)
                src_series = src_series[src_series != 'None']
                src_series = src_series[src_series != 'nan']
                src_series = src_series[src_series != '']
                
                if len(src_series) > 0:
                    counts = src_series.value_counts().head(n)
                    result["by_packets"]["src"] = [
                        [str(ip), int(cnt)] for ip, cnt in counts.items()
                    ]
            except Exception as e:
                print(f"Error in top_talkers src: {e}", file=sys.stderr)
        
        # Top destination IPs by packet count
        if 'dst_ip' in self.df.columns:
            try:
                dst_series = self.df['dst_ip'].astype(str)
                dst_series = dst_series[dst_series != 'None']
                dst_series = dst_series[dst_series != 'nan']
                dst_series = dst_series[dst_series != '']
                
                if len(dst_series) > 0:
                    counts = dst_series.value_counts().head(n)
                    result["by_packets"]["dst"] = [
                        [str(ip), int(cnt)] for ip, cnt in counts.items()
                    ]
            except Exception as e:
                print(f"Error in top_talkers dst: {e}", file=sys.stderr)
        
        # Top source IPs by bytes
        if 'src_ip' in self.df.columns and 'length' in self.df.columns:
            try:
                df_temp = self.df[['src_ip', 'length']].copy()
                df_temp['src_ip'] = df_temp['src_ip'].astype(str)
                df_temp = df_temp[df_temp['src_ip'] != 'None']
                df_temp = df_temp[df_temp['src_ip'] != 'nan']
                df_temp = df_temp[df_temp['length'].notna()]
                
                if len(df_temp) > 0:
                    bytes_sum = df_temp.groupby('src_ip')['length'].sum()
                    bytes_sum = bytes_sum.sort_values(ascending=False).head(n)
                    result["by_bytes"]["src"] = [
                        [str(ip), int(b)] for ip, b in bytes_sum.items()
                    ]
            except Exception as e:
                print(f"Error in top_talkers src_bytes: {e}", file=sys.stderr)
        
        # Top destination IPs by bytes
        if 'dst_ip' in self.df.columns and 'length' in self.df.columns:
            try:
                df_temp = self.df[['dst_ip', 'length']].copy()
                df_temp['dst_ip'] = df_temp['dst_ip'].astype(str)
                df_temp = df_temp[df_temp['dst_ip'] != 'None']
                df_temp = df_temp[df_temp['dst_ip'] != 'nan']
                df_temp = df_temp[df_temp['length'].notna()]
                
                if len(df_temp) > 0:
                    bytes_sum = df_temp.groupby('dst_ip')['length'].sum()
                    bytes_sum = bytes_sum.sort_values(ascending=False).head(n)
                    result["by_bytes"]["dst"] = [
                        [str(ip), int(b)] for ip, b in bytes_sum.items()
                    ]
            except Exception as e:
                print(f"Error in top_talkers dst_bytes: {e}", file=sys.stderr)
        
        return _to_json_serializable(result)
    
    def get_port_analysis(self, n: int = 10) -> List[Dict[str, Any]]:
        if self.df.empty or 'dst_port' not in self.df.columns:
            return []
        
        try:
            port_series = pd.to_numeric(self.df['dst_port'], errors='coerce')
            port_series = port_series.dropna()
            
            if len(port_series) == 0:
                return []
            
            port_counts = port_series.value_counts().head(n)
            
            result = []
            for port, count in port_counts.items():
                port_int = int(port)
                service = COMMON_PORTS.get(port_int, "Unknown")
                result.append({
                    "port": port_int,
                    "service": service,
                    "count": int(count)
                })
            
            return _to_json_serializable(result)
        except Exception as e:
            print(f"Error in port_analysis: {e}", file=sys.stderr)
            return []
    
    def get_traffic_timeline(self, interval: str = '1S') -> List[Dict[str, Any]]:
        if self.df.empty or 'timestamp' not in self.df.columns:
            return []
        
        try:
            df = self.df.copy()
            
            # Ensure timestamp is numeric
            df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
            df = df[df['timestamp'].notna()]
            
            if len(df) == 0:
                return []
            
            # Convert to datetime
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
            df = df[df['datetime'].notna()]
            
            if len(df) == 0:
                return []
            
            # Group by time interval
            df = df.set_index('datetime')
            
            # Resample and aggregate
            agg_dict = {'timestamp': 'count'}  # Count packets
            if 'length' in df.columns:
                agg_dict['length'] = 'sum'
            
            timeline = df.resample(interval).agg(agg_dict)
            timeline = timeline.rename(columns={'timestamp': 'packets'})
            
            if 'length' not in timeline.columns:
                timeline['length'] = 0
            
            timeline = timeline.fillna(0)
            timeline = timeline.reset_index()
            
            result = []
            for _, row in timeline.iterrows():
                result.append({
                    "time": row['datetime'].strftime("%Y-%m-%d %H:%M:%S"),
                    "packets": int(row['packets']),
                    "bytes": int(row.get('length', 0))
                })
            
            return _to_json_serializable(result)
        except Exception as e:
            print(f"Error in traffic_timeline: {e}", file=sys.stderr)
            return []
    
    def get_connection_pairs(self, n: int = 10) -> List[Dict[str, Any]]:
        
        if self.df.empty:
            return []
        
        if 'src_ip' not in self.df.columns or 'dst_ip' not in self.df.columns:
            return []
        
        try:
            df = self.df[['src_ip', 'dst_ip']].copy()
            df['src_ip'] = df['src_ip'].astype(str)
            df['dst_ip'] = df['dst_ip'].astype(str)
            
            # Filter out invalid values
            df = df[df['src_ip'] != 'None']
            df = df[df['src_ip'] != 'nan']
            df = df[df['dst_ip'] != 'None']
            df = df[df['dst_ip'] != 'nan']
            
            if len(df) == 0:
                return []
            
            # Group and count
            pairs = df.groupby(['src_ip', 'dst_ip']).size()
            pairs = pairs.sort_values(ascending=False).head(n)
            
            result = []
            for (src, dst), count in pairs.items():
                result.append({
                    "src": str(src),
                    "dst": str(dst),
                    "packets": int(count)
                })
            
            return _to_json_serializable(result)
        except Exception as e:
            print(f"Error in connection_pairs: {e}", file=sys.stderr)
            return []
    
    def get_ip_version_distribution(self) -> Dict[str, Dict[str, Any]]:
        #Get IPv4 vs IPv6 distribution.
        default_result = {
            "IPv4": {"count": 0, "percentage": 0.0},
            "IPv6": {"count": 0, "percentage": 0.0}
        }
        
        if self.df.empty or 'ip_version' not in self.df.columns:
            return default_result
        
        try:
            ip_series = pd.to_numeric(self.df['ip_version'], errors='coerce')
            ip_series = ip_series.dropna()
            
            if len(ip_series) == 0:
                return default_result
            
            total = len(ip_series)
            ipv4_count = int((ip_series == 4).sum())
            ipv6_count = int((ip_series == 6).sum())
            
            ipv4_pct = round((ipv4_count / total) * 100, 2) if total > 0 else 0.0
            ipv6_pct = round((ipv6_count / total) * 100, 2) if total > 0 else 0.0
            
            return _to_json_serializable({
                "IPv4": {"count": ipv4_count, "percentage": ipv4_pct},
                "IPv6": {"count": ipv6_count, "percentage": ipv6_pct}
            })
        except Exception as e:
            print(f"Error in ip_version_distribution: {e}", file=sys.stderr)
            return default_result
    
    def analyze_all(self) -> Dict[str, Any]:
        #Run all traffic analysis and return combined results
        result = {}
        
        try:
            result["summary"] = self.get_summary()
        except Exception as e:
            result["summary"] = {"error": str(e)}
        
        try:
            result["protocol_distribution"] = self.get_protocol_distribution()
        except Exception as e:
            result["protocol_distribution"] = {"error": str(e)}
        
        try:
            result["top_talkers"] = self.get_top_talkers()
        except Exception as e:
            result["top_talkers"] = {"error": str(e)}
        
        try:
            result["port_analysis"] = self.get_port_analysis()
        except Exception as e:
            result["port_analysis"] = {"error": str(e)}
        
        try:
            result["traffic_timeline"] = self.get_traffic_timeline()
        except Exception as e:
            result["traffic_timeline"] = {"error": str(e)}
        
        try:
            result["connection_pairs"] = self.get_connection_pairs()
        except Exception as e:
            result["connection_pairs"] = {"error": str(e)}
        
        try:
            result["ip_version_distribution"] = self.get_ip_version_distribution()
        except Exception as e:
            result["ip_version_distribution"] = {"error": str(e)}
        
        return result


class TCPAnalyzer:
    #Analyzer for TCP-specific analysis including failures and health.
    
    def __init__(self, df: pd.DataFrame):
        self.df = df.copy() if not df.empty else pd.DataFrame()
        
        # Filter TCP-related packets
        if not self.df.empty and 'protocol' in self.df.columns:
            tcp_protocols = ['TCP', 'TLS', 'HTTP', 'HTTPS']
            protocol_upper = self.df['protocol'].astype(str).str.upper()
            mask = protocol_upper.isin(tcp_protocols)
            self.tcp_df = self.df[mask].copy()
        else:
            self.tcp_df = pd.DataFrame()
    
    def get_tcp_flags_summary(self) -> Dict[str, int]:
        default_result = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0}
        
        if self.tcp_df.empty or 'tcp_flags' not in self.tcp_df.columns:
            return default_result
        
        try:
            flags_series = self.tcp_df['tcp_flags'].astype(str)
            flags_series = flags_series[flags_series != 'None']
            flags_series = flags_series[flags_series != 'nan']
            
            if len(flags_series) == 0:
                return default_result
            
            result = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0}
            
            for flags_str in flags_series:
                if isinstance(flags_str, str):
                    for flag in flags_str.split(','):
                        flag = flag.strip().upper()
                        if flag in result:
                            result[flag] += 1
            
            return _to_json_serializable(result)
        except Exception as e:
            print(f"Error in tcp_flags_summary: {e}", file=sys.stderr)
            return default_result
    
    def detect_retransmissions(self) -> Dict[str, Any]:
        default_result = {"count": 0, "percentage": 0.0, "packets": []}
        
        if self.tcp_df.empty:
            return default_result
        
        required_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'seq_num']
        if not all(col in self.tcp_df.columns for col in required_cols):
            return default_result
        
        try:
            df = self.tcp_df.copy()
            
            # Convert all columns to string for consistent comparison
            for col in required_cols:
                df[col] = df[col].astype(str)
            
            # Filter out invalid values
            for col in required_cols:
                df = df[df[col] != 'None']
                df = df[df[col] != 'nan']
                df = df[df[col] != '']
            
            if len(df) == 0:
                return default_result
            
            # Group by connection + seq_num
            grouped = df.groupby(['src_ip', 'dst_ip', 'src_port', 'dst_port', 'seq_num']).size()
            
            # Find duplicates
            duplicates = grouped[grouped > 1]
            retransmission_count = int(duplicates.sum() - len(duplicates)) if len(duplicates) > 0 else 0
            
            total = len(df)
            percentage = round((retransmission_count / total) * 100, 2) if total > 0 else 0.0
            
            return _to_json_serializable({
                "count": retransmission_count,
                "percentage": percentage,
                "packets": []
            })
        except Exception as e:
            print(f"Error in detect_retransmissions: {e}", file=sys.stderr)
            return default_result
    
    def detect_connection_resets(self) -> Dict[str, Any]:
        default_result = {"count": 0, "connections": []}
        
        if self.tcp_df.empty or 'tcp_flags' not in self.tcp_df.columns:
            return default_result
        
        try:
            flags_str = self.tcp_df['tcp_flags'].astype(str)
            rst_mask = flags_str.str.contains('RST', case=False, na=False)
            rst_packets = self.tcp_df[rst_mask]
            
            if len(rst_packets) == 0:
                return default_result
            
            connections = []
            for _, packet in rst_packets.iterrows():
                src = safe_scalar(packet.get('src_ip', 'Unknown'))
                dst = safe_scalar(packet.get('dst_ip', 'Unknown'))
                port = safe_scalar(packet.get('dst_port', 0))
                
                try:
                    port_int = int(port) if port is not None and str(port) not in ['None', 'nan', ''] else None
                except (ValueError, TypeError):
                    port_int = None
                
                connections.append({
                    "src": str(src) if src else 'Unknown',
                    "dst": str(dst) if dst else 'Unknown',
                    "port": port_int,
                    "reason": "unknown"
                })
            
            return _to_json_serializable({
                "count": len(rst_packets),
                "connections": connections[:50]  # Limit to 50
            })
        except Exception as e:
            print(f"Error in detect_connection_resets: {e}", file=sys.stderr)
            return default_result
    
    def detect_failed_connections(self) -> Dict[str, Any]:
        default_result = {"count": 0, "connections": []}
        
        if self.tcp_df.empty or 'tcp_flags' not in self.tcp_df.columns:
            return default_result
        
        required_cols = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
        if not all(col in self.tcp_df.columns for col in required_cols):
            return default_result
        
        try:
            df = self.tcp_df.copy()
            flags_str = df['tcp_flags'].astype(str)
            
            # Find SYN-only packets
            syn_mask = flags_str.str.contains('SYN', case=False, na=False)
            ack_mask = flags_str.str.contains('ACK', case=False, na=False)
            syn_only_mask = syn_mask & ~ack_mask
            syn_packets = df[syn_only_mask]
            
            if len(syn_packets) == 0:
                return default_result
            
            # Find all SYN-ACK packets for lookup
            syn_ack_mask = syn_mask & ack_mask
            syn_ack_df = df[syn_ack_mask].copy()
            
            # Convert to strings for matching
            for col in required_cols:
                syn_ack_df[col] = syn_ack_df[col].astype(str)
            
            # Create set of connections that got SYN-ACK
            syn_ack_set = set()
            for _, row in syn_ack_df.iterrows():
                # SYN-ACK comes FROM the server (dst) TO the client (src)
                key = (str(row['dst_ip']), str(row['src_ip']), 
                       str(row['dst_port']), str(row['src_port']))
                syn_ack_set.add(key)
            
            failed_connections = []
            for _, syn_packet in syn_packets.iterrows():
                src = safe_scalar(syn_packet.get('src_ip'))
                dst = safe_scalar(syn_packet.get('dst_ip'))
                src_port = safe_scalar(syn_packet.get('src_port'))
                dst_port = safe_scalar(syn_packet.get('dst_port'))
                
                if any(str(v) in ['None', 'nan', ''] for v in [src, dst, src_port, dst_port]):
                    continue
                
                # Check if SYN-ACK exists for this connection
                key = (str(src), str(dst), str(src_port), str(dst_port))
                if key not in syn_ack_set:
                    try:
                        port_int = int(dst_port)
                    except (ValueError, TypeError):
                        port_int = None
                    
                    failed_connections.append({
                        "src": str(src),
                        "dst": str(dst),
                        "port": port_int
                    })
            
            return _to_json_serializable({
                "count": len(failed_connections),
                "connections": failed_connections[:50]  # Limit to 50
            })
        except Exception as e:
            print(f"Error in detect_failed_connections: {e}", file=sys.stderr)
            return default_result
    
    def detect_connection_terminations(self) -> Dict[str, Any]:
        default_result = {"count": 0, "connections": []}
        
        if self.tcp_df.empty or 'tcp_flags' not in self.tcp_df.columns:
            return default_result
        
        try:
            flags_str = self.tcp_df['tcp_flags'].astype(str)
            fin_mask = flags_str.str.contains('FIN', case=False, na=False)
            fin_packets = self.tcp_df[fin_mask]
            
            if len(fin_packets) == 0:
                return default_result
            
            connections = []
            for _, packet in fin_packets.iterrows():
                src = safe_scalar(packet.get('src_ip', 'Unknown'))
                dst = safe_scalar(packet.get('dst_ip', 'Unknown'))
                port = safe_scalar(packet.get('dst_port', 0))
                
                try:
                    port_int = int(port) if port is not None and str(port) not in ['None', 'nan', ''] else None
                except (ValueError, TypeError):
                    port_int = None
                
                connections.append({
                    "src": str(src) if src else 'Unknown',
                    "dst": str(dst) if dst else 'Unknown',
                    "port": port_int
                })
            
            return _to_json_serializable({
                "count": len(fin_packets),
                "connections": connections[:50]  # Limit to 50
            })
        except Exception as e:
            print(f"Error in detect_connection_terminations: {e}", file=sys.stderr)
            return default_result
    
    def calculate_tcp_health_score(self) -> Dict[str, Any]:
        default_result = {
            "score": 0,
            "grade": "F",
            "factors": {
                "retransmission_rate": 0.0,
                "reset_rate": 0.0,
                "failed_connection_rate": 0.0
            }
        }
        
        if self.tcp_df.empty:
            return default_result
        
        total_tcp = len(self.tcp_df)
        if total_tcp == 0:
            return default_result
        
        try:
            # Get rates
            retransmissions = self.detect_retransmissions()
            resets = self.detect_connection_resets()
            failed = self.detect_failed_connections()
            
            retransmission_rate = float(retransmissions.get('percentage', 0.0)) / 100.0
            reset_rate = float(resets.get('count', 0)) / total_tcp
            failed_rate = float(failed.get('count', 0)) / total_tcp
            
            # Calculate scores
            retransmission_score = max(0, 100 - (retransmission_rate * 1000))
            reset_score = max(0, 100 - (reset_rate * 2000))
            failed_score = max(0, 100 - (failed_rate * 2000))
            
            score = round((retransmission_score * 0.5 + reset_score * 0.25 + failed_score * 0.25), 2)
            score = max(0, min(100, score))
            
            # Assign grade
            if score >= 90:
                grade = "A"
            elif score >= 80:
                grade = "B"
            elif score >= 70:
                grade = "C"
            elif score >= 60:
                grade = "D"
            else:
                grade = "F"
            
            return _to_json_serializable({
                "score": score,
                "grade": grade,
                "factors": {
                    "retransmission_rate": round(retransmission_rate, 4),
                    "reset_rate": round(reset_rate, 4),
                    "failed_connection_rate": round(failed_rate, 4)
                }
            })
        except Exception as e:
            print(f"Error in calculate_tcp_health_score: {e}", file=sys.stderr)
            return default_result
    
    def get_tcp_issues_summary(self) -> Dict[str, Any]:
        default_result = {
            "total_tcp_packets": 0,
            "issues": {
                "retransmissions": {"count": 0, "severity": "low"},
                "resets": {"count": 0, "severity": "low"},
                "failed_connections": {"count": 0, "severity": "low"}
            },
            "health_score": {"score": 0, "grade": "F"}
        }
        
        if self.tcp_df.empty:
            return default_result
        
        total_tcp = len(self.tcp_df)
        
        try:
            retransmissions = self.detect_retransmissions()
            resets = self.detect_connection_resets()
            failed = self.detect_failed_connections()
            health = self.calculate_tcp_health_score()
            
            retransmission_rate = float(retransmissions.get('percentage', 0.0)) / 100.0
            reset_rate = float(resets.get('count', 0)) / total_tcp if total_tcp > 0 else 0.0
            failed_rate = float(failed.get('count', 0)) / total_tcp if total_tcp > 0 else 0.0
            
            return _to_json_serializable({
                "total_tcp_packets": total_tcp,
                "issues": {
                    "retransmissions": {
                        "count": retransmissions.get('count', 0),
                        "severity": calculate_severity(retransmission_rate)
                    },
                    "resets": {
                        "count": resets.get('count', 0),
                        "severity": calculate_severity(reset_rate)
                    },
                    "failed_connections": {
                        "count": failed.get('count', 0),
                        "severity": calculate_severity(failed_rate)
                    }
                },
                "health_score": {
                    "score": health.get('score', 0),
                    "grade": health.get('grade', 'F')
                }
            })
        except Exception as e:
            print(f"Error in get_tcp_issues_summary: {e}", file=sys.stderr)
            return default_result
    
    def analyze_all(self) -> Dict[str, Any]:
        result = {}
        
        try:
            result["flags_summary"] = self.get_tcp_flags_summary()
        except Exception as e:
            result["flags_summary"] = {"error": str(e)}
        
        try:
            result["retransmissions"] = self.detect_retransmissions()
        except Exception as e:
            result["retransmissions"] = {"error": str(e)}
        
        try:
            result["connection_resets"] = self.detect_connection_resets()
        except Exception as e:
            result["connection_resets"] = {"error": str(e)}
        
        try:
            result["failed_connections"] = self.detect_failed_connections()
        except Exception as e:
            result["failed_connections"] = {"error": str(e)}
        
        try:
            result["connection_terminations"] = self.detect_connection_terminations()
        except Exception as e:
            result["connection_terminations"] = {"error": str(e)}
        
        try:
            result["health_score"] = self.calculate_tcp_health_score()
        except Exception as e:
            result["health_score"] = {"error": str(e)}
        
        try:
            result["issues_summary"] = self.get_tcp_issues_summary()
        except Exception as e:
            result["issues_summary"] = {"error": str(e)}
        
        return result


def analyze_pcap(df: pd.DataFrame) -> Dict[str, Any]:

    try:
        traffic_analyzer = TrafficAnalyzer(df)
        tcp_analyzer = TCPAnalyzer(df)
        
        return {
            "traffic": traffic_analyzer.analyze_all(),
            "tcp": tcp_analyzer.analyze_all()
        }
    except Exception as e:
        return {
            "traffic": {},
            "tcp": {},
            "error": str(e)
        }