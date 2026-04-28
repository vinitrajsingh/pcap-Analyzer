# PCAP Analyzer

A comprehensive network traffic analysis tool for PCAP files with real-time visualization, anomaly detection, geolocation mapping, and professional PDF report generation.

## Features

- **File Upload**: Upload and analyze PCAP/PCAPNG files
- **Dashboard**: Real-time visualization of network traffic with interactive charts
- **Protocol Analysis**: Detailed breakdown of network protocols (TCP, UDP, DNS, HTTP, etc.)
- **Traffic Timeline**: Time-based traffic visualization
- **Top Talkers**: Identify most active network participants by packets and bytes
- **Geolocation**: Map IP addresses to geographic locations with interactive world map
- **TCP Health Assessment**: Detect and display TCP-related issues (retransmissions, resets, failed connections)
- **Port Analysis**: Analyze destination ports and associated services
- **PDF Reports**: Generate comprehensive professional PDF reports
- **Packet Filtering**: Filter packets by protocol, IP address, and more
- **Pagination**: Efficiently browse through large packet captures

## Prerequisites

Before you begin, ensure you have the following installed:

1. **Python 3.8+**
   - Download from: https://www.python.org/downloads/
   - Verify installation: `python --version`

2. **Node.js 16+ and npm**
   - Download from: https://nodejs.org/
   - Verify installation: `node --version` and `npm --version`

3. **Wireshark** (Required for PCAP parsing)
   - Download from: https://www.wireshark.org/
   - Ensure `tshark` is in your system PATH
   - Verify installation: `tshark -v`

4. **GeoLite2 Database** (Optional, for geolocation features)
   - Sign up for free account: https://www.maxmind.com/en/geolite2/signup
   - Download GeoLite2-City.mmdb
   - Place in `backend/data/` folder

## Project Structure

```
pcap-analyzer/
│
├── backend/
│   ├── app/
│   │   ├── __init__.py          # Flask app initialization
│   │   ├── routes.py            # API endpoints
│   │   ├── parser.py            # PCAP file parsing
│   │   ├── analyzer.py          # Traffic and TCP analysis
│   │   ├── geolocation.py       # IP geolocation mapping
│   │   ├── anomaly_detection.py # Anomaly detection (future)
│   │   └── report_generator.py  # PDF report generation
│   ├── uploads/                 # Uploaded PCAP files (gitignored)
│   ├── outputs/                 # Generated outputs (gitignored)
│   ├── data/                    # GeoLite2 database location
│   ├── requirements.txt         # Python dependencies
│   ├── config.py                # Configuration settings
│   └── run.py                   # Server entry point
│
├── frontend/
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── pages/               # Page components
│   │   ├── services/            # API service functions
│   │   ├── App.jsx              # Main app component
│   │   └── main.jsx             # Entry point
│   ├── package.json             # Node dependencies
│   └── vite.config.js           # Vite configuration
│
└── README.md
```

## Technologies

### Frontend
- **React 19.2.0** - UI framework
- **Vite 7.2.4** - Build tool and dev server
- **Tailwind CSS 4.1.18** - Styling
- **React Router DOM 7.12.0** - Routing
- **React Plotly.js 2.6.0** - Interactive charts and maps
- **Plotly.js 3.3.1** - Charting library

### Backend
- **Flask 3.0.0** - Web framework
- **Flask-CORS 4.0.0** - Cross-origin resource sharing
- **Pyshark 0.6** - PCAP file parsing
- **Pandas 2.1.0** - Data manipulation
- **NumPy 1.26.0** - Numerical computing
- **GeoIP2 4.7.0+** - IP geolocation
- **ReportLab 4.0.0+** - PDF generation
- **Matplotlib 3.7.0+** - Map visualization

