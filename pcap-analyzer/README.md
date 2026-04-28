# PCAP Analyzer

A full-stack network traffic analysis tool that turns raw Wireshark packet captures into interactive dashboards, anomaly insights, geolocation maps, and downloadable PDF reports. Built with a Flask backend and a React + Vite frontend.

---

## Features

- **Drag-and-drop upload** for `.pcap` and `.pcapng` files (up to 100 MB)
- **Protocol distribution** pie chart (TCP, UDP, DNS, HTTP, ICMP, etc.)
- **Top talkers** ranked by packets and bytes
- **Traffic timeline** showing packets-per-second over the capture duration
- **TCP health score** combining retransmission, reset, and failed-connection rates into a single graded indicator
- **Severity classification** (low / medium / high) for detected anomalies
- **Geolocation world map** plotting public-IP endpoints via the GeoLite2 database
- **Paginated, filterable packet table** with protocol and IP filters
- **One-click PDF report** with charts, tables, and a geographic map
- **Session-based workflow** so the file is parsed once and reused across all views

---

## Prerequisites

Install these before running the project. Verify each one in a terminal as shown.

| Tool | Minimum version | Verify with | Notes |
|------|-----------------|-------------|-------|
| **Python** | 3.8+ | `python --version` | Add to PATH during installation |
| **Node.js + npm** | 16+ | `node --version` and `npm --version` | npm ships with Node |
| **Wireshark / tshark** | Any recent | `tshark -v` | Required — the parser shells out to `tshark` |
| **Git** (optional) | Any | `git --version` | Only needed if cloning |

### Tshark on PATH (Windows)

If `tshark -v` says "command not found", add the Wireshark install folder to your PATH:

1. Default location: `C:\Program Files\Wireshark`
2. Settings → System → About → Advanced system settings → Environment Variables → edit `Path` → New → paste the folder.
3. Open a fresh terminal and re-run `tshark -v`.

### GeoLite2 database (optional, for the map)

The geolocation map needs MaxMind's free GeoLite2 City database. Without it, every other feature still works — only the map will be empty.

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>.
2. Download the **GeoLite2-City.mmdb** binary.
3. Place the file at `backend/data/GeoLite2-City.mmdb`.

---

## Folder structure

```
pcap-analyzer/
├── backend/
│   ├── app/
│   │   ├── __init__.py             # Flask application factory
│   │   ├── routes.py               # /api endpoints (upload, packets, analysis, report)
│   │   ├── parser.py               # tshark subprocess + DataFrame normalisation
│   │   ├── analyzer.py             # TrafficAnalyzer + TCPAnalyzer + health score
│   │   ├── geolocation.py          # GeoIP2 lookups with private-IP filtering
│   │   ├── anomaly_detection.py    # Reserved for future ML hooks
│   │   └── report_generator.py     # ReportLab PDF assembly
│   ├── data/                       # GeoLite2-City.mmdb lives here
│   ├── uploads/                    # Uploaded captures (gitignored)
│   ├── outputs/                    # Generated artefacts (gitignored)
│   ├── config.py                   # HOST, PORT, upload limits, allowed extensions
│   ├── requirements.txt            # Python dependencies
│   └── run.py                      # Backend entry point
│
├── frontend/
│   ├── src/
│   │   ├── components/             # Charts, tables, upload zone, map
│   │   ├── pages/                  # Dashboard, results, report views
│   │   ├── services/               # API client (fetch wrappers)
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json                # Node dependencies and scripts
│   └── vite.config.js              # Dev server + /api proxy to Flask
│
├── .gitignore
└── README.md
```

---

## First-time setup

Open a terminal at the project root (the folder containing `backend/` and `frontend/`).

### 1. Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If activation fails with an execution-policy error, run this once and retry:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

On macOS / Linux:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Frontend

In a **separate** terminal:

```bash
cd frontend
npm install
```

---

## Running the app

You need **two terminals running simultaneously** — one for the backend, one for the frontend.

### Terminal 1 — Flask backend (port 5000)

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python run.py
```

Expected output:

```
 * Running on http://0.0.0.0:5000
```

### Terminal 2 — Vite dev server (port 3000)

```bash
cd frontend
npm run dev
```

Expected output:

```
  VITE vX.X.X  ready in XXX ms
  ➜  Local:   http://localhost:3000/
```

Open **<http://localhost:3000>** in your browser. The Vite dev server proxies `/api/*` requests to the Flask backend, so both servers must be up.

---

## Using the tool

1. Drag a `.pcap` or `.pcapng` file onto the upload zone (or click to browse).
2. Wait for parsing to complete — large captures (50 MB+) may take a minute.
3. Explore the dashboard:
   - Protocol distribution and top talkers
   - TCP health score and severity breakdown
   - Traffic timeline
   - Geolocation map (if GeoLite2 is installed)
   - Paginated packet table with filters
4. Click **Generate PDF Report** to download a formatted summary.

Sessions expire after **one hour of inactivity**; uploading a new file invalidates older sessions automatically.

---

## Configuration

Backend behaviour is controlled by environment variables (all optional):

| Variable | Default | Purpose |
|----------|---------|---------|
| `FLASK_HOST` | `0.0.0.0` | Bind address |
| `FLASK_PORT` | `5000` | Backend port |
| `FLASK_DEBUG` | `False` | Set to `true` for autoreload |

Set them before launching, for example:

```powershell
$env:FLASK_PORT = "5001"; python run.py
```

If you change the port, also update the `proxy.target` in `frontend/vite.config.js` to match.

Other limits live in `backend/config.py`:

- `MAX_CONTENT_LENGTH` — upload size cap (default 100 MB)
- `ALLOWED_EXTENSIONS` — `{'pcap', 'pcapng'}`

---

## REST API reference

All endpoints are prefixed with `/api`. The frontend talks to these directly through the Vite proxy.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET`  | `/api/health` | Liveness check |
| `POST` | `/api/upload` | Upload a PCAP file, returns `session_id` |
| `GET`  | `/api/packets/<session_id>` | Paginated packet rows with optional filters |
| `GET`  | `/api/analysis/<session_id>` | Traffic + TCP analysis summary |
| `GET`  | `/api/geolocation/<session_id>` | Country counts and coordinate pairs |
| `GET`  | `/api/report/<session_id>/status` | Whether the report is ready to download |
| `GET`  | `/api/report/<session_id>` | Streams the PDF as an attachment |

---

## Tech stack

**Backend** — Flask 3.0, Flask-CORS, Pandas, NumPy, GeoIP2, ReportLab, Matplotlib, tshark via `subprocess`.

**Frontend** — React 19, Vite 7, Tailwind CSS 4, React Router 7, Plotly.js + react-plotly.js.

---

## Troubleshooting

**`tshark not found` during upload**
The backend cannot locate the tshark binary. Reinstall Wireshark with the "Add to PATH" option ticked, or add `C:\Program Files\Wireshark` to PATH manually, then restart your terminal.

**`Port 5000 already in use`**
Something else (often AirPlay on macOS or a previous Flask instance) is holding the port. Either kill the other process or set `FLASK_PORT=5001` and update the Vite proxy target.

**`venv\Scripts\activate : The module 'venv' could not be loaded`**
PowerShell needs the explicit script path: use `.\venv\Scripts\Activate.ps1`. If execution policy blocks it, run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once.

**Geolocation map is empty**
Confirm `backend/data/GeoLite2-City.mmdb` exists and is the City variant (not Country). Captures containing only private IP addresses (10.x, 192.168.x, 172.16-31.x) will also produce an empty map by design.

**Frontend shows network errors / CORS warnings**
Make sure both servers are running and you opened `http://localhost:3000`, not the backend URL directly. The proxy only works through the Vite dev server.

**Upload rejected as too large**
Files over 100 MB are blocked. Either trim the capture in Wireshark (File → Export Specified Packets) or raise `MAX_CONTENT_LENGTH` in `backend/config.py`.

**Parsing hangs on large files**
The tshark subprocess has a 5-minute timeout. Captures with millions of packets may exceed this; split them with `editcap -c 100000 input.pcap output.pcap` and analyse the chunks separately.

---

## Stopping the servers

Press `Ctrl+C` in each terminal. To deactivate the Python virtual environment, run `deactivate`.
