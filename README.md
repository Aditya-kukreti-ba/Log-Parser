# 🔍 Network Traffic Inspector
### A Data Engineering AI Project for Log & Packet Analysis

🌐 **Live Demo:** [https://log-parser-ten.vercel.app/](https://log-parser-ten.vercel.app/)

A beginner-friendly tool for analysing network traffic captured by **Wireshark**, plus a Python pipeline for parsing server log files. Built with **Pandas**, **NumPy**, and **React**.

---

## 📁 Project Structure

```
Log-Parsing/
├── log_parser.py       # Parses text-based log files (Apache, Nginx, Syslog…)
├── analysis.py         # NumPy-powered anomaly detection and traffic statistics
├── pipeline.py         # End-to-end orchestrator with CLI interface
├── requirements.txt    # Python dependencies
└── dashboard.jsx       # React web dashboard for Wireshark PCAP/PCAPNG files
```

---

## ✨ Features

### 🐍 Python Pipeline (`log_parser.py`, `analysis.py`, `pipeline.py`)
- **Multi-format log parsing** — Apache Common, Apache Error, Nginx, Syslog, JSON logs
- **Pandas DataFrames** — structured output with proper types (`Int16`, `Int64`, `datetime`)
- **NumPy statistics** — mean, median, standard deviation, P95, max packet size
- **Anomaly detection** — Z-score outliers, IQR fences, request-rate heuristics
- **Export** — saves results as `.parquet` and `.csv`
- **CLI interface** — run from the terminal with custom flags

### 🌐 React Dashboard (`dashboard.jsx`)
- **Wireshark file upload** — drag-and-drop any `.pcap`, `.pcapng`, or `.cap` file
- **Binary PCAP/PCAPNG parser** — reads directly in the browser; no data sent to any server
- **Packet decoding** — Ethernet → IPv4/IPv6 → TCP/UDP/ICMP with full header extraction
- **Plain-English explanations** — every field explained for non-technical users
- **Slide-out detail drawer** — click any packet row to open a detailed breakdown
- **Animated transitions** — smooth tab switches and directional page slides
- **Suspicious activity detection** — port scans, SYN floods, bad ports, oversized packets
- **Charts** — protocol distribution, top senders, traffic over time, anomaly breakdown

---

## 🚀 Getting Started

### Running the Python Pipeline

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Run on built-in sample data** (no file needed)
```bash
python pipeline.py
```

**3. Run on your own log file**
```bash
python pipeline.py --file access.log --format apache_common --out ./output
```

**Available format options:**

| Flag | Log Format |
|------|-----------|
| `apache_common` | Apache access logs |
| `apache_error` | Apache error logs |
| `nginx` | Nginx access logs |
| `syslog` | Linux system logs |
| `json_log` | JSON structured logs |

**All CLI flags:**
```
--file    Path to your log file
--format  Log format (see table above)
--out     Output folder for CSV/Parquet files (default: ./output)
--z       Z-score threshold for anomaly detection (default: 2.5)
```

---

### Running the React Dashboard

**Option A — Use the live hosted version** (no setup needed)
Visit **[https://log-parser-ten.vercel.app/](https://log-parser-ten.vercel.app/)** — works instantly in any browser.

**Option B — Run locally with Create React App**
```bash
# 1. Create a new React app
npx create-react-app log-parser
cd log-parser

# 2. Install charting library
npm install recharts

# 3. Replace the default App.js with the dashboard
copy "..\Log-Parsing\dashboard.jsx" "src\App.js"   # Windows
cp ../Log-Parsing/dashboard.jsx src/App.js          # Mac/Linux

# 4. Start the app
npm start
```
Opens at **http://localhost:3000**

**Option C — Run locally with Vite** (faster)
```bash
npm create vite@latest log-parser -- --template react
cd log-parser
npm install
npm install recharts
cp ../Log-Parsing/dashboard.jsx src/App.jsx
npm run dev
```
Opens at **http://localhost:5173**

---

## 🖥️ How to Use the Dashboard

1. **Open** http://localhost:3000 in your browser
2. **Drag and drop** a `.pcap` or `.pcapng` file from Wireshark onto the upload area
   - Don't have one? Click **"Load a demo capture"** to try it immediately
3. **Explore the tabs:**

| Tab | What it shows |
|-----|--------------|
| **Summary** | Plain-English overview — total packets, devices, suspicious events, size stats |
| **All Packets** | Full table of every packet · filter by IP, port, or protocol · click any row for details |
| **⚠ Suspicious** | Flagged packets with plain-English explanations of why they look unusual |
| **Charts** | Protocol pie chart, top sender bar chart, traffic-over-time area chart |

4. **Click any packet row** → a panel slides out from the right with a full plain-English breakdown
5. **Use the search box** to filter — try typing an IP address like `192.168`, a protocol like `UDP`, or a port like `443`

---

## 🔬 How Anomaly Detection Works

The tool uses three detection methods inspired by NumPy statistical analysis:

### 📏 Z-Score (Packet Size Outliers)
Calculates the mean and standard deviation of all packet sizes. Any packet more than **3 standard deviations** from the mean is flagged. Large outliers can indicate data exfiltration or malformed packets.

### 📦 IQR Fence
Uses the **Interquartile Range** (Q1 − 1.5×IQR to Q3 + 1.5×IQR) to find extreme values that Z-score alone might miss. Equivalent to NumPy's `nanpercentile`.

### 🚪 Heuristics
Rule-based checks on top of the statistics:
- **Port scan** — one device connecting to more than 15 different ports
- **SYN flood** — more than 10 SYN packets to the same destination without completing the handshake
- **Suspicious ports** — connections to ports commonly used by hacking tools: `4444`, `1337`, `31337`, `6666`, `1080`, etc.
- **Oversized ICMP** — ping packets larger than 512 bytes (potential ping flood)

Each finding is scored **0.0 → 1.0** and assigned a severity level:

| Score | Severity |
|-------|----------|
| ≥ 0.70 | 🔴 Critical |
| ≥ 0.50 | 🟠 High |
| ≥ 0.30 | 🟡 Medium |
| < 0.30 | 🟢 Low |

---

## 📦 Python Module Usage

You can import the modules directly into your own scripts:

```python
from log_parser import LogParser
from analysis import TrafficAnalyzer, AnomalyDetector

# Parse a log file
df = LogParser("nginx").load_file("access.log").parse()

# Run analysis
analyzer = TrafficAnalyzer()
report = analyzer.analyze(df)

# Print full report
analyzer.print_report(report)

# Access specific data
print(report.top_ips)
print(report.bytes_stats)
print(report.anomalies)
```

```python
# Or use the full pipeline in one call
from pipeline import LogPipeline

LogPipeline(log_format="apache_common").run(
    filepath="access.log",
    output_dir="./output"
)
```

---

## 📋 Requirements

### Python
```
pandas >= 2.2.0
numpy  >= 1.26.0
pyarrow >= 15.0.0
```

### JavaScript (React Dashboard)
```
react >= 18
recharts >= 2.0
```

---

## 🗂️ Output Files

After running the Python pipeline, the `./output` folder will contain:

| File | Description |
|------|-------------|
| `parsed_logs.csv` | All parsed log entries as a spreadsheet |
| `parsed_logs.parquet` | Same data in Parquet format (faster, smaller) |

---

## 🔒 Privacy

The React dashboard reads your Wireshark file **entirely in your browser** using the browser's built-in `FileReader` API and binary `DataView`. No packet data is uploaded to any server or sent anywhere over the internet.

---

## 📖 Glossary

| Term | Plain English |
|------|--------------|
| **Packet** | A small chunk of data sent over a network — like an envelope in the mail |
| **IP Address** | A unique address for each device, like a home address |
| **Port** | A numbered door on a device — different apps use different doors (e.g. 443 = secure web) |
| **Protocol** | The language two devices agree to speak — TCP, UDP, ICMP, etc. |
| **TCP** | Reliable connection — like a phone call. Both sides confirm they received data |
| **UDP** | Fast, no confirmation — like sending a text. Good for streaming and DNS |
| **ICMP** | Network diagnostics — used by the `ping` command |
| **ARP** | How devices find each other on a local network |
| **SYN** | The first step of opening a TCP connection |
| **TTL** | "Time to Live" — how many routers a packet can pass through before being discarded |
| **Anomaly** | Something that looks unusual compared to the rest of the traffic |
| **PCAP** | "Packet Capture" — the file format Wireshark uses to save recorded traffic |

---

*Built with Python · Pandas · NumPy · React · Recharts*
