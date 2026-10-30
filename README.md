<p align="center">
  <img src="banner.svg" alt="CyberCube banner" width="100%">
</p>

<p align="center">
  <a href="https://ai-powered-cyber-threat-detection-soc.onrender.com/"><b>Live Demo</b></a>
  &nbsp;|&nbsp;
  <a href="#architecture">Architecture</a>
  &nbsp;|&nbsp;
  <a href="#model-benchmark">Benchmark</a>
  &nbsp;|&nbsp;
  <a href="#quick-start">Quick Start</a>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-F7931E?logo=scikitlearn&logoColor=white">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white">
</p>

# CyberCube: AI-Powered Cyber Threat Detection and SOC Platform

CyberCube is a full-stack Security Operations Center (SOC) console. It ingests network flow telemetry from PCAP uploads or a live interface, classifies each flow with a machine learning model, explains the decision with SHAP, maps it to MITRE ATT&CK, and streams alerts to analysts in real time.

> **Note on data.** The training data is synthesized to follow the CIC-IDS2017 flow schema (12,000 records, 22 features). The reported metrics describe model behaviour on this synthetic set and are not a claim about performance on real-world traffic. Validation on the original CIC-IDS2017 capture is listed under [Roadmap](#roadmap).

---

## Features

| Capability | What it does |
|---|---|
| PCAP ingestion | Drag-and-drop `.pcap` upload. A custom parser reads Ethernet, IP and TCP headers with `struct.unpack`, aggregates bidirectional flows, runs inference and stores the result. |
| Live packet capture | `live_sniffer.py` captures from the host interface. Without admin privileges it falls back to generated probes so the demo keeps running. |
| Multi-model benchmark | Random Forest, Histogram Gradient Boosting, MLP and Logistic Regression compared on accuracy, macro-F1, inference latency and training time. |
| Explainable AI | SHAP TreeExplainer waterfall plots in the investigation drawer show which flow features pushed a prediction toward attack or benign. |
| MITRE ATT&CK mapping | Every classified threat carries a technique ID, for example DDoS to T1498, PortScan to T1046, Brute Force to T1110. |
| Real-time streaming | WebSocket endpoint `/ws/threats` pushes new alerts to every connected analyst console, scoped by tenant. |
| PDF incident reports | One-click ReportLab reports with severity, attacker GeoIP, MITRE tags, 22 flow metrics, root-cause text and a signature block. |
| Active containment | Generates Windows `netsh advfirewall` commands and exports `iptables`, Suricata and Snort rules for the attacker IP. |
| Generative explanations | Gemini 1.5 Flash writes plain-English root-cause summaries through a backend proxy, with a rule-based fallback when no key is set. |
| Global threat map | SVG world map plots attacker origins and animates traffic toward the protected cluster. |
| Red Team Injector | Instant 1-click adversary simulation for DDoS (T1498), Brute Force (T1110), Web Exploits (T1190), Port Scans (T1046) and C2 Botnets (T1071). |
| Containment Rollback | Autonomous IPS quarantine with full reversal capabilities (deleting host OS firewall block and updating audit records). |
| Counterfactual Sandbox | Interactive XAI "What-If" simulator evaluating how packet perturbations flip model verdicts towards Benign. |
| Cryptographic Audit Trail | Sequential SHA-256 Merkle hash chain proving tamper-evident forensic log integrity for compliance (SOC 2, ISO 27001). |
| SIEM Webhook Bridge | Real-time formatted incident dispatch to Slack, Discord, and external SIEM collectors. |
| Multi-tenant access | Google OAuth sign-in, per-user tenant keys derived with HMAC, and 12-hour signed session tokens. |

---

## Architecture

<p align="center">
  <img src="architecture.svg" alt="CyberCube system architecture diagram" width="100%">
</p>

The platform has four layers:

1. **Ingestion.** PCAP upload, the live sniffer, the synthetic dataset pipeline and a traffic simulator that replays sampled flows as events.
2. **Intelligence and defense.** Model training and benchmarking, flow inference, SHAP explanations and firewall rule generation.
3. **Serving and visualization.** A FastAPI backend (REST plus WebSockets) feeding a React SOC dashboard, the PDF report engine and the Gemini proxy.
4. **Persistence.** SQLAlchemy ORM over PostgreSQL in production, or SQLite for local demos.

---

## Model Benchmark

Evaluated on 2,400 held-out samples from a stratified 80/20 split of the synthesized dataset.

| Model | Accuracy | Macro-F1 | Inference latency | Status |
|---|---|---|---|---|
| Random Forest | 99.50% | 99.37% | 16.9 µs | Deployed |
| Histogram Gradient Boosting | 99.50% | 99.37% | 30.1 µs | Benchmarked |
| Multi-Layer Perceptron | 99.00% | 98.73% | 2.9 µs | Benchmarked |
| Logistic Regression | 98.38% | 97.90% | 0.7 µs | Baseline |

Random Forest was deployed for its accuracy and for native compatibility with SHAP TreeExplainer. Full per-class reports, confusion matrices and feature importances are in `ml/metrics.json`.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, SQLAlchemy, WebSockets |
| ML and XAI | scikit-learn, SHAP |
| Frontend | React, Vite, Tailwind CSS |
| Database | PostgreSQL (Neon), SQLite fallback |
| AI | Google Gemini 1.5 Flash |
| Reporting | ReportLab |
| CI and hosting | GitHub Actions (traffic simulation), Render (backend), Vercel (frontend) |

---

## Project Structure

```
backend/
  app/
    main.py            REST endpoints, WebSockets, PCAP ingestion
    models.py          Threat ORM model (GeoIP, MITRE ID, JSON features)
    schemas.py         Pydantic request and response schemas
    config.py          Environment loader
    database.py        Engine and session factory
    xai_service.py     SHAP feature attribution
    ai_service.py      Gemini client with fallback
    report_service.py  PDF incident report generator
  scripts/seed.py      Database seeder
data/
  threats_cleaned.csv  12,000 synthesized flow records
  live_sample.pcap     Demo packet capture
frontend/src/
  components/          PcapUploadModal, GlobalThreatMap, ThreatDetailModal
  pages/               Overview, Alerts, Analytics, Models, Settings
ml/
  model.pkl            Serialized Random Forest pipeline
  metrics.json         Benchmark results and class reports
src/
  data_pipeline.py     Flow telemetry generator (22 features)
  train_model.py       Multi-model trainer
  predict.py           Inference and severity assessment
  pcap_analyzer.py     Binary PCAP flow parser
  live_sniffer.py      Live interface sniffer
  simulate_live_traffic.py
```

---

## Quick Start

**Prerequisites:** Python 3.10+ and Node.js 18+.

**1. Configure the environment.** Create `.env` in the project root or in `backend/`:

```env
# Leave as SQLite for local use, or point to PostgreSQL
DATABASE_URL=sqlite:///./threats.db

# Optional: enables live Gemini explanations
GEMINI_API_KEY=your_key_here
```

**2. Build the data and models.**

```bash
python src/data_pipeline.py     # synthesize 12,000 flow records
python src/train_model.py       # benchmark the four classifiers
python backend/scripts/seed.py  # seed incidents, GeoIP and MITRE IDs
```

**3. Run the backend.**

```bash
python -m uvicorn backend.app.main:app --port 8000 --reload
```

Interactive API docs are served at `http://127.0.0.1:8000/docs`.

**4. Run the frontend.**

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

---

## Demo Walkthrough

1. **Analyze a capture.** Open Alerts, choose *Ingest PCAP Capture*, then drop a `.pcap` file or use the one-click demonstration capture. Classified flows appear with MITRE codes.
2. **Investigate a threat.** Open any incident. Use *Calculate SHAP* for the feature waterfall, *PDF Report* for the incident document and *Firewall Rules* for copy-ready `netsh`, `iptables` and Suricata rules.
3. **Compare models.** Open the Models page for the benchmark table.
4. **Stream live traffic.** Run `python src/live_sniffer.py --count 10` and watch alerts arrive through the WebSocket connection.

---

## Testing & Quality Assurance

CyberCube includes an automated end-to-end integration and unit testing suite located in `tests/`:
- `tests/test_pcap_analyzer.py`: Validates binary PCAP header creation, packet unpacking, and bidirectional flow extraction.
- `tests/test_ml_pipeline.py`: Tests Random Forest inference, MITRE ATT&CK technique mapping, and counterfactual perturbation calculations.
- `tests/test_api_endpoints.py`: Tests FastAPI REST routes, tenant key isolation, automated IPS containment, and hash chain audit verification.

Run the test suite with:
```bash
pytest tests/ -v
```

---

## Roadmap

- Evaluate on the original CIC-IDS2017 capture and report results on the official held-out days.
- Add unit tests for the PCAP parser and the inference pipeline.
- Add per-class precision and recall to the Models page.
- Persist containment actions with an audit trail.

---

