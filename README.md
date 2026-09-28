# CyberFlux

### AI-Powered Network Attacks Forecasting and Behavior-based Attack Chains Detection

**Smart India Hackathon 2026 — PS #26153**

CyberFlux is an AI-based network security solution that analyzes network traffic in order to detect behavioral anomalies and find the progression of possible attacks.

As opposed to using only known IoCs, CyberFlux looks for **behavioral anomalies in the network traffic**.

## Key Features

* Feature extraction from network flows
* 30-second behavioral windows at the host level
* Behavioral anomaly detection
* Threat risk scores
* Explainable detection
* Attack chain correlation
* Temporal attack forecasting
* SOC-oriented visualization

## Detection pipeline

```text
Network Traffic
      ↓
Feature Extraction
      ↓
Behavioral Windows
      ↓
Anomaly Detection
      ↓
Risk Scoring
      ↓
Attack Chain Detection
      ↓
Attack Forecasting
      ↓
SOC Dashboard
```

## Tech stack

**Machine Learning:** Python, Pandas, NumPy, Scikit-learn, Isolation Forest
**Backend:** FastAPI
**Frontend:** Next.js, React, TypeScript, Tailwind CSS, Recharts

## Data

CyberFlux supports network flows and packet-level traffic data including CIC-IDS2017 dataset and will include PCAP data support soon.

## Roadmap

* Live packets monitoring
* PCAP analysis
* MITRE ATT&CK mapping
* Temporal attacks forecasting
* Explainable predictions
* Real-time SOC dashboard
