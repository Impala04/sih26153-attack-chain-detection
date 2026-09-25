# Adaptive Behavioural Attack-Chain Detection for Non-IoC Compromise Detection

An AI-powered cybersecurity system developed for **Smart India Hackathon 2026** under the problem statement:

> **Adaptive Behavioural Attack-Chain Detection for Non-IoC Compromise Detection**

## Overview

The system detects potentially compromised hosts without relying solely on traditional Indicators of Compromise (IoCs) such as known IPs, hashes, signatures, or domains.

It analyzes **host behaviour, network-flow characteristics, anomalies, and temporal patterns** to identify suspicious activity, assign dynamic risk scores, and correlate behavioural anomalies into potential attack chains.

## Key Features

* Network-flow preprocessing and normalization
* Host-level behavioural feature extraction
* Time-window based analysis
* Isolation Forest anomaly detection
* Dynamic host risk scoring
* Behavioural indicators such as:

  * Connection volume
  * Port diversity
  * Destination diversity
  * Temporal activity
* Explainable risk factors
* Attack-chain correlation
* SOC-style monitoring dashboard

## Detection Pipeline

```text
Network Traffic
      ↓
Feature Extraction
      ↓
Host-Level Time Windows
      ↓
Anomaly Detection
      ↓
Risk Scoring
      ↓
Attack-Chain Correlation
      ↓
Explainable Detection
      ↓
SOC Dashboard
```

## Technology Stack

* Python
* Pandas
* NumPy
* Scikit-learn
* Isolation Forest
* Next.js
* Machine Learning

## Objective

The goal is to identify **novel and non-IoC-based compromises** by focusing on behavioural deviations rather than relying exclusively on known attack signatures.

The system aims to help SOC analysts identify suspicious hosts, understand why they were flagged, and prioritize potential threats.

## Project Status

Currently under active development for **Smart India Hackathon 2026**.
