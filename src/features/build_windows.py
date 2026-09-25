"""
build_windows.py — Rebuild windowed host features from raw labelled CIC-IDS2017
flow CSVs, fixing the dilution problem in the original 5-minute/host windowing
(where attack_flow_ratio averaged out to ~0.001 and the model couldn't
separate attack from benign traffic).

Key fixes vs. the original pipeline:
  1. Much shorter windows (default 30s) per (Source IP, Destination IP) pair,
     not 5 minutes per Source IP alone — attacks are bursty and get diluted
     when averaged with a host's other, unrelated normal traffic.
  2. Window label = "attack" if ANY flow in the window is non-BENIGN, not an
     average ratio across the window.
  3. Adds burst-aware features (max, std, bytes_per_connection,
     flows_per_second) alongside the original mean/sum features, since
     attacks often show up as outliers/bursts rather than shifted averages.

Usage:
    python src/features/build_windows.py --input_dir ../sih26153-attack-chain-detection/data/labelled_flows --out ../sih26153-attack-chain-detection/data/host_features_v2.csv
    python src/features/build_windows.py --window_seconds 30
"""

import argparse
import glob
import os

import numpy as np
import pandas as pd

WINDOW_SECONDS_DEFAULT = 30

# Raw CICFlowMeter columns have inconsistent leading spaces across files.
# Strip them immediately on load so all downstream code can use clean names.
def load_and_clean(path: str) -> pd.DataFrame:
    # Some CIC-IDS2017 files (e.g. the WebAttacks file) contain non-UTF-8
    # bytes. Try utf-8 first, fall back to latin-1 (which accepts any byte
    # value) rather than crashing the whole pipeline on one file.
    try:
        df = pd.read_csv(path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        print(f"  (utf-8 decode failed for {os.path.basename(path)}, retrying with latin-1)")
        df = pd.read_csv(path, low_memory=False, encoding="latin-1")
    df.columns = [c.strip() for c in df.columns]
    return df


def build_windows_for_file(path: str, window_seconds: int) -> pd.DataFrame:
    df = load_and_clean(path)
    source_file = os.path.basename(path)

    # Some CIC-IDS2017 CSVs have header rows repeated mid-file (Timestamp ==
    # "Timestamp") or garbage rows — drop anything that fails to parse.
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce", dayfirst=True)
    df = df.dropna(subset=["Timestamp", "Source IP", "Destination IP"])

    # Numeric coercion — some columns can contain "Infinity"/"NaN" strings
    numeric_cols = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Destination Port",
    ]
    for c in numeric_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=numeric_cols)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=numeric_cols)

    df["is_attack_flow"] = (df["Label"].str.strip().str.upper() != "BENIGN").astype(int)
    df["bytes_total"] = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
    df["packets_total"] = df["Total Fwd Packets"] + df["Total Backward Packets"]

    # Bucket into fixed-size time windows
    df["window_start"] = df["Timestamp"].dt.floor(f"{window_seconds}s")

    grouped = df.groupby(["Source IP", "Destination IP", "window_start"])

    windows = grouped.agg(
        connection_count=("Flow Duration", "count"),
        unique_ports=("Destination Port", "nunique"),
        total_fwd_packets=("Total Fwd Packets", "sum"),
        total_bwd_packets=("Total Backward Packets", "sum"),
        total_bytes_fwd=("Total Length of Fwd Packets", "sum"),
        total_bytes_bwd=("Total Length of Bwd Packets", "sum"),
        avg_flow_duration=("Flow Duration", "mean"),
        max_flow_duration=("Flow Duration", "max"),
        std_flow_duration=("Flow Duration", "std"),
        max_bytes_total=("bytes_total", "max"),
        std_bytes_total=("bytes_total", "std"),
        max_packets_total=("packets_total", "max"),
        attack_flow_count=("is_attack_flow", "sum"),
        n_flows=("is_attack_flow", "count"),
    ).reset_index()

    # unique_destinations: per (Source IP, window_start), how many distinct
    # Destination IPs — needs a second groupby since the first was keyed by
    # (src, dst, window) already
    dest_counts = (
        df.groupby(["Source IP", "window_start"])["Destination IP"]
        .nunique()
        .reset_index()
        .rename(columns={"Destination IP": "unique_destinations"})
    )
    windows = windows.merge(dest_counts, on=["Source IP", "window_start"], how="left")

    windows["std_flow_duration"] = windows["std_flow_duration"].fillna(0)
    windows["std_bytes_total"] = windows["std_bytes_total"].fillna(0)

    windows["bytes_per_connection"] = windows["total_bytes_fwd"] / windows["connection_count"].replace(0, np.nan)
    windows["bytes_per_connection"] = windows["bytes_per_connection"].fillna(0)
    windows["flows_per_second"] = windows["connection_count"] / window_seconds

    # KEY FIX: label a window as attack if ANY flow in it is non-benign,
    # not an averaged ratio across a large window.
    windows["attack_flow_ratio"] = windows["attack_flow_count"] / windows["n_flows"]
    windows["is_attack_window"] = (windows["attack_flow_count"] > 0).astype(int)

    windows["source_file"] = source_file
    windows = windows.rename(columns={"Source IP": "src_ip", "Destination IP": "dst_ip"})

    return windows


def main(input_dir: str, out_path: str, window_seconds: int):
    files = sorted(glob.glob(os.path.join(input_dir, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {input_dir}")

    all_windows = []
    for path in files:
        print(f"Processing {os.path.basename(path)} ...")
        w = build_windows_for_file(path, window_seconds)
        print(f"  -> {len(w)} windows, {w['is_attack_window'].sum()} flagged attack-containing")
        all_windows.append(w)

    result = pd.concat(all_windows, ignore_index=True)
    result = result.drop(columns=["attack_flow_count", "n_flows"])

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    result.to_csv(out_path, index=False)
    print(f"\nSaved {len(result)} total windows to {out_path}")
    print(f"Overall attack-window rate: {result['is_attack_window'].mean():.4f}")
    print("\nPer-file attack window rate:")
    print(result.groupby("source_file")["is_attack_window"].mean())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rebuild windowed features with burst-aware, non-diluted labeling")
    parser.add_argument("--input_dir", default="../sih26153-attack-chain-detection/data/labelled_flows")
    parser.add_argument("--out", default="../sih26153-attack-chain-detection/data/host_features_v2.csv")
    parser.add_argument("--window_seconds", type=int, default=WINDOW_SECONDS_DEFAULT)
    args = parser.parse_args()

    main(args.input_dir, args.out, args.window_seconds)