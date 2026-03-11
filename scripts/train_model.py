"""
Train and export an anomaly detection model to ONNX format for SmallNetworkIDS.

This script trains a Scikit-learn IsolationForest model on network flow data
and exports it to ONNX format for use with the C# IDS application.

Usage:
    python train_model.py training_data.csv

Requirements:
    pip install scikit-learn skl2onnx pandas numpy
"""

import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Feature columns expected by SmallNetworkIDS
FEATURE_COLUMNS = [
    'packets_per_sec',
    'bytes_per_sec', 
    'avg_packet_size',
    'syn_ratio',
    'ack_ratio',
    'fin_rst_ratio',
    'unique_ports_ratio',
    'flow_duration'
]

def load_and_prepare_data(csv_path: str) -> pd.DataFrame:
    """Load CSV and prepare features for training."""
    df = pd.read_csv(csv_path)
    
    # If raw flow data, compute normalized features
    if 'packet_count' in df.columns:
        print("[*] Converting raw flow data to features...")
        df['packets_per_sec'] = df['packets_per_sec'] / 10000.0  # Normalize
        df['bytes_per_sec'] = df['bytes_per_sec'] / 1_000_000_000.0
        df['avg_packet_size'] = (df['byte_count'] / df['packet_count'].clip(lower=1)) / 1500.0
        df['syn_ratio'] = df['syn_count'] / df['packet_count'].clip(lower=1)
        df['ack_ratio'] = df['ack_count'] / df['packet_count'].clip(lower=1)
        df['fin_rst_ratio'] = (df['fin_count'] + df['rst_count']) / df['packet_count'].clip(lower=1)
        df['unique_ports_ratio'] = 0.1  # Placeholder - needs port tracking
        df['flow_duration'] = df['duration_sec'] / 3600.0
    
    # Ensure all features exist
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            print(f"[!] Warning: Missing column {col}, using zeros")
            df[col] = 0.0
    
    return df[FEATURE_COLUMNS]

def train_isolation_forest(X: np.ndarray, contamination: float = 0.1) -> IsolationForest:
    """Train IsolationForest anomaly detector."""
    print(f"[*] Training IsolationForest on {len(X)} samples...")
    
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    
    # Evaluate on training data
    predictions = model.predict(X)
    anomaly_count = (predictions == -1).sum()
    print(f"[*] Detected {anomaly_count} anomalies ({100*anomaly_count/len(X):.1f}%)")
    
    return model

def export_to_onnx(model: IsolationForest, output_path: str):
    """Export trained model to ONNX format."""
    print(f"[*] Exporting model to {output_path}...")
    
    # Define input shape
    initial_type = [('input', FloatTensorType([None, len(FEATURE_COLUMNS)]))]
    
    # Convert to ONNX
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset={'': 12, 'ai.onnx.ml': 3},
        options={id(model): {'score_samples': True}}
    )
    
    # Save
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"[+] Model exported successfully!")
    print(f"    Input: {len(FEATURE_COLUMNS)} features")
    print(f"    Output: anomaly label (-1/1) and scores")

def main():
    if len(sys.argv) < 2:
        print("Usage: python train_model.py <training_data.csv> [output.onnx]")
        print("\nTo generate training data:")
        print("  1. Run SmallNetworkIDS and capture normal traffic")
        print("  2. Export to CSV when prompted")
        print("  3. Run this script on the exported CSV")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'model.onnx'
    
    # Load and prepare data
    X = load_and_prepare_data(csv_path)
    print(f"[*] Loaded {len(X)} samples with {len(FEATURE_COLUMNS)} features")
    
    # Train model
    model = train_isolation_forest(X.values)
    
    # Export to ONNX
    export_to_onnx(model, output_path)
    
    print(f"\n[+] Done! Copy {output_path} to your SmallNetworkIDS folder.")

if __name__ == '__main__':
    main()
