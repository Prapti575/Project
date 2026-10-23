import pandas as pd

def generate_sample_data():
    """Create deterministic synthetic network flows for safe demonstrations."""
    rows = []
    # Ordinary-looking flows
    for i in range(30):
        rows.append({
            "timestamp": f"2026-10-01 10:{i:02d}:00",
            "src_ip": f"192.168.1.{10 + (i % 8)}",
            "dst_ip": f"10.0.0.{20 + (i % 12)}",
            "dst_port": [53, 80, 443, 123, 8080][i % 5],
            "protocol": ["TCP", "UDP"][i % 2],
            "bytes": 300 + (i * 73) % 5000,
            "packets": 2 + i % 20,
        })
    # Simulated scan-like activity: many destination ports from one source
    for port in range(20, 35):
        rows.append({
            "timestamp": f"2026-10-01 11:{port-20:02d}:00",
            "src_ip": "203.0.113.77",
            "dst_ip": "10.0.0.25",
            "dst_port": port,
            "protocol": "TCP",
            "bytes": 80 + port,
            "packets": 1,
        })
    # Simulated high-volume source and large flow
    for i in range(12):
        rows.append({
            "timestamp": f"2026-10-01 12:{i:02d}:00",
            "src_ip": "198.51.100.42",
            "dst_ip": "10.0.0.50",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 1500000 if i == 0 else 1500,
            "packets": 1500 if i == 0 else 20,
        })
    return pd.DataFrame(rows)
