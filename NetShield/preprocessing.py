import pandas as pd

REQUIRED_COLUMNS = ["src_ip", "dst_ip", "dst_port", "protocol", "bytes", "packets"]

def validate_and_clean(df):
    """Validate required fields and remove rows with unusable core values."""
    issues = []
    if df is None or df.empty:
        return pd.DataFrame(columns=REQUIRED_COLUMNS), ["The uploaded CSV is empty."]
    df = df.copy()
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError("Missing required column(s): " + ", ".join(missing))
    for col in ["src_ip", "dst_ip", "protocol"]:
        df[col] = df[col].astype("string").str.strip()
    for col in ["dst_port", "bytes", "packets"]:
        original_count = len(df)
        df[col] = pd.to_numeric(df[col], errors="coerce")
        bad_count = int(df[col].isna().sum())
        if bad_count:
            issues.append(f"{bad_count} row(s) had invalid or missing values in '{col}'.")
    before = len(df)
    df = df.dropna(subset=REQUIRED_COLUMNS)
    removed = before - len(df)
    if removed:
        issues.append(f"Removed {removed} row(s) with missing/invalid required values.")
    df = df[(df["dst_port"].between(0, 65535)) & (df["bytes"] >= 0) & (df["packets"] >= 0)]
    if len(df) < before - removed:
        issues.append("Removed rows with out-of-range ports or negative byte/packet counts.")
    df["dst_port"] = df["dst_port"].astype(int)
    df["bytes"] = df["bytes"].astype(int)
    df["packets"] = df["packets"].astype(int)
    return df.reset_index(drop=True), issues
