import pandas as pd

def analyze_logs(df):

    alerts = []

    # Rule 1
    failed_logins = df[df["status"] == "failed"]

    for _, row in failed_logins.iterrows():
        alerts.append({
            "type": "Failed Login",
            "ip": row["ip"],
            "user": row["user"],
            "severity": "Low"
        })

    # Rule 2
    brute_force = df[df["status"] == "failed"].groupby("ip").size()

    for ip, count in brute_force.items():
        if count >= 3:
            alerts.append({
                "type": "Brute Force Attack",
                "ip": ip,
                "user": "Multiple",
                "severity": "High"
            })

    return alerts