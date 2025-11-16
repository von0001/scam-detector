import time
import json
from pathlib import Path

ANALYTICS_FILE = Path("analytics/data.json")

# Make sure the file exists
if not ANALYTICS_FILE.exists():
    ANALYTICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ANALYTICS_FILE.write_text(json.dumps({
        "total_requests": 0,
        "scam_detections": 0,
        "safe_detections": 0,
        "ocr_uses": 0,
        "timestamp_log": []
    }, indent=4))


def load_data():
    return json.loads(ANALYTICS_FILE.read_text())


def save_data(data):
    ANALYTICS_FILE.write_text(json.dumps(data, indent=4))


def record_event(event_type: str):
    data = load_data()

    if event_type == "request":
        data["total_requests"] += 1
    elif event_type == "scam":
        data["scam_detections"] += 1
    elif event_type == "safe":
        data["safe_detections"] += 1
    elif event_type == "ocr":
        data["ocr_uses"] += 1

    data["timestamp_log"].append(int(time.time()))
    save_data(data)


def get_analytics():
    return load_data()