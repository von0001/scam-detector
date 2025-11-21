import json
import time
from pathlib import Path

FEEDBACK_FILE = Path("analytics/feedback.json")

if not FEEDBACK_FILE.exists():
    FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    FEEDBACK_FILE.write_text("[]")


def load_feedback():
    return json.loads(FEEDBACK_FILE.read_text())


def save_feedback(data):
    FEEDBACK_FILE.write_text(json.dumps(data, indent=4))


def add_feedback(message: str, page: str, ip: str, user_agent: str):
    data = load_feedback()
    data.append({
        "timestamp": int(time.time()),
        "message": message,
        "page": page,
        "ip": ip,
        "user_agent": user_agent
    })
    save_feedback(data)