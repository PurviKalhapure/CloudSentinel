
from datetime import datetime, timezone
from uuid import uuid4
import boto3
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="CloudSentinel SOC API",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve local Swagger UI files
app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)

security_events = []
dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-2")
events_table = dynamodb.Table("CloudSentinelEvents")


class SecurityEvent(BaseModel):
    event_type: str
    source_ip: str
    severity: str = "low"
    description: str = "Security event detected"
    timestamp: Optional[str] = None


@app.get("/docs", include_in_schema=False)
def custom_swagger_docs():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="CloudSentinel SOC API - Swagger UI",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )


@app.get("/")
def home():
    return {
        "message": "CloudSentinel SOC API is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/events")
def create_security_event(event: SecurityEvent):
    record = event.model_dump()
    record["event_id"] = str(uuid4())
    record["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Detect repeated failed logins from the same IP
    if record["event_type"] == "failed_login":
        ip = record["source_ip"]

        previous_attempts = sum(
            1
            for existing_event in security_events
            if existing_event["event_type"] == "failed_login"
            and existing_event["source_ip"] == ip
        )

        total_attempts = previous_attempts + 1

        if total_attempts >= 2:
            record["severity"] = "high"
            record["description"] = (
                "Repeated failed login attempts detected"
            )

    security_events.append(record)
    events_table.put_item(Item=record)

    return {
        "message": "Security event logged successfully",
        "event": record,
    }


@app.get("/events")
def get_security_events():
    return {
        "total": len(security_events),
        "events": security_events,
    }


@app.get("/analytics")
def get_analytics():
    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    event_type_counts = {}

    for event in security_events:
        severity = event.get("severity", "low").lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

        event_type = event.get("event_type", "unknown")
        event_type_counts[event_type] = (
            event_type_counts.get(event_type, 0) + 1
        )

    return {
        "total_events": len(security_events),
        "severity_counts": severity_counts,
        "event_type_counts": event_type_counts,
    }


@app.get("/alerts")
def get_security_alerts():
    alerts = [
        event
        for event in security_events
        if event.get("severity", "").lower() == "high"
    ]

    return {
        "total_alerts": len(alerts),
        "alerts": alerts,
    }

