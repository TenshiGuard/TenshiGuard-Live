# app/routes/api_dashboard.py
# ============================================================
#  TenshiGuard Admin Dashboard API
#  - /api/dashboard/summary
#  - /api/dashboard/failed-logins-trend
#  - /api/dashboard/top-devices
# ============================================================

from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy import func
from app.extensions import db
from app.models import Device, Event, Alert, AISignal

# This name MUST match the one used in app/__init__.py optional_routes
api_dash = Blueprint("api_dash", __name__)

# ------------------------------------------------------------
# Helper: resolve organization_id safely
# ------------------------------------------------------------
def _get_org_id():
    try:
        if not current_user.is_authenticated:
            return None
        return getattr(current_user, "organization_id", None)
    except Exception:
        return None

def _utc_now():
    return datetime.now(timezone.utc)

# ------------------------------------------------------------
# GET /api/dashboard/summary
# ------------------------------------------------------------
@api_dash.route("/dashboard/summary", methods=["GET"])
@login_required
def dashboard_summary():
    org_id = _get_org_id()
    if not org_id:
        return jsonify({"status": "error", "message": "No organization context"}), 400

    now = _utc_now()
    window_24h = now - timedelta(hours=24)

    # 1. Devices
    total_devices = db.session.query(func.count(Device.id)).filter_by(organization_id=org_id).scalar() or 0
    online_devices = db.session.query(func.count(Device.id)).filter_by(organization_id=org_id, status="online").scalar() or 0
    offline_devices = max(total_devices - online_devices, 0)

    # 2. Events (Alerts)
    events_24h = db.session.query(func.count(Event.id)).filter(
        Event.organization_id == org_id,
        Event.ts >= window_24h
    ).scalar() or 0

    failed_logins_24h = db.session.query(func.count(Event.id)).filter(
        Event.organization_id == org_id,
        Event.category == "auth",
        Event.ts >= window_24h
    ).scalar() or 0

    # Severity Breakdown
    severities = ["critical", "high", "medium", "low", "info"]
    by_severity = {}
    for sev in severities:
        count = db.session.query(func.count(Event.id)).filter(
            Event.organization_id == org_id,
            Event.severity == sev,
            Event.ts >= window_24h
        ).scalar() or 0
        by_severity[sev] = count

    # --------------------------------------------------------
    # 🧪 MOCK DATA INJECTION REMOVED
    # --------------------------------------------------------

    return jsonify({
        "status": "ok",
        "devices": {
            "total": total_devices,
            "online": online_devices,
            "offline": offline_devices
        },
        "events": {
            "last_24h": events_24h,
            "failed_logins_24h": failed_logins_24h,
            "by_severity": by_severity
        }
    })

# ------------------------------------------------------------
# GET /api/dashboard/failed-logins-trend
# ------------------------------------------------------------
@api_dash.route("/dashboard/failed-logins-trend", methods=["GET"])
@login_required
def failed_logins_trend():
    org_id = _get_org_id()
    if not org_id:
        return jsonify({"status": "error", "message": "No organization context"}), 400

    now = _utc_now()
    window_24h = now - timedelta(hours=24)

    # Query Events (not AISignal) for auth failures
    rows = (
        db.session.query(
            func.strftime("%H:00", Event.ts).label("bucket"),
            func.count(Event.id).label("count"),
        )
        .filter(
            Event.organization_id == org_id,
            Event.category == "auth",
            Event.ts >= window_24h,
        )
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )

    points = [{"bucket": r.bucket, "count": r.count} for r in rows]

    # --------------------------------------------------------
    # 🧪 MOCK DATA INJECTION REMOVED
    # --------------------------------------------------------

    return jsonify({
        "status": "ok",
        "points": points
    })

# ------------------------------------------------------------
# GET /api/dashboard/top-devices
# ------------------------------------------------------------
@api_dash.route("/dashboard/top-devices", methods=["GET"])
@login_required
def top_devices():
    org_id = _get_org_id()
    if not org_id:
        return jsonify({"status": "error", "message": "No organization context"}), 400

    devices = Device.query.filter_by(organization_id=org_id).limit(10).all()
    
    items = []
    for d in devices:
        # Count events for this device
        evt_count = Event.query.filter_by(device_id=d.id).count()
        items.append({
            "device_name": d.device_name,
            "mac": d.mac,
            "os": d.os,
            "status": d.status,
            "events": evt_count
        })

    # --------------------------------------------------------
    # 🧪 MOCK DATA INJECTION REMOVED
    # --------------------------------------------------------

    return jsonify({
        "status": "ok",
        "items": items
    })

# ------------------------------------------------------------
# GET /api/dashboard/history
# ------------------------------------------------------------
@api_dash.route("/dashboard/history", methods=["GET"])
@login_required
def dashboard_history():
    org_id = _get_org_id()
    if not org_id:
        return jsonify({"status": "error", "message": "No organization context"}), 400

    alerts = Event.query.filter_by(organization_id=org_id).order_by(Event.ts.desc()).limit(10).all()
    
    items = []
    for a in alerts:
        items.append({
            "ts": a.ts.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": a.severity,
            "category": a.category,
            "detail": a.message or a.detail
        })

    # --------------------------------------------------------
    # 🧪 MOCK DATA INJECTION REMOVED
    # --------------------------------------------------------

    return jsonify({
        "status": "ok",
        "items": items
    })
