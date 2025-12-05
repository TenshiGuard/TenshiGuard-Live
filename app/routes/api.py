# ============================================================
# 🌐 TenshiGuard Agent API v1.0
#  Register / Heartbeat / AI Hybrid Analysis + Persistence
# ============================================================

from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Blueprint, jsonify, request, current_app

from app.extensions import db
from app.models import (
    Organization,
    Device,
    Event,

    # AI models aligned with DB
    AIFileScan,
    AIProcessEvent,
    AINetworkEvent,
    AIEvent,
    AIRiskScore,
    DeviceTelemetry,
)

# ============================================================
# 🔹 Blueprint
# ============================================================

api_bp = Blueprint("api_bp", __name__, url_prefix="/api/agent")


# ============================================================
# 🔹 Utility Helpers
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def json_error(msg: str, status: int = 400):
    return jsonify({"status": "error", "message": msg}), status


def to_float(val: Any, default: float = 0.0):
    try:
        return float(val)
    except Exception:
        return default


def get_org_from_token(token: str):
    if not token:
        return None
    return Organization.query.filter_by(agent_token=token).first()


def get_ai_engine():
    app = current_app
    return getattr(app, "ai_engine", None)


# ============================================================
# 🟢 REGISTER AGENT
# ============================================================

@api_bp.post("/register")
def register_agent():

    data = request.get_json(silent=True) or {}
    token = (data.get("org_token") or "").strip()
    hostname = (data.get("hostname") or "").strip()
    mac = (data.get("mac") or "").strip().lower()
    os_name = (data.get("os") or "unknown").strip()
    ip_addr = (data.get("ip") or "").strip() or None
    version = (data.get("agent_version") or "0.1-sim").strip()

    if not token:
        return json_error("Missing org_token")
    if not hostname:
        return json_error("Missing hostname")
    if not mac:
        return json_error("Missing MAC")

    org = get_org_from_token(token)
    if not org:
        return json_error("Invalid organization token", 404)

    # Lookup by MAC only (globally unique) to prevent IntegrityError
    device = Device.query.filter_by(mac=mac).first()

    cpu = to_float(data.get("cpu_percent"), 0.0)
    mem = to_float(data.get("mem_percent"), 0.0)

    if device:
        # SECURITY FIX: Prevent device takeover from another organization
        if device.organization_id != org.id:
            return json_error("Device MAC already registered to another organization. Deregister it first.", 403)

        # Update metadata for same-org device
        device.device_name = hostname
        device.os = os_name
        device.ip = ip_addr
        device.cpu_percent = cpu
        device.mem_percent = mem
        device.agent_version = version
        device.status = "online"
        device.last_seen = utc_now()

        evt = Event(
            organization_id=org.id,
            mac=mac,
            category="agent",
            action="reconnected",
            severity="info",
            detail=f"Agent reconnected from {hostname}",
            event_type="agent",
            ts=utc_now()
        )
        db.session.add(evt)
        db.session.commit()

        return jsonify({
            "status": "ok",
            "message": "Device reconnected",
            "device_id": device.id
        })

    # create new device
    device = Device(
        organization_id=org.id,
        device_name=hostname,
        os=os_name,
        ip=ip_addr,
        mac=mac,
        status="online",
        last_seen=utc_now(),
        cpu_percent=cpu,
        mem_percent=mem,
        agent_version=version
    )
    db.session.add(device)

    evt = Event(
        organization_id=org.id,
        mac=mac,
        category="agent",
        action="registered",
        severity="info",
        detail=f"Agent registered from {hostname}",
        event_type="agent",
        ts=utc_now()
    )
    db.session.add(evt)
    db.session.commit()

    return jsonify({
        "status": "ok",
        "message": "Agent registered",
        "device_id": device.id
    }), 201


# ============================================================
# 💓 HEARTBEAT + HYBRID AI PIPELINE (Option C)
# ============================================================

@api_bp.post("/heartbeat")
def heartbeat():

    data = request.get_json(silent=True) or {}

    token = (data.get("org_token") or "").strip()
    mac = (data.get("mac") or "").strip().lower()

    if not token:
        return json_error("Missing org_token")
    if not mac:
        return json_error("Missing MAC")

    org = get_org_from_token(token)
    if not org:
        return json_error("Invalid organization token", 404)

    # Lookup by MAC only (globally unique)
    device = Device.query.filter_by(mac=mac).first()
    if not device:
        return json_error("Device not registered. Call /register first.", 404)

    # SECURITY FIX: Prevent device takeover
    if device.organization_id != org.id:
        return json_error("Device MAC registered to another organization.", 403)

    # -------------------------
    # Update device
    # -------------------------
    device.device_name = (data.get("hostname") or device.device_name).strip()
    device.os = (data.get("os") or device.os).strip()
    device.ip = (data.get("ip") or device.ip).strip()
    device.agent_version = (data.get("agent_version") or device.agent_version).strip()
    device.cpu_percent = to_float(data.get("cpu_percent"), device.cpu_percent or 0.0)
    device.mem_percent = to_float(data.get("mem_percent"), device.mem_percent or 0.0)
    device.status = (data.get("status") or "online").strip()
    device.last_seen = utc_now()

    # ---------------------------------------
    # PERSIST TELEMETRY (History)
    # ---------------------------------------
    telemetry = DeviceTelemetry(
        device_id=device.id,
        cpu_percent=device.cpu_percent,
        mem_percent=device.mem_percent,
        agent_version=device.agent_version,
        ts=utc_now()
    )
    db.session.add(telemetry)

    engine = get_ai_engine()

    ai_results = {
        "files": [],
        "processes": [],
        "network": [],
        "events": [],
    }

    if engine:
        for f in data.get("files", []) or []:
            ai_results["files"].append(engine.analyze_file(f))

        for p in data.get("processes", []) or []:
            ai_results["processes"].append(engine.analyze_process(p))

        for n in data.get("network", []) or []:
            ai_results["network"].append(engine.analyze_network(n))

        for ev in data.get("events", []) or []:
            ai_results["events"].append(engine.analyze_event(ev))

    # ---------------------------------------
    # PERSIST SUSPICIOUS FINDINGS TO DB
    # ---------------------------------------
    def _persist_file(res):
        """Save malicious file detections."""
        return AIFileScan(
            organization_id=org.id,
            device_id=device.id,
            file_hash=res["raw"].get("hash") or res["raw"].get("file_hash"),
            file_path=res["raw"].get("path"),
            severity=res["findings"][0].get("severity"),
            rule_id=res["findings"][0].get("rule_id"),
            rule_name=res["findings"][0].get("meta", {}).get("name"),
            score=res.get("score", 0),
            findings_json=res.get("findings", [])
        )

    def _persist_process(res):
        return AIProcessEvent(
            organization_id=org.id,
            device_id=device.id,
            process_name=res["raw"].get("name") or res["raw"].get("process_name"),
            command_line=res["raw"].get("cmdline") or res["raw"].get("command_line"),
            severity=res["findings"][0].get("severity"),
            rule_id=res["findings"][0].get("rule_id"),
            score=res.get("score", 0),
            findings_json=res.get("findings", []),
        )

    def _persist_network(res):
        return AINetworkEvent(
            organization_id=org.id,
            device_id=device.id,
            dest_ip=res["raw"].get("dest_ip"),
            dest_port=res["raw"].get("dest_port"),
            severity=res["findings"][0].get("severity"),
            rule_id=res["findings"][0].get("rule_id"),
            score=res.get("score", 0),
            findings_json=res.get("findings", []),
        )

    def _persist_event(res):
        return AIEvent(
            organization_id=org.id,
            device_id=device.id,
            event_type=res["entity_type"],
            severity=res["findings"][0].get("severity"),
            score=res.get("score", 0),
            findings_json=res.get("findings", []),
            raw_json=res.get("raw", {}),
        )

    # ---------------------------------------
    # Save only suspicious results
    # ---------------------------------------
    suspicious_count = 0

    for res in ai_results["files"]:
        if res["is_suspicious"]:
            db.session.add(_persist_file(res))
            suspicious_count += 1

    for res in ai_results["processes"]:
        if res["is_suspicious"]:
            db.session.add(_persist_process(res))
            suspicious_count += 1

    for res in ai_results["network"]:
        if res["is_suspicious"]:
            db.session.add(_persist_network(res))
            suspicious_count += 1

    for res in ai_results["events"]:
        if res["is_suspicious"]:
            db.session.add(_persist_event(res))
            suspicious_count += 1

    # ---------------------------------------
    # Update risk score
    # ---------------------------------------
    if suspicious_count > 0:
        risk = AIRiskScore(
            organization_id=org.id,
            device_id=device.id,
            score=min(suspicious_count * 25, 100),
            highest_severity="high",
            summary_json={"suspicious": suspicious_count},
        )
        db.session.add(risk)

    db.session.commit()

    return jsonify({
        "status": "ok",
        "message": "Heartbeat received",
        "device_id": device.id,
        "device_status": device.status,
        "ai_summary": {
            "suspicious_saved": suspicious_count,
            "files": len(ai_results["files"]),
            "processes": len(ai_results["processes"]),
            "network": len(ai_results["network"]),
            "events": len(ai_results["events"]),
        }
    }), 200


# ============================================================
# 🔧 DEBUG PING
# ============================================================

@api_bp.get("/ping")
def ping():
    return jsonify({
        "status": "ok",
        "message": "TenshiGuard agent API is alive",
        "time": utc_now().isoformat(),
    })
