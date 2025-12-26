from __future__ import annotations
from datetime import datetime, timezone, timedelta
import random
import secrets
from typing import List, Dict, Any
from flask import (
    Blueprint, render_template, jsonify, redirect, url_for,
    flash, request, current_app
)
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash

# ----- App Imports -----
from app.models import User, Organization
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.extensions import db, bcrypt

# 🔥 ADD THIS HERE — REQUIRED
from app.security.permissions import role_required



# ----- Utility Imports -----
from app.utils.compliance_score import get_compliance_score
from app.utils.compliance_breakdown import get_compliance_breakdown
from app.utils.sector_features import get_sector_features
from app.utils.sector_compliance import get_sector_compliance
from app.utils.sector_data import get_sector_info
from app.utils.notify import send_email_alert, send_sms_alert

# ============================================================
# 🔧 Constants & Utility Helpers
# ============================================================
HEARTBEAT_INTERVAL_SEC = 15    # Agent sends heartbeats every 15s
SLA_MULTIPLIER = 2             # Tolerance factor
TIMEOUT_SECONDS = HEARTBEAT_INTERVAL_SEC * SLA_MULTIPLIER  # 30s total timeout
AT_RISK_WINDOW_MIN = 15

def _now_utc() -> datetime:
    """Return current UTC time safely."""
    return datetime.now(timezone.utc)

# ============================================================
# 🔹 Blueprint
# ============================================================
dashboard_bp = Blueprint("dashboard", __name__)

# ============================================================
# 🧠 Global Context Processor for All Dashboard Templates
# ============================================================
@dashboard_bp.app_context_processor
def inject_dashboard_context():
    """Ensure all dashboard templates have org/sub/user in context."""
    from flask_login import current_user
    org = getattr(current_user, "organization", None)
    sub = getattr(org, "subscription", None)
    return dict(
        org=org,
        sub=sub,
        user=current_user
    )

# ============================================================
# 🔹 Common Context Helper
# ============================================================
def get_context() -> dict:
    """Provide shared context objects to all templates."""
    org = getattr(current_user, "organization", None)
    sub = getattr(org, "subscription", None)
    return dict(
        user=current_user,
        org=org,
        sub=sub,
        now_utc=_now_utc(),
        timedelta=timedelta
    )
# ============================================================
# 🔒 Context Enforcer Decorator
# ============================================================
from functools import wraps
from flask import g

def ensure_context(f):
    """Ensure org/sub context variables are always present for sidebar rendering."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        ctx = get_context()
        g.org = ctx.get("org")
        g.sub = ctx.get("sub")
        return f(*args, **kwargs)
    return wrapper

# ============================================================
# 🔹 Agent Token Helper
# ============================================================
def ensure_agent_token(org: Organization) -> str:
    """Ensure each organization has a persistent agent token."""
    if org and not getattr(org, "agent_token", ""):
        org.agent_token = secrets.token_hex(16)
        db.session.commit()
    return org.agent_token if org else ""

# ============================================================
# 🔹 Dashboard Routing
# ============================================================
@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    """
    Main landing dashboard after login.
    Redirects by role, handles users with no organization gracefully.
    """
    org = getattr(current_user, "organization", None)

    # Handle missing organization safely
    if not org:
        flash("No organization linked to your account yet.", "warning")
        return render_template(
            "dashboard/dashboard_user.html",
            org=None,
            devices=[],
            events=[],
            agg={"total": 0, "online": 0, "offline": 0, "uptime_pct": 0},
        )

    # Role-based redirection
    if getattr(current_user, "role", "") == "admin":
        return admin_dashboard()
    return user_dashboard()

# ============================================================
# 🎨 PUBLIC PORTFOLIO & DOCS
# ============================================================
@dashboard_bp.route("/portfolio")
def portfolio():
    """Public portfolio page for HR/Recruiters."""
    return render_template("portfolio.html")

@dashboard_bp.route("/documentation")
def documentation():
    """Public documentation page (Print to PDF)."""
    return render_template("documentation.html")

# ============================================================
# 👤 USER DASHBOARD
# ============================================================
@dashboard_bp.route("/dashboard/user")
@login_required
def user_dashboard():
    from app.models import Device, Alert
    ctx = get_context()
    org = ctx["org"]

    devices = Device.query.filter_by(organization_id=org.id).all() if org else []
    alerts = (
        Alert.query.filter_by(organization_id=org.id)
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
        if org else []
    )

    total = len(devices)
    online = sum(1 for d in devices if d.status == "online")
    offline = total - online

    agg = {
        "total": total,
        "online": online,
        "offline": offline,
        "uptime_pct": round((online / total * 100), 1) if total else 0.0,
    }

    ctx.update(dict(devices=devices, events=alerts, agg=agg))
    return render_template("dashboard/dashboard_user.html", **ctx)

# ============================================================
# 🛰️ COMMAND CENTER (New AI Dashboard)
# ============================================================
@dashboard_bp.route("/command-center")
@role_required("admin")
def command_center():
    ctx = get_context()
    return render_template("dashboard/command_center.html", **ctx)

# ============================================================
# 🤖 AI INSIGHTS DASHBOARD
# ============================================================
@dashboard_bp.route("/dashboard/ai")
@login_required
@role_required("admin")
def ai_insights_dashboard():
    from app.models.event import Event
    ctx = get_context()
    org = ctx["org"]

    # Fetch events (assuming all events are relevant for now, or filter by category if needed)
    alerts = (
        Event.query.filter_by(organization_id=org.id)
        .order_by(Event.ts.desc())
        .limit(50)
        .all()
        if org else []
    )

    # Calculate Summary Metrics
    # 1. File Scans (Category: 'malware', 'file')
    file_scans_count = sum(1 for a in alerts if a.category in ["malware", "file"])
    
    # 2. Process Events (Category: 'process', 'execution')
    process_events_count = sum(1 for a in alerts if a.category in ["process", "execution"])

    # 3. Network Events (Category: 'network')
    network_events_count = sum(1 for a in alerts if a.category == "network")

    # 4. Threat View (High/Critical Severity)
    threat_view_count = sum(1 for a in alerts if a.severity in ["high", "critical"])

    metrics = {
        "file_scans": file_scans_count,
        "process_events": process_events_count,
        "network_events": network_events_count,
        "threat_view": threat_view_count
    }

    # 5. Top At-Risk Devices (Aggregation)
    from app.models.device import Device
    from sqlalchemy import func
    
    # Query: Group by device, count high/critical alerts
    risky_query = (
        db.session.query(
            Event.device_id,
            func.count(Event.id).label('alert_count')
        )
        .filter(Event.organization_id == org.id)
        .filter(Event.severity.in_(["high", "critical"]))
        .filter(Event.device_id.isnot(None))
        .group_by(Event.device_id)
        .order_by(func.count(Event.id).desc())
        .limit(5)
        .all()
    )
    
    risky_devices = []
    for r in risky_query:
        device = Device.query.get(r.device_id)
        if device:
            risky_devices.append({
                "id": device.id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "mac": device.mac,
                "count": r.alert_count,
                "status": device.status,
                "os": device.os or "Unknown"
            })

    ctx.update(dict(alerts=alerts, metrics=metrics, risky_devices=risky_devices))
    return render_template("dashboard/ai/ai_insights.html", **ctx)


@dashboard_bp.route("/dashboard/ai/files")
@role_required("admin")
def ai_files():
    from app.models.event import Event
    from sqlalchemy.orm import joinedload
    ctx = get_context()
    org = ctx["org"]
    
    alerts = (
        Event.query.options(joinedload(Event.device))
        .filter_by(organization_id=org.id)
        .filter(Event.category.in_(["malware", "file"]))
        .order_by(Event.ts.desc())
        .limit(100)
        .all()
        if org else []
    )
    
    ctx.update(dict(alerts=alerts, title="File Security Scans"))
    return render_template("dashboard/ai/ai_files.html", **ctx)


@dashboard_bp.route("/dashboard/ai/processes")
@role_required("admin")
def ai_processes():
    from app.models.event import Event
    from sqlalchemy.orm import joinedload
    ctx = get_context()
    org = ctx["org"]
    
    alerts = (
        Event.query.options(joinedload(Event.device))
        .filter_by(organization_id=org.id)
        .filter(Event.category.in_(["process", "execution"]))
        .order_by(Event.ts.desc())
        .limit(100)
        .all()
        if org else []
    )
    
    ctx.update(dict(alerts=alerts, title="Process Activity Analysis"))
    return render_template("dashboard/ai/ai_processes.html", **ctx)


@dashboard_bp.route("/dashboard/ai/network")
@role_required("admin")
def ai_network():
    from app.models.event import Event
    from sqlalchemy.orm import joinedload
    ctx = get_context()
    org = ctx["org"]
    
    alerts = (
        Event.query.options(joinedload(Event.device))
        .filter_by(organization_id=org.id)
        .filter(Event.category == "network")
        .order_by(Event.ts.desc())
        .limit(100)
        .all()
        if org else []
    )
    
    ctx.update(dict(alerts=alerts, title="Network Traffic Analysis"))
    return render_template("dashboard/ai/ai_network.html", **ctx)


@dashboard_bp.route("/dashboard/ai/threats")
@role_required("admin")
def ai_threats():
    from app.models.event import Event
    from sqlalchemy.orm import joinedload
    ctx = get_context()
    org = ctx["org"]
    
    # High/Critical threats from ANY category
    alerts = (
        Event.query.options(joinedload(Event.device))
        .filter_by(organization_id=org.id)
        .filter(Event.severity.in_(["high", "critical"]))
        .order_by(Event.ts.desc())
        .limit(100)
        .all()
        if org else []
    )
    
    ctx.update(dict(alerts=alerts, title="High Priority Threats"))
    return render_template("dashboard/ai/ai_threats.html", **ctx)





@dashboard_bp.route("/dashboard/ai/training")
@role_required("admin")
def ai_training():
    from app.ai.learning_engine import LearningEngine
    from app.models.ai_learned_rule import AILearnedRule
    
    ctx = get_context()
    org = ctx["org"]
    
    engine = LearningEngine()
    stats = engine.get_training_stats(org.id) if org else {}
    threats = engine.fetch_global_threats()
    
    # Fetch learned rules
    learned_rules = AILearnedRule.query.order_by(AILearnedRule.last_updated.desc()).all()
    
    ctx.update(dict(stats=stats, threats=threats, learned_rules=learned_rules))
    return render_template("dashboard/ai/ai_training.html", **ctx)


@dashboard_bp.route("/api/ai/feedback", methods=["POST"])
@role_required("admin")
def ai_feedback():
    from app.ai.learning_engine import LearningEngine
    from flask import request, jsonify
    
    data = request.json
    alert_id = data.get("alert_id")
    feedback = data.get("feedback") # 'true_positive' or 'false_positive'
    
    if not alert_id or not feedback:
        return jsonify({"error": "Missing data"}), 400
        
    engine = LearningEngine()
    success, msg = engine.submit_feedback(alert_id, feedback)
    
    if success:
        return jsonify({"ok": True, "msg": msg})
    else:
        return jsonify({"ok": False, "error": msg}), 404

# ============================================================
# 🧑‍💼 ADMIN DASHBOARD
# ============================================================
@dashboard_bp.route("/dashboard/admin")
@role_required("admin")
def admin_dashboard():
    from app.models import Device, Alert
    ctx = get_context()
    org = ctx["org"]

    devices = Device.query.filter_by(organization_id=org.id).all() if org else []
    alerts = (
        Alert.query.filter_by(organization_id=org.id)
        .order_by(Alert.created_at.desc())

        .limit(20)
        .all()
        if org else []
    )

    total = len(devices)
    online = sum(1 for d in devices if d.status == "online")
    offline = total - online

    agg = {
        "total": total,
        "online": online,
        "offline": offline,
        "unusual": 0,
        "uptime_pct": round((online / total * 100), 1) if total else 0.0,
    }

    # Calculate Severity Counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in alerts:
        sev = (a.severity or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # 1. OS Distribution
    os_counts = {"Windows": 0, "Linux": 0, "macOS": 0, "Other": 0}
    for d in devices:
        os_name = (d.os or "Other").lower()
        if "windows" in os_name:
            os_counts["Windows"] += 1
        elif "linux" in os_name or "ubuntu" in os_name or "debian" in os_name:
            os_counts["Linux"] += 1
        elif "mac" in os_name or "darwin" in os_name:
            os_counts["macOS"] += 1
        else:
            os_counts["Other"] += 1

    # 2. Failed Logins Trend (Last 24h, 4h buckets)
    # We look for events with category='auth' or 'security' and high severity
    from app.models.event import Event
    now = _now_utc()
    since_24h = now - timedelta(hours=24)
    
    login_events = (
        Event.query.filter(Event.organization_id == org.id)
        .filter(Event.ts >= since_24h)
        .filter(Event.category.in_(["auth", "security", "login"]))
        .all()
    )

    # Filter for failures in Python (or add to query if simple)
    failed_events = []
    for e in login_events:
        msg = (e.message or "").lower()
        dtl = (e.detail or "").lower()
        if "fail" in msg or "fail" in dtl:
            failed_events.append(e)
    
    # Bucket into 6 4-hour slots
    failed_logins_trend = [0] * 6
    for e in failed_events:
        # Calculate which bucket (0 = oldest, 5 = newest)
        ts = e.ts
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
            
        age_hours = (now - ts).total_seconds() / 3600
        bucket_idx = 5 - int(age_hours / 4)
        if 0 <= bucket_idx <= 5:
            failed_logins_trend[bucket_idx] += 1

    # 3. CPU/Mem Trend (Last 24h, 4h buckets) - Average across all devices
    # We need to query DeviceTelemetry
    from app.models.device_telemetry import DeviceTelemetry
    from sqlalchemy import func

    # Get average CPU/Mem per 4h bucket
    # This is a bit complex in pure SQL with SQLite, so we'll fetch recent telemetry and aggregate in Python for simplicity
    # Limiting to last 1000 points to avoid performance hit
    telemetry = (
        DeviceTelemetry.query.join(Device)
        .filter(Device.organization_id == org.id)
        .filter(DeviceTelemetry.ts >= since_24h)
        .order_by(DeviceTelemetry.ts.asc())
        # .limit(1000)  <-- REMOVED LIMIT to ensure we see recent data
        .all()
    )

    cpu_trend = [0.0] * 6
    mem_trend = [0.0] * 6
    counts = [0] * 6

    for t in telemetry:
        ts = t.ts
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_hours = (now - ts).total_seconds() / 3600
        bucket_idx = 5 - int(age_hours / 4)
        if 0 <= bucket_idx <= 5:
            cpu_trend[bucket_idx] += t.cpu_percent
            mem_trend[bucket_idx] += t.mem_percent
            counts[bucket_idx] += 1
    
    # Average them
    for i in range(6):
        if counts[i] > 0:
            cpu_trend[i] = round(cpu_trend[i] / counts[i], 1)
            mem_trend[i] = round(mem_trend[i] / counts[i], 1)

    status_counts = {"online": online, "offline": offline, "unusual": 0}

    chart_data = {
        "threatTrend": [], # TODO: Implement if needed
        "cpuTrend": cpu_trend,
        "memTrend": mem_trend,
        "statusSplit": [online, offline, 0],
        "severityCounts": [
            severity_counts["critical"],
            severity_counts["high"],
            severity_counts["medium"],
            severity_counts["low"],
            severity_counts["info"]
        ],
        "failedLogins": failed_logins_trend,
        "osCounts": [
            os_counts["Windows"],
            os_counts["Linux"],
            os_counts["macOS"],
            os_counts["Other"]
        ]
    }

    # --------------------------------------------------------
    # 🧪 MOCK DATA INJECTION REMOVED
    # Now relying purely on live data from the database.
    # --------------------------------------------------------

    ctx.update(dict(
        devices=devices,
        events=alerts,
        agg=agg,
        status_counts=status_counts,
        chart_data=chart_data
    ))

    return render_template("dashboard/dashboard_admin.html", **ctx)

# ============================================================
# 🧠 PROFILE (with Compliance)
# ============================================================
@dashboard_bp.route("/profile")
@login_required
def profile():
    ctx = get_context()
    org = ctx["org"]
    sub = ctx["sub"]
    sector_key = (org.sector if org and getattr(org, "sector", None) else "academic").lower()

    sector_info = get_sector_info(sector_key)
    plan = (sub.plan if sub else "basic").lower()
    compliance_score = get_compliance_score(sector_key, plan)
    breakdown = get_compliance_breakdown(sector_key, plan)

    ctx.update(dict(
        sector_info=sector_info,
        compliance_score=compliance_score,
        breakdown=breakdown
    ))
    return render_template("dashboard/profile.html", **ctx)

# ============================================================
# 💳 SUBSCRIPTION MANAGEMENT
# ============================================================
@dashboard_bp.route("/subscription", methods=["GET", "POST"])
@login_required
def subscription():
    ctx = get_context()
    org, sub = ctx["org"], ctx["sub"]
    sector = (org.sector if org and getattr(org, "sector", None) else "academic").lower()

    if request.method == "POST":
        action = request.form.get("action")
        if action and sub:
            if action == "upgrade_pro":
                sub.plan = "professional"
                sub.sos_enabled = True
                flash("Plan upgraded to Professional.", "success")
            elif action == "upgrade_ent":
                sub.plan = "enterprise"
                sub.sos_enabled = True
                flash("Plan upgraded to Enterprise.", "success")
            elif action == "downgrade_basic":
                sub.plan = "basic"
                sub.sos_enabled = False
                flash("Plan downgraded to Basic.", "warning")
            elif action == "cancel":
                sub.status = "canceled"
                flash("Subscription canceled.", "warning")
            db.session.commit()
        return redirect(url_for("dashboard.subscription"))

    features = get_sector_features(sector)
    compliance = get_sector_compliance(sector)
    ctx.update(dict(features=features, compliance=compliance))
    return render_template("dashboard/subscription.html", **ctx)

# ============================================================
# ⚠️ AT-RISK DEVICES
# ============================================================
@dashboard_bp.route("/at-risk")
@role_required("admin")
def at_risk():
    from app.models import Device
    ctx = get_context()
    org = ctx["org"]
    if not org:
        flash("No organization linked.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    devices = Device.query.filter_by(organization_id=org.id).all()
    risky = []
    for d in devices:
        if d.status != "online":
            d.risk_type = "Offline Device"
            d.severity = "critical"
            d.mitigation = "Check agent service or network."
            risky.append(d)
        elif "high" in (d.agent_version or "").lower():
            d.risk_type = "Outdated Agent"
            d.severity = "medium"
            d.mitigation = "Update agent to latest version."
            risky.append(d)

    ctx.update(dict(risky=risky))
    return render_template("dashboard/at_risk.html", **ctx)

# ============================================================
# 🖥️ DEVICES PAGE (REAL ENDPOINTS)
# ============================================================
@dashboard_bp.route("/dashboard/devices")
@role_required("admin")
@ensure_context
def devices_page():
    from app.models import Device
    org = getattr(current_user, "organization", None)
    if not org:
        return redirect(url_for("dashboard.overview"))

    devices = Device.query.filter_by(organization_id=org.id).all()
    now = _now_utc()

    for d in devices:
        if d.last_seen:
            last_seen = d.last_seen.replace(tzinfo=timezone.utc) if not d.last_seen.tzinfo else d.last_seen
            stale = (now - last_seen).total_seconds() > TIMEOUT_SECONDS
        else:
            stale = True
        d.status = "offline" if stale else "online"

    stats = {
        "total": len(devices),
        "online": sum(1 for d in devices if d.status == "online"),
        "high_risk": sum(1 for d in devices if d.risk_level == "high"),
        "critical": sum(1 for d in devices if d.risk_level == "critical")
    }

    return render_template("dashboard/devices.html", devices=devices, stats=stats, now=now, timeout_seconds=TIMEOUT_SECONDS)


# ============================================================
# 🗑️ DELETE DEVICE
# ============================================================
@dashboard_bp.route("/dashboard/devices/delete/<int:device_id>", methods=["POST"])
@role_required("admin")
def delete_device(device_id):
    from app.models import Device
    org = getattr(current_user, "organization", None)
    if not org:
        return redirect(url_for("dashboard.overview"))

    device = Device.query.get_or_404(device_id)

    # Security check: Ensure device belongs to this org
    if device.organization_id != org.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard.devices_page"))

    try:
        db.session.delete(device)
        db.session.commit()
        flash(f"Device '{device.device_name}' deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting device: {str(e)}", "danger")

    return redirect(url_for("dashboard.devices_page"))

# ============================================================
# ⚙️ SETUP AGENT GUIDE
# ============================================================
@dashboard_bp.route("/dashboard/setup-agent")
@role_required("admin")
@ensure_context
def setup_agent_page():
    ctx = get_context()
    org = ctx["org"]
    token = ensure_agent_token(org)
    manager_url = request.host_url.rstrip("/")

    if not ctx.get("sub"):
        ctx["sub"] = getattr(org, "subscription", None)

    ctx.update(dict(agent_token=token, manager_url=manager_url))
    
    # Force cache busting
    from flask import make_response
    resp = make_response(render_template("dashboard/setup_agent.html", **ctx))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# ============================================================
# 👥 USER MANAGEMENT
# ============================================================
@dashboard_bp.route("/add-user", methods=["GET", "POST"])
@role_required("admin")
def add_user():
    ctx = get_context()
    org, sub = ctx["org"], ctx["sub"]
    plan = (sub.plan.lower() if sub else "basic")
    existing_users = User.query.filter_by(organization_id=org.id).count() if org else 0

    if plan == "basic" and existing_users >= 5:
        flash("❌ Basic Plan Limit Reached: Maximum 5 users allowed.", "danger")
        return redirect(url_for("dashboard.admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("A user with this email already exists.", "warning")
            return redirect(url_for("dashboard.add_user"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_pw,
            role="user",
            sector=getattr(org, "sector", "academic"),
            organization_id=org.id if org else None,
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f"✅ User '{username}' added successfully under {org.name}!", "success")
        return redirect(url_for("dashboard.add_user"))

    ctx.update(dict(plan=plan, existing_users=existing_users))
    return render_template("dashboard/add_user.html", **ctx)


@dashboard_bp.route("/manage-users")
@role_required("admin")
def manage_users():
    ctx = get_context()
    org, sub = ctx["org"], ctx["sub"]

    user_count = User.query.filter_by(organization_id=org.id).count() if org else 0
    plan = (sub.plan if sub else "basic").lower()
    max_users = 5 if plan == "basic" else None
    limit_reached = max_users is not None and user_count >= max_users

    users = (
        User.query.filter_by(organization_id=org.id)
        .order_by(User.id.desc())
        .all()
        if org else []
    )
    ctx.update(dict(users=users, limit_reached=limit_reached, max_users=max_users))
    return render_template("dashboard/manage_users.html", **ctx)


@dashboard_bp.route("/dashboard/users/edit/<int:user_id>", methods=["POST"])
@role_required("admin")
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    org = getattr(current_user, "organization", None)
    if not org or user.organization_id != org.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard.manage_users"))

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    if username:
        user.username = username
    if email:
        user.email = email
    if password:
        user.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    db.session.commit()
    flash(f"✅ User '{user.username}' updated successfully.", "success")
    return redirect(url_for("dashboard.manage_users"))


@dashboard_bp.route("/dashboard/users/deactivate/<int:user_id>")
@role_required("admin")
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    org = getattr(current_user, "organization", None)
    if not org or user.organization_id != org.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard.manage_users"))

    user.is_enabled = not getattr(user, "is_enabled", True)
    db.session.commit()
    state = "activated" if user.is_enabled else "deactivated"
    flash(f"User '{user.username}' has been {state}.", "info")
    return redirect(url_for("dashboard.manage_users"))


@dashboard_bp.route("/dashboard/users/promote/<int:user_id>")
@role_required("admin")
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    org = getattr(current_user, "organization", None)
    sub = getattr(org, "subscription", None)

    if not org or user.organization_id != org.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard.manage_users"))

    if sub and sub.plan == "basic":
        flash("⚠️ Role management is only available for Professional/Enterprise plans.", "warning")
        return redirect(url_for("dashboard.manage_users"))

    if user.id == current_user.id:
        flash("You cannot change your own role.", "danger")
        return redirect(url_for("dashboard.manage_users"))

    user.role = "admin" if user.role == "user" else "user"
    db.session.commit()
    flash(f"✅ User '{user.username}' role changed to {user.role.upper()}.", "success")
    return redirect(url_for("dashboard.manage_users"))


@dashboard_bp.route("/dashboard/users/delete/<int:user_id>", methods=["POST"])
@role_required("admin")
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    org = getattr(current_user, "organization", None)
    if not org or user.organization_id != org.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard.manage_users"))

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("dashboard.manage_users"))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted.", "danger")
    return redirect(url_for("dashboard.manage_users"))

# ============================================================
# 📡 DEVICE API — LIST / CLEANUP / STATUS
# ============================================================
@dashboard_bp.route("/api/devices/list")
@role_required("admin")
def api_devices_list():
    from app.models import Device
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "No organization linked"}), 400

    devices = Device.query.filter_by(organization_id=org.id).order_by(Device.last_seen.desc()).all()
    now = _now_utc()

    items = []
    for d in devices:
        if not d.last_seen:
            status = "offline"
            diff = 9999
        else:
            last_seen = d.last_seen.replace(tzinfo=timezone.utc) if not d.last_seen.tzinfo else d.last_seen
            diff = (now - last_seen).total_seconds()
            status = "online" if diff <= TIMEOUT_SECONDS else "offline"

        if d.status != status:
            d.status = status

        items.append({
            "id": d.id,
            "name": d.device_name,
            "os": d.os,
            "ip": d.ip,
            "status": status,
            "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M:%S") if d.last_seen else None,
            "version": d.agent_version
        })

    db.session.commit()
    return jsonify({"status": "ok", "items": items})


@dashboard_bp.route("/api/devices/cleanup", methods=["POST"])
@role_required("admin")
def api_devices_cleanup():
    from app.models import Device
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "No organization linked"}), 400

    devices = Device.query.filter_by(organization_id=org.id).all()
    seen = {}
    removed = 0
    for d in sorted(devices, key=lambda x: x.id, reverse=True):
        if d.device_name in seen:
            db.session.delete(d)
            removed += 1
        else:
            seen[d.device_name] = True

    db.session.commit()
    return jsonify({"status": "ok", "removed": removed})

# ============================================================
# 🚨 DEMO SEED: Generate SOS Alerts for Testing
# ============================================================
@dashboard_bp.route("/api/sos/seed", endpoint="api_sos_seed")
@role_required("admin")
def api_sos_seed():
    """Generate sample SOS alerts for testing and visualization."""
    from app.models import Alert
    org = getattr(current_user, "organization", None)
    if not org:
        flash("No organization linked to your account.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    sample_alerts = [
        ("Brute Force Attempt", "Multiple failed SSH logins detected.", "high"),
        ("Unauthorized Access", "Unrecognized admin login from new IP.", "medium"),
        ("Malware Activity", "Suspicious outbound traffic detected.", "critical"),
    ]

    for title, message, sev in sample_alerts:
        alert = Alert(
            title=title,
            message=message,
            severity=sev,
            category="system",
            organization_id=org.id,
        )
        db.session.add(alert)
    db.session.commit()

    flash("✅ Demo SOS Alerts seeded successfully!", "success")
    return redirect(url_for("dashboard.alerts_dashboard"))

# ============================================================
# 🆘 SOS CONTACT MANAGEMENT + ALERTING FRAMEWORK
# ============================================================

@dashboard_bp.route(
    "/dashboard/update-sos-contacts",
    methods=["POST"],
    endpoint="update_sos_contacts"
)
@role_required("admin")
def update_sos_contacts():
    """Update SOS alert contact details (email & phone)."""
    org = getattr(current_user, "organization", None)
    if not org:
        flash("Organization not found.", "danger")
        return redirect(url_for("dashboard.profile"))

    org.alert_email = request.form.get("alert_email", "").strip() or None
    org.alert_phone = request.form.get("alert_phone", "").strip() or None
    db.session.commit()
    flash("✅ SOS alert contact details updated successfully.", "success")
    return redirect(url_for("dashboard.profile"))


@dashboard_bp.route(
    "/dashboard/clear-sos-contacts",
    endpoint="clear_sos_contacts"
)
@role_required("admin")
def clear_sos_contacts():
    """Remove all SOS contact details."""
    org = getattr(current_user, "organization", None)
    if not org:
        flash("Organization not found.", "danger")
        return redirect(url_for("dashboard.profile"))

    org.alert_email = None
    org.alert_phone = None
    db.session.commit()
    flash("🗑️ SOS alert contact details removed.", "info")
    return redirect(url_for("dashboard.profile"))


@dashboard_bp.route("/dashboard/alerts", endpoint="alerts_dashboard")
@role_required("admin")
def alerts_dashboard():
    """Display all SOS alerts for the admin’s organization."""
    from app.models import Alert
    org = getattr(current_user, "organization", None)
    if not org:
        flash("No organization linked.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    alerts = (
        Alert.query.filter_by(organization_id=org.id)
        .order_by(Alert.created_at.desc())

        .limit(100)
        .all()
    )
    ctx = get_context()
    ctx.update(dict(alerts=alerts))
    return render_template("dashboard/alerts.html", **ctx)


@dashboard_bp.route("/dashboard/sos-preferences", endpoint="sos_preferences_page")
@role_required("admin")
def sos_preferences_page():
    """Display the SOS preferences setup page."""
    from app.models import AlertPreference
    org = getattr(current_user, "organization", None)
    sub = getattr(org, "subscription", None)

    if not org:
        flash("No organization linked.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))
    if not sub or not getattr(sub, "sos_enabled", False):
        flash("SOS is not enabled for your plan. Upgrade in Subscription.", "warning")
        return redirect(url_for("dashboard.subscription"))

    pref = AlertPreference.query.filter_by(organization_id=org.id).first()
    if not pref:
        pref = AlertPreference(organization_id=org.id)
        db.session.add(pref)
        db.session.commit()

    ctx = get_context()
    ctx.update(dict(prefs=pref))
    return render_template("dashboard/sos_preferences.html", **ctx)
# ============================================================
# 🔴 LIVE EVENTS DASHBOARD — Unified Agent + SOS Feed
# ============================================================
from flask import render_template, jsonify
from flask_login import login_required, current_user
from app.models.event import Event
from app.models.device import Device



# ============================================================
# 🧠 AI Insights (main AI dashboard page)
# ============================================================


@dashboard_bp.route("/api/events/live", methods=["GET"])
@login_required
def api_events_live():
    """
    Returns the last 24 hours of Event model entries
    with full SIEM-style fields for Live Events UI.
    """
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "No organization"}), 400

    since = datetime.now(timezone.utc) - timedelta(hours=24)

    events = (
        Event.query
        .filter(Event.organization_id == org.id)
        .filter(Event.ts >= since)
        .order_by(Event.ts.desc())
        .limit(200)
        .all()
    )

    results = []
    for e in events:
        # Resolve device name (safe even if device deleted)
        device_name = None
        if e.device_id:
            dev = Device.query.get(e.device_id)
            device_name = dev.device_name if dev else None

        results.append({
            "id": e.id,
            "time": e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "severity": e.severity,
            "category": e.category,
            "event_type": e.event_type,

            # AI / rule metadata
            "rule_name": getattr(e, "rule_name", None),
            "ai_rule": getattr(e, "rule_name", None),

            "device": device_name or "Unlinked",
            "mac": e.mac or "-",
            "detail": e.detail or e.message or "-",
            "mitigation": getattr(e, "mitigation", None),

            # Risk score (for AI insight chip)
            "risk_score": getattr(e, "risk_score", 0),

            # NEW: correlation fields
            "correlation_id": getattr(e, "correlation_id", None),
            "correlation_key": getattr(e, "correlation_key", None),
            "correlation_score": getattr(e, "correlation_score", None),

            "action": e.action,
            "ip": getattr(e, "ip", None),
            "raw": e.raw if getattr(e, "raw", None) else {},
        })

    return jsonify({"status": "ok", "events": results})

# ============================================================
# 📂 INCIDENT DASHBOARD (LIST + DETAIL)
# ============================================================
@dashboard_bp.route("/dashboard/incidents", methods=["GET"])
@login_required
@role_required("admin")
def incidents_dashboard():
    """
    Main Incident Console:
    - Shows all incidents for the current org
    - Basic stats: open vs closed
    """
    ctx = get_context()
    org = ctx["org"]

    if not org:
        flash("No organization linked.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    incidents = (
        Incident.query
        .filter_by(organization_id=org.id)
        .order_by(Incident.created_at.desc())
        .limit(200)
        .all()
    )

    open_count = sum(
        1 for i in incidents
        if (i.status or "").lower() in ("open", "investigating", "escalated")
    )
    closed_count = sum(
        1 for i in incidents
        if (i.status or "").lower() in ("closed", "resolved")
    )

    ctx.update(
        dict(
            incidents=incidents,
            open_count=open_count,
            closed_count=closed_count,
        )
    )
    return render_template("dashboard/incidents.html", **ctx)


@dashboard_bp.route("/dashboard/incidents/<int:incident_id>", methods=["GET"])
@login_required
@role_required("admin")
def incident_detail(incident_id: int):
    """
    Incident drill-down:
    - Shows incident metadata
    - Shows all linked Event rows (via incident_id)
    """
    ctx = get_context()
    org = ctx["org"]

    if not org:
        flash("No organization linked.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    incident = (
        Incident.query
        .filter_by(id=incident_id, organization_id=org.id)
        .first_or_404()
    )

    events = (
        Event.query
        .filter_by(organization_id=org.id, incident_id=incident.id)
        .order_by(Event.ts.asc())
        .all()
    )

    ctx.update(dict(incident=incident, events=events))
    return render_template("dashboard/incident_detail.html", **ctx)


@dashboard_bp.route("/api/events/<int:event_id>", methods=["GET"])
@login_required
def api_event_detail(event_id: int):
    """
    Detailed view for a single Event, plus a short related timeline
    for correlation-style context.
    """
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "No organization"}), 400

    e = Event.query.get_or_404(event_id)
    if e.organization_id != org.id:
        # Do not leak cross-org event existence
        return jsonify({"status": "error", "message": "Not found"}), 404

    # Resolve device name (safe if deleted)
    device_name = None
    if e.device_id:
        dev = Device.query.get(e.device_id)
        device_name = dev.device_name if dev else None

    # Small correlation-style window: last 10 minutes on same MAC
    window_start = e.ts - timedelta(minutes=10)

    related_rows = (
        Event.query
        .filter(
            Event.organization_id == org.id,
            Event.mac == e.mac,
            Event.ts >= window_start,
            Event.id != e.id,
        )
        .order_by(Event.ts.asc())
        .limit(20)
        .all()
    )

    related = []
    for r in related_rows:
        related.append({
            "id": r.id,
            "time": r.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "severity": r.severity,
            "category": r.category or r.event_type,
            "event_type": r.event_type,
            "action": r.action or "",
            "detail": r.detail or r.message or "-",
        })

    # Main event payload
    event_payload = {
        "id": e.id,
        "time": e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "severity": e.severity,
        "category": e.category or e.event_type,
        "event_type": e.event_type,
        "action": e.action or "",
        "device": device_name or "Unlinked",
        "mac": e.mac or "-",
        "detail": e.detail or e.message or "-",
        "correlation": {
            "id": e.correlation_id,
            "key": e.correlation_key,
            "score": e.correlation_score or 0,
        },
        # AI metadata (may be empty today, but future-proof)
        "ai_rule": getattr(e, "ai_rule", None),
        "risk_score": getattr(e, "risk_score", None) or 0,
    }

    return jsonify({
        "status": "ok",
        "event": event_payload,
        "related": related,
    }), 200
# ============================================================
# 🧠 AI Correlation Incidents (Phase 2.5)
# ============================================================
from app.models.device import Device  # already imported earlier, safe to reuse


@dashboard_bp.route("/dashboard/ai/correlation", methods=["GET"])
@login_required
@role_required("admin")
def ai_correlation_page():
    """
    Main AI Correlation incidents page.
    The table itself is populated via /api/ai/correlation/incidents (AJAX).
    """
    ctx = get_context()
    org = ctx["org"]

    if not org:
        flash("No organization linked.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    return render_template("dashboard/ai/ai_correlation.html", **ctx)


@dashboard_bp.route("/api/ai/correlation/incidents", methods=["GET"])
@login_required
@role_required("admin")
def api_ai_correlation_incidents():
    """
    Returns recent correlation events as 'incidents' for the correlation UI.

    We treat any Event where event_type == 'correlation' as a correlated incident
    generated by the AI correlation engine.
    """
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "No organization"}), 400

    # last 24h of correlated incidents
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    rows = (
        Event.query
        .filter(
            Event.organization_id == org.id,
            Event.event_type == "correlation",
            Event.ts >= since,
        )
        .order_by(Event.ts.desc())
        .limit(200)
        .all()
    )

    incidents = []
    for e in rows:
        device_name = None
        if e.device_id:
            dev = Device.query.get(e.device_id)
            device_name = dev.device_name if dev else None

        incidents.append({
            "id": e.id,
            "time": e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "category": e.category or "correlation",
            "severity": e.severity or "info",
            "device": device_name or "Unlinked",
            "mac": e.mac or "-",
            "correlation_score": e.correlation_score or 0,
            "detail": e.detail or e.message or "-",
        })

    return jsonify({"status": "ok", "incidents": incidents}), 200

# ============================================================
# 🔹 Device Management
# ============================================================
@dashboard_bp.route("/devices")
@login_required
@ensure_context
def devices():
    """
    Device Management Dashboard.
    Supports filtering by risk level and status.
    """
    from app.models.device import Device
    
    # Get filter parameters
    risk_filter = request.args.get('risk', 'all')
    status_filter = request.args.get('status', 'all')
    
    # Base query
    query = Device.query.filter_by(organization_id=current_user.organization_id)
    
    # Apply filters
    if risk_filter != 'all':
        query = query.filter_by(risk_level=risk_filter)
        
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
        
    # Get devices sorted by priority (desc) and last_seen (desc)
    devices = query.order_by(Device.priority.desc(), Device.last_seen.desc()).all()
    
    # Calculate stats
    total_devices = Device.query.filter_by(organization_id=current_user.organization_id).count()
    online_devices = Device.query.filter_by(organization_id=current_user.organization_id, status='online').count()
    high_risk_devices = Device.query.filter_by(organization_id=current_user.organization_id, risk_level='high').count()
    critical_risk_devices = Device.query.filter_by(organization_id=current_user.organization_id, risk_level='critical').count()
    
    return render_template(
        "dashboard/devices.html",
        devices=devices,
        risk_filter=risk_filter,
        status_filter=status_filter,
        stats={
            "total": total_devices,
            "online": online_devices,
            "high_risk": high_risk_devices,
            "critical": critical_risk_devices
        }
    )
    


@dashboard_bp.route("/dashboard/live-events")
@login_required
@ensure_context
def live_events():
    """
    Live Event Dashboard.
    Displays real-time activity of all endpoint devices with detailed event info.
    """
    from app.models.event import Event
    from app.models.device import Device
    
    # Fetch events joined with Device, ordered by timestamp desc
    events = (
        db.session.query(Event, Device)
        .outerjoin(Device, Event.device_id == Device.id)
        .filter(Event.organization_id == current_user.organization_id)
        .order_by(Event.ts.desc())
        .limit(100)  # Limit to last 100 events for performance
        .all()
    )
    
    return render_template("dashboard/live_events.html", events=events)
