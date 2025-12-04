from __future__ import annotations
from flask import Blueprint, request, Response, abort, render_template
from app.extensions import db  # kept for future use / consistency
from app.models import Organization
import textwrap

agent_installer_bp = Blueprint("agent_installer_bp", __name__)

# -------------------------------------------------
# Helpers
# -------------------------------------------------
def _server_base_url() -> str:
    """e.g. http://127.0.0.1:5000 (no trailing slash)."""
    return request.host_url.rstrip("/")


def _get_org_or_404(org_token: str):
    org = Organization.query.filter_by(agent_token=org_token).first()
    if not org:
        abort(404, description="Invalid organization token")
    return org


def _sh(text: str) -> Response:
    return Response(text, mimetype="text/x-shellscript")


def _ps1(text: str) -> Response:
    return Response(text, mimetype="text/plain")


def _py(text: str) -> Response:
    return Response(text, mimetype="text/x-python")


# =====================================================
# Linux Installer (bash)
# =====================================================
def _build_linux_sh(org: Organization, base: str) -> str:
    return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        set -e

        echo "==========================================="
        echo " 🔐 Installing TenshiGuard Agent for: {org.name}"
        echo "==========================================="

        # Ensure Python 3 and venv present
        if ! command -v python3 >/dev/null 2>&1; then
          echo "Python3 not found. Installing..."
          if command -v apt >/dev/null 2>&1; then
            sudo apt update && sudo apt -y install python3 python3-pip python3-venv curl
          elif command -v dnf >/dev/null 2>&1; then
            sudo dnf -y install python3 python3-pip curl
          elif command -v yum >/dev/null 2>&1; then
            sudo yum -y install python3 python3-pip curl
          fi
        fi

        sudo mkdir -p /opt/tenshiguard
        cd /opt/tenshiguard

        echo "📦 Setting up virtual environment..."
        if [ ! -d "venv" ]; then
            sudo python3 -m venv venv
        fi
        
        echo "⬇️  Installing dependencies..."
        sudo ./venv/bin/pip install --upgrade pip requests psutil

        echo "⬇️  Fetching agent client..."
        sudo curl -sSL "{base}/install/agent/client/{org.agent_token}" -o agent_client.py
        sudo chmod +x agent_client.py

        echo "🧩 Creating systemd service..."
        cat <<'EOF' | sudo tee /etc/systemd/system/tenshiguard-agent.service >/dev/null
        [Unit]
        Description=TenshiGuard Agent
        After=network.target

        [Service]
        Type=simple
        ExecStart=/opt/tenshiguard/venv/bin/python /opt/tenshiguard/agent_client.py
        Restart=always
        RestartSec=2
        User=root

        [Install]
        WantedBy=multi-user.target
        EOF

        # Uninstall helper
        cat <<'EOF' | sudo tee /opt/uninstall_tenshiguard.sh >/dev/null
        #!/usr/bin/env bash
        set -e
        echo "==========================================="
        echo " 🚫 Uninstalling TenshiGuard Agent"
        echo "==========================================="
        sudo systemctl stop tenshiguard-agent || true
        sudo systemctl disable tenshiguard-agent || true
        sudo rm -f /etc/systemd/system/tenshiguard-agent.service
        sudo systemctl daemon-reload
        sudo rm -rf /opt/tenshiguard
        echo "✅ TenshiGuard Agent fully removed."
        EOF
        sudo chmod +x /opt/uninstall_tenshiguard.sh

        sudo systemctl daemon-reload
        sudo systemctl enable tenshiguard-agent
        sudo systemctl restart tenshiguard-agent

        echo "✅ Done. Check status with:  systemctl status tenshiguard-agent --no-pager"
        echo "📜 Logs (service):          journalctl -u tenshiguard-agent -f"
    """)


# =====================================================
# Windows Installer (PowerShell)
# =====================================================
def _build_windows_ps(org: Organization, base: str) -> str:
    return textwrap.dedent(f"""\
        # TenshiGuard Windows Agent Installer
        $ErrorActionPreference = "Stop"

        Write-Host "== TenshiGuard Windows Agent =="

        $root = "C:\\TenshiGuard"
        $taskName = "TenshiGuardAgent"

        # 1. Stop existing agent to release file locks
        Write-Host "🛑 Stopping existing agent..."
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        # Kill any python processes running from this folder (aggressive cleanup)
        Get-WmiObject Win32_Process | Where-Object {{ $_.CommandLine -like "*$root*" }} | ForEach-Object {{ 
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue 
        }}
        Start-Sleep -Seconds 2

        if (-not (Test-Path $root)) {{
            New-Item -ItemType Directory -Path $root | Out-Null
        }}

        # Check for Python
        $py = (Get-Command python -ErrorAction SilentlyContinue)
        $validPython = $false

        if ($py) {{
            # Check if it is the Windows Store stub or actually works
            try {{
                $res = python --version 2>&1
                if ($LASTEXITCODE -eq 0) {{
                    $validPython = $true
                }}
            }} catch {{}}
        }}

        if (-not $validPython) {{
            Write-Host "Python not found (or is just a stub). Attempting to install via winget..."
            try {{
                # Install Python 3.11
                winget install -e --id Python.Python.3.11 --scope machine --accept-package-agreements --accept-source-agreements
                
                # Refresh Path
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                
                # Re-check
                $py = (Get-Command python -ErrorAction SilentlyContinue)
                if ($py) {{
                    $res = python --version 2>&1
                    if ($LASTEXITCODE -eq 0) {{
                        $validPython = $true
                    }}
                }}
            }} catch {{
                Write-Host "Winget failed. Please install Python 3 manually and re-run."
                exit 1
            }}
        }}

        if (-not $validPython) {{
             Write-Host "Python still not found. Please restart PowerShell or install Python manually."
             exit 1
        }}

        Write-Host "📦 Setting up virtual environment..."
        Set-Location $root
        # Check if venv exists AND has python.exe. If not, remove and recreate.
        if ((Test-Path "$root\\venv") -and (-not (Test-Path "$root\\venv\\Scripts\\python.exe"))) {{
            Write-Host "   Found broken venv, removing..."
            try {{
                Remove-Item -Path "$root\\venv" -Recurse -Force -ErrorAction Stop
            }} catch {{
                Write-Host "❌ Failed to remove broken venv. Files are locked."
                Write-Host "   Please manually delete C:\\TenshiGuard and try again."
                exit 1
            }}
        }}

        if (-not (Test-Path "$root\\venv")) {{
            try {{
                & $py.Source -m venv venv
                if ($LASTEXITCODE -ne 0) {{ throw "venv creation failed with exit code $LASTEXITCODE" }}
            }} catch {{
                Write-Host "❌ Failed to create virtual environment."
                Write-Host "   Error: $_"
                exit 1
            }}
        }}

        Write-Host "⬇️  Installing dependencies..."
        & "$root\\venv\\Scripts\\python.exe" -m pip install --upgrade pip requests psutil watchdog

        Write-Host "⬇️  Fetching agent client..."
        $client = "{base}/install/agent/client/{org.agent_token}"
        Invoke-WebRequest -Uri $client -OutFile "$root\\agent_client.py"

        Write-Host "Registering scheduled task (SYSTEM)..."
        $action   = New-ScheduledTaskAction -Execute "$root\\venv\\Scripts\\python.exe" -Argument "$root\\agent_client.py"
        $trigger  = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Create settings to allow running on battery and immediately
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Days 0)

        
        try {{
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            Write-Host "✅ Installed successfully. Agent will run on startup."
            
            # Force start now
            Start-ScheduledTask -TaskName $taskName
            Write-Host "   Agent started."
        }} catch {{
            Write-Host "⚠️  Warning: Could not register Scheduled Task (Requires Admin)." -ForegroundColor Yellow
            Write-Host "   The agent will run now, but will not start automatically on reboot."
            Write-Host "   To fix: Run PowerShell as Administrator and reinstall."
            
            # Fallback: Run directly
            Write-Host "🚀 Starting agent manually..."
            & "$root\\venv\\Scripts\\python.exe" "$root\\agent_client.py"
        }}
    """)


# =====================================================
# macOS Installer (bash + launchctl)
# =====================================================
def _build_macos_sh(org: Organization, base: str) -> str:
    return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        set -e
        echo "== TenshiGuard macOS Agent =="

        if ! command -v python3 >/dev/null 2>&1; then
          echo "Please install Python3 (e.g., brew install python)."
          exit 1
        fi

        sudo mkdir -p /opt/tenshiguard
        cd /opt/tenshiguard
        curl -sSL "{base}/install/agent/client/{org.agent_token}" -o agent_client.py
        sudo chmod +x agent_client.py

        cat <<'PLIST' | sudo tee /Library/LaunchDaemons/com.tenshiguard.agent.plist >/dev/null
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>com.tenshiguard.agent</string>
          <key>ProgramArguments</key>
            <array>
              <string>/usr/bin/python3</string>
              <string>/opt/tenshiguard/agent_client.py</string>
            </array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><true/>
          <key>StandardOutPath</key><string>/var/log/tenshiguard.out</string>
          <key>StandardErrorPath</key><string>/var/log/tenshiguard.err</string>
        </dict>
        </plist>
        PLIST

        sudo launchctl load -w /Library/LaunchDaemons/com.tenshiguard.agent.plist
        echo "✅ Installed & started."
    """)


# =====================================================
# Human Preview Page
# =====================================================
@agent_installer_bp.get("/install/agent/test/<org_token>")
def installer_preview(org_token: str):
    org = _get_org_or_404(org_token)
    base = _server_base_url()
    preview = f"""
    <!doctype html>
    <html>
    <head><meta charset="utf-8"><title>TenshiGuard Installer</title></head>
    <body style="font-family:system-ui,Segoe UI,Roboto,Arial">
      <h2>TenshiGuard Agent Installer — {org.name}</h2>
      <p>Linux/macOS:</p>
      <pre>curl -sSL {base}/install/agent/{org.agent_token} | sudo bash</pre>
      <p>Windows (Admin PowerShell):</p>
      <pre>iwr -UseBasicParsing {base}/install/agent/windows/{org.agent_token} | iex</pre>
    </body>
    </html>
    """
    return Response(preview, mimetype="text/html")


# =====================================================
# Installer Endpoints
# =====================================================
@agent_installer_bp.get("/install/agent/<org_token>")
def serve_install_script(org_token: str):
    org = _get_org_or_404(org_token)
    base = _server_base_url()
    return _sh(_build_linux_sh(org, base))


@agent_installer_bp.get("/install/agent/windows/<org_token>")
def windows_ps1(org_token: str):
    org = _get_org_or_404(org_token)
    base = _server_base_url()
    return _ps1(_build_windows_ps(org, base))


@agent_installer_bp.get("/install/agent/macos/<org_token>")
def macos_sh(org_token: str):
    org = _get_org_or_404(org_token)
    base = _server_base_url()
    return _sh(_build_macos_sh(org, base))


# =====================================================
# HTML Guides (your existing pages)
# =====================================================
@agent_installer_bp.get("/install/linux/<org_token>")
def linux_guide(org_token: str):
    org = _get_org_or_404(org_token)
    base = _server_base_url()
    script = _build_linux_sh(org, base)
    return render_template("install/install_linux.html",
                           org=org, org_token=org_token, script=script,
                           manager_url=base)


@agent_installer_bp.get("/install/windows/<org_token>")
def windows_guide(org_token: str):
    org = _get_org_or_404(org_token)
    script = _build_windows_ps(org, _server_base_url())
    return render_template("install/install_windows.html",
                           org=org, org_token=org_token,
                           manager_url=_server_base_url())


@agent_installer_bp.get("/install/macos/<org_token>")
def macos_guide(org_token: str):
    org = _get_org_or_404(org_token)
    script = _build_macos_sh(org, _server_base_url())
    return render_template("install/install_mac.html",
                           org=org, org_token=org_token, script=script,
                           manager_url=_server_base_url())


@agent_installer_bp.get("/install/firewall/<org_token>")
def firewall_guide(org_token: str):
    org = _get_org_or_404(org_token)
    script = _build_linux_sh(org, _server_base_url())
    return render_template("install/install_firewall.html",
                           org=org, org_token=org_token, script=script)


@agent_installer_bp.get("/install/cloud/<org_token>")
def cloud_guide(org_token: str):
    org = _get_org_or_404(org_token)
    script = _build_linux_sh(org, _server_base_url())
    return render_template("install/install_cloud.html",
                           org=org, org_token=org_token, script=script)


@agent_installer_bp.get("/install/android")
def android_guide():
    return render_template("install/install_android.html")


# =====================================================
# Dynamic Python Agent Client (Option B)
# =====================================================
@agent_installer_bp.get("/install/agent/client/<org_token>")
def serve_agent_client(org_token: str):
    org = _get_org_or_404(org_token)
    base = _server_base_url()

    client_py = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"TenshiGuard unified Agent (Linux/Windows/macOS)
        - Registers device
        - Sends heartbeats every 2s (Real-time)
        - Streams login/logout events immediately
        - Monitors file system for new executables
        \"\"\"
        import os, time, socket, uuid, threading, subprocess, platform, shutil, sys
        from datetime import datetime, timezone

        import requests
        try:
            import psutil
        except ImportError:
            psutil = None

        # Watchdog for file monitoring
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            Observer = None
            FileSystemEventHandler = object

        SERVER = "{base}"
        ORG_TOKEN = "{org.agent_token}"
        HEARTBEAT_INTERVAL = 2  # Real-time feedback

        # ------------------ Helpers ------------------
        def log(msg):
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            line = f"[agent] {{now}} :: {{msg}}"
            print(line, flush=True)
            try:
                # Simple file logging for debugging
                log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.log")
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\\n")
            except:
                pass

        def mac_address():
            try:
                mac = uuid.getnode()
                parts = []
                for ele in range(40, -8, -8):
                    parts.append(f"{{(mac >> ele) & 0xff:02x}}")
                return ":".join(parts)
            except Exception:
                return "unknown"

        def get_ip():
            # Best-effort outward IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                try:
                    return socket.gethostbyname(socket.gethostname())
                except Exception:
                    return "0.0.0.0"

        def system_info():
            return {{
                "hostname": platform.node(),
                "os": f"{{platform.system()}} {{platform.release()}}",
                "ip": get_ip(),
                "mac": mac_address(),
            }}

        def post(path, payload):
            url = f"{{SERVER}}{{path}}"
            try:
                r = requests.post(url, json=payload, timeout=2) # Fast timeout for real-time
                return r.status_code, r.text
            except Exception as e:
                # log(f"post error: {{e}}") # Reduce noise
                return 0, str(e)

        # -------------- Metrics ----------------
        def gather_stats():
            cpu = mem = 0.0
            if psutil:
                try:
                    cpu = psutil.cpu_percent(interval=None) # Non-blocking
                    mem = psutil.virtual_memory().percent
                except Exception:
                    cpu = mem = 0.0
            return cpu, mem

        # -------------- API calls --------------
        def register():
            info = system_info()
            cpu, mem = gather_stats()
            payload = {{
                "org_token": ORG_TOKEN,
                "hostname": info["hostname"],
                "mac": info["mac"],
                "os": info["os"],
                "ip": info["ip"],
                "cpu_percent": cpu,
                "mem_percent": mem,
                "agent_version": "1.0.0",
                "ts": datetime.now(timezone.utc).isoformat(),
            }}
            code, body = post("/api/agent/register", payload)
            log(f"register -> {{code}}")
            return code

        def heartbeat():
            info = system_info()
            cpu, mem = gather_stats()
            payload = {{
                "org_token": ORG_TOKEN,
                "hostname": info["hostname"],
                "mac": info["mac"],
                "os": info["os"],
                "ip": info["ip"],
                "cpu_percent": cpu,
                "mem_percent": mem,
                "status": "online",
                "agent_version": "1.0.0",
                "ts": datetime.now(timezone.utc).isoformat(),
            }}
            code, body = post("/api/agent/heartbeat", payload)
            # log(f"heartbeat -> {{code}}") # Too noisy for 2s
            return code

        def send_event(category, action, detail, severity="medium"):
            info = system_info()
            payload = {{
                "org_token": ORG_TOKEN,
                "mac": info["mac"],
                "category": category,
                "action": action,
                "detail": detail,
                "severity": severity,
                "ts": datetime.now(timezone.utc).isoformat(),
            }}
            # UPDATED: Send to the AI ingest endpoint which handles generic events too
            code, body = post("/api/agent/ai/event", payload)
            log(f"event({{category}}/{{action}}) -> {{code}}")
            return code

        # -------------- File Monitoring (Watchdog) --------------
        class ExecutableHandler(FileSystemEventHandler):
            def on_created(self, event):
                if event.is_directory:
                    return
                self._check(event.src_path, "created")

            def on_moved(self, event):
                if event.is_directory:
                    return
                self._check(event.dest_path, "moved/renamed")

            def _check(self, filepath, action):
                # Filter out noisy system paths
                lower_path = filepath.lower()
                if "windows\\\\servicing" in lower_path or "windows\\\\winsxs" in lower_path or "appdata\\\\local\\\\temp" in lower_path:
                    return

                ext = os.path.splitext(lower_path)[1]
                if ext in ['.exe', '.bat', '.ps1', '.msi', '.vbs', '.com']:
                    log(f"New executable detected: {{filepath}}")
                    send_event("file", "created", f"New executable detected: {{filepath}} ({{action}})", "medium")

        def start_file_watcher():
            if not Observer:
                log("Watchdog library not found. File monitoring disabled.")
                return

            log("Starting File System Monitor (Executables)...")
            observer = Observer()
            handler = ExecutableHandler()

            # Detect fixed drives
            drives = []
            if platform.system() == 'Windows':
                try:
                    import string
                    from ctypes import windll
                    drives = []
                    bitmask = windll.kernel32.GetLogicalDrives()
                    for letter in string.ascii_uppercase:
                        if bitmask & 1:
                            drives.append(f"{{letter}}:\\\\")
                        bitmask >>= 1
                except:
                    drives = ["C:\\"]
            else:
                drives = ["/"]

            for drive in drives:
                if os.path.exists(drive):
                    try:
                        # Recursive watch on root of drive
                        observer.schedule(handler, drive, recursive=True)
                        log(f"Watching drive: {{drive}}")
                    except Exception as e:
                        log(f"Failed to watch {{drive}}: {{e}}")

            observer.start()

        # -------------- Auth Monitoring (Cross-Platform) --------------
        
        def tail_linux_auth():
            \"\"\"Stream journald or auth.log for Linux\"\"\"
            cmd = None
            source = None

            if shutil.which("journalctl"):
                cmd = ["journalctl", "-f", "-n", "0", "-u", "ssh", "-u", "sshd", "_COMM=sshd", "_COMM=login", "_COMM=sudo"]
                source = "journald"
            elif os.path.exists("/var/log/auth.log"):
                cmd = ["tail", "-n", "0", "-F", "/var/log/auth.log"]
                source = "/var/log/auth.log"
            elif os.path.exists("/var/log/secure"): # RHEL/CentOS
                cmd = ["tail", "-n", "0", "-F", "/var/log/secure"]
                source = "/var/log/secure"

            if not cmd:
                log("No auth log source found (journald/auth.log/secure).")
                return

            log(f"Watching {{source}} for auth events...")
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Keywords for detection
                fail_patterns = ["Failed password", "authentication failure", "Invalid user"]
                success_patterns = ["Accepted password", "session opened for user"]
                logout_patterns = ["session closed for user", "pam_unix(sshd:session): session closed"]

                for line in iter(proc.stdout.readline, ""):
                    line = line.strip()
                    if not line: continue

                    if any(p in line for p in fail_patterns):
                        send_event("auth", "failed_login", line, "medium")
                    elif any(p in line for p in success_patterns):
                        send_event("auth", "login", line, "info")
                    elif any(p in line for p in logout_patterns):
                        send_event("auth", "logout", line, "info")
            except Exception as e:
                log(f"Linux auth watcher failed: {{e}}")

        def is_admin():
            try:
                if platform.system().lower() == 'windows':
                    import ctypes
                    return ctypes.windll.shell32.IsUserAnAdmin() != 0
                else:
                    return os.geteuid() == 0
            except:
                return False

        def tail_windows_events():
            '''Stream Windows Event Log via PowerShell (Robust RecordId Tailing)'''
            if not is_admin():
                log("Running as non-admin: Windows Security Log monitoring disabled.")
                send_event("agent", "error", "Running as non-admin. Security Log monitoring disabled.", "high")
                return

            log("Watching Windows Security Event Log (RecordId Tailing)...")
            
            # 1. Get initial baseline (latest event RecordId)
            # Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4625 or EventID=4647)]]" -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object RecordId | ConvertTo-Json
            startup_b64 = "RwBlAHQALQBXAGkAbgBFAHYAZQBuAHQAIAAtAEwAbwBnAE4AYQBtAGUAIABTAGUAYwB1AHIAaQB0AHkAIAAtAEYAaQBsAHQAZQByAFgAUABhAHQAaAAgACIAKgBbAFMAeQBzAHQAZQBtAFsAKABFAHYAZQBuAHQASQBEAD0ANAA2ADIANAAgAG8AcgAgAEUAdgBlAG4AdABJAEQAPQA0ADYAMgA1ACAAbwByACAARQB2AGUAbgB0AEkARAA9ADQANgA0ADcAKQBdAF0AIgAgAC0ATQBhAHgARQB2AGUAbgB0AHMAIAAxACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuAA=="
            
            last_record_id = 0
            try:
                out = subprocess.check_output(["powershell", "-EncodedCommand", startup_b64], text=True).strip()
                if out:
                    import json
                    try:
                        data = json.loads(out)
                        if isinstance(data, dict):
                            last_record_id = int(data.get("RecordId", 0))
                        elif isinstance(data, list) and len(data) > 0:
                            last_record_id = int(data[0].get("RecordId", 0))
                    except:
                        pass
            except:
                pass
                
            log(f"Starting event tail from RecordId > {{last_record_id}}")

            # 2. Polling Loop
            # Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4625 or EventID=4647)]]" -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object RecordId, Id, Message, TimeCreated | ConvertTo-Json
            poll_b64 = "RwBlAHQALQBXAGkAbgBFAHYAZQBuAHQAIAAtAEwAbwBnAE4AYQBtAGUAIABTAGUAYwB1AHIAaQB0AHkAIAAtAEYAaQBsAHQAZQByAFgAUABhAHQAaAAgACIAKgBbAFMAeQBzAHQAZQBtAFsAKABFAHYAZQBuAHQASQBEAD0ANAA2ADIANAAgAG8AcgAgAEUAdgBlAG4AdABJAEQAPQA0ADYAMgA1ACAAbwByACAARQB2AGUAbgB0AEkARAA9ADQANgA0ADcAKQBdAF0AIgAgAC0ATQBhAHgARQB2AGUAbgB0AHMAIAAxADAAIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAFIAZQBjAG8AcgBkAEkAZAAsACAASQBkACwAIABNAGUAcwBzAGEAZwBlACwAIABUAGkAbQBlAEMAcgBlAGEAdABlAGQAIAB8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuAA=="
            cmd = ["powershell", "-EncodedCommand", poll_b64]

            while True:
                try:
                    out = subprocess.check_output(cmd, text=True).strip()
                    if out:
                        import json
                        try:
                            data = json.loads(out)
                            if isinstance(data, dict): data = [data]
                            
                            # Sort by RecordId ascending to process in order
                            data.sort(key=lambda x: x.get("RecordId", 0))

                            for event in data:
                                rid = int(event.get("RecordId", 0))
                                if rid <= last_record_id:
                                    continue
                                
                                last_record_id = rid
                                eid = event.get("Id")
                                msg = event.get("Message", "")[:200]
                                
                                if eid == 4624:
                                    if "Advapi" not in msg and "SYSTEM" not in msg: 
                                        send_event("auth", "login", f"Windows Logon: {{msg}}", "info")
                                elif eid == 4625:
                                    send_event("auth", "failed_login", f"Windows Failed Logon: {{msg}}", "medium")
                                elif eid == 4647:
                                    send_event("auth", "logout", f"Windows Logoff: {{msg}}", "info")
                                    
                        except json.JSONDecodeError:
                            pass
                except subprocess.CalledProcessError:
                    pass
                    
                time.sleep(2)

        def start_auth_watcher():
            sys_plat = platform.system().lower()
            if "linux" in sys_plat or "darwin" in sys_plat: # macOS is similar to Linux (uses unified log, but tailing works for some things)
                # For macOS specifically, 'log stream' is better, but let's stick to linux tail for now as fallback
                # If macOS, we might need a specific handler.
                if "darwin" in sys_plat:
                    # macOS 'log stream' TODO
                    pass 
                else:
                    threading.Thread(target=tail_linux_auth, daemon=True).start()
            elif "windows" in sys_plat:
                threading.Thread(target=tail_windows_events, daemon=True).start()

        # -------------- Main loop --------------
        def main():
            log(f"Starting TenshiGuard Agent v1.0.0 on {{platform.system()}}...")
            
            # Initial Register
            code = register()
            if code not in (200, 201):
                log("Initial register failed; will retry in loop")

            # Start Event Monitoring
            start_auth_watcher()
            start_file_watcher()

            # Heartbeat Loop
            while True:
                code = heartbeat()
                if code == 404:
                    log("Heartbeat 404: Device not found. Re-registering...")
                    register()
                
                time.sleep(HEARTBEAT_INTERVAL)

        if __name__ == "__main__":
            main()
    """)

    return _py(client_py)


# =====================================================
# Raw uninstall helper (standalone URL)
# =====================================================
@agent_installer_bp.get("/install/agent/uninstall.sh")
def uninstall_sh():
    sh = textwrap.dedent("""\
        #!/usr/bin/env bash
        set -e
        echo "==========================================="
        echo " 🚫 Uninstalling TenshiGuard Agent"
        echo "==========================================="
        sudo systemctl stop tenshiguard-agent || true
        sudo systemctl disable tenshiguard-agent || true
        sudo rm -f /etc/systemd/system/tenshiguard-agent.service
        sudo systemctl daemon-reload
        sudo rm -rf /opt/tenshiguard
        echo "✅ TenshiGuard Agent fully removed."
    """)
    return _sh(sh)
