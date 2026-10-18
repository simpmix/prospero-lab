"""
Interactive HTML Audit Report & Security Dashboard Generator.
Generates an offline, single-file HTML report summarizing Prospero kernel attack surfaces,
IOCTL character devices, XOM mitigation findings, and Syzkaller grammar definitions.
"""

from pathlib import Path
from typing import Dict, Any, Optional
from prospero_lab.kernel.surface_auditor import KernelSurfaceAuditor


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProsperoLab // PS5 Systems Security Dashboard</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --accent-purple: #bc8cff;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .header h1 {
            margin: 0;
            font-size: 22px;
            font-weight: 600;
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .badge {
            background-color: rgba(88, 166, 255, 0.15);
            color: var(--accent-blue);
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 12px;
            border: 1px solid rgba(88, 166, 255, 0.3);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }
        .card .title {
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
            text-transform: uppercase;
            font-weight: 600;
        }
        .card .value {
            font-size: 26px;
            font-weight: 700;
            color: #fff;
        }
        .card.danger .value { color: var(--accent-red); }
        .card.warning .value { color: var(--accent-orange); }
        .card.success .value { color: var(--accent-green); }
        
        .tab-nav {
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }
        .tab-btn {
            background: none;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-muted);
            padding: 10px 16px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .tab-btn:hover {
            color: var(--text-main);
        }
        .tab-btn.active {
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
        }
        .search-box {
            width: 100%;
            padding: 10px 14px;
            background-color: #030407;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-main);
            font-size: 14px;
            margin-bottom: 16px;
        }
        .search-box:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
        }
        th, td {
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }
        th {
            background-color: #21262d;
            color: var(--text-muted);
            font-weight: 600;
        }
        tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        .tag {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .tag-ipc { background: #388bfd26; color: #58a6ff; }
        .tag-threading { background: #d2992226; color: #d29922; }
        .tag-memory { background: #bc8cff26; color: #bc8cff; }
        .tag-hardware { background: #f8514926; color: #f85149; }
        .tag-loader { background: #3fb95026; color: #3fb950; }

        pre {
            background-color: #030407;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            color: #79c0ff;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>
            <span>ProsperoLab Security Console</span>
            <span class="badge">PlayStation 5 / Prospero OS</span>
        </h1>
        <div style="font-size: 12px; color: var(--text-muted);">
            Engineered for Systems Security & Vulnerability Research
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="title">Monitored Syscalls</div>
            <div class="value">{{TOTAL_SYSCALLS}}</div>
        </div>
        <div class="card danger">
            <div class="title">High-Risk Targets</div>
            <div class="value">{{CRITICAL_TARGETS}}</div>
        </div>
        <div class="card warning">
            <div class="title">Hardware IOCTL Vectors</div>
            <div class="value">{{TOTAL_IOCTLS}}</div>
        </div>
        <div class="card success">
            <div class="title">BD-J Compliance Engine</div>
            <div class="value">Ready</div>
        </div>
    </div>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="switchTab('tab-syscalls')">System Calls</button>
        <button class="tab-btn" onclick="switchTab('tab-ioctls')">Hardware IOCTLs</button>
        <button class="tab-btn" onclick="switchTab('tab-syzkaller')">Syzkaller Grammar</button>
    </div>

    <!-- Tab 1: Syscalls -->
    <div id="tab-syscalls" class="tab-content">
        <input type="text" id="syscall-search" class="search-box" placeholder="Filter system calls by name, subsystem, or vulnerability class..." onkeyup="filterTable('syscall-search', 'table-syscalls')">
        <table id="table-syscalls">
            <thead>
                <tr>
                    <th style="width: 70px;">Syscall</th>
                    <th>Name</th>
                    <th>Subsystem</th>
                    <th>Vulnerability Class</th>
                    <th>Security Notes</th>
                </tr>
            </thead>
            <tbody>
                {{SYSCALL_ROWS}}
            </tbody>
        </table>
    </div>

    <!-- Tab 2: IOCTLs -->
    <div id="tab-ioctls" class="tab-content" style="display: none;">
        <input type="text" id="ioctl-search" class="search-box" placeholder="Filter IOCTL commands by device node or name..." onkeyup="filterTable('ioctl-search', 'table-ioctls')">
        <table id="table-ioctls">
            <thead>
                <tr>
                    <th>Command Code</th>
                    <th>Name</th>
                    <th>Device</th>
                    <th>Direction</th>
                    <th>Payload Size</th>
                    <th>Audit Details</th>
                </tr>
            </thead>
            <tbody>
                {{IOCTL_ROWS}}
            </tbody>
        </table>
    </div>

    <!-- Tab 3: Syzkaller -->
    <div id="tab-syzkaller" class="tab-content" style="display: none;">
        <pre><code>{{SYZKALLER_CODE}}</code></pre>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById(tabId).style.display = 'block';
            event.target.classList.add('active');
        }

        function filterTable(inputId, tableId) {
            const query = document.getElementById(inputId).value.toLowerCase();
            const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
            rows.forEach(r => {
                r.style.display = r.innerText.toLowerCase().includes(query) ? '' : 'none';
            });
        }
    </script>
</body>
</html>
"""


class DashboardGenerator:
    """
    Renders the security audit results into a multi-tab interactive HTML report.
    """

    def __init__(self, auditor: Optional[KernelSurfaceAuditor] = None):
        self.auditor = auditor or KernelSurfaceAuditor()

    def generate_html(self) -> str:
        report = self.auditor.audit_attack_surface()
        syzkaller_defs = self.auditor.generate_syzkaller_descriptions()

        # Render Syscalls
        sys_rows = []
        for t in report["critical_race_uaf_targets"]:
            sub = t["subsystem"]
            tag_class = f"tag tag-{sub}" if sub in ["ipc", "threading", "memory", "hardware", "loader"] else "tag"
            vuln_str = t.get("vuln_class") or "General Surface"
            sys_rows.append(
                f"<tr>"
                f"  <td><strong>#{t['num']}</strong></td>"
                f"  <td><code>{t['name']}</code></td>"
                f"  <td><span class='{tag_class}'>{sub}</span></td>"
                f"  <td style='color: var(--accent-red);'>{vuln_str}</td>"
                f"  <td style='color: var(--text-muted);'>{t['notes']}</td>"
                f"</tr>"
            )

        # Render IOCTLs
        ioctl_rows = []
        for i in report.get("hardware_ioctl_surface", []):
            ioctl_rows.append(
                f"<tr>"
                f"  <td><code>{i['code']}</code></td>"
                f"  <td><strong>{i['name']}</strong></td>"
                f"  <td><code>{i['device']}</code></td>"
                f"  <td><span class='tag'>{i['direction']}</span></td>"
                f"  <td>{i['size']} bytes</td>"
                f"  <td style='color: var(--text-muted);'>{i['notes']}</td>"
                f"</tr>"
            )

        html = (
            HTML_TEMPLATE
            .replace("{{TOTAL_SYSCALLS}}", str(report["total_monitored_syscalls"]))
            .replace("{{CRITICAL_TARGETS}}", str(len(report["critical_race_uaf_targets"])))
            .replace("{{TOTAL_IOCTLS}}", str(report.get("total_monitored_ioctls", len(ioctl_rows))))
            .replace("{{SYSCALL_ROWS}}", "\n".join(sys_rows))
            .replace("{{IOCTL_ROWS}}", "\n".join(ioctl_rows))
            .replace("{{SYZKALLER_CODE}}", syzkaller_defs.replace("<", "&lt;").replace(">", "&gt;"))
        )
        return html

    def write_report(self, target_path: Path) -> Path:
        target_path.write_text(self.generate_html(), encoding="utf-8")
        return target_path
