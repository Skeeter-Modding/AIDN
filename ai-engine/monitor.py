#!/usr/bin/env python3
"""
AIDN Real-Time Monitoring Dashboard
Provides live visibility into DDoS defense status

Features:
- Real-time traffic statistics
- Attack detection alerts
- Player trust visualization
- System health monitoring
"""

import os
import sys
import time
import json
import curses
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import deque
import socket
import struct


@dataclass
class TrafficStats:
    """Current traffic statistics"""
    packets_per_second: int = 0
    bytes_per_second: int = 0
    active_connections: int = 0
    blocked_ips: int = 0
    rate_limited_ips: int = 0
    whitelisted_ips: int = 0
    attack_level: str = "none"  # none, low, medium, high, critical
    top_sources: List[tuple] = field(default_factory=list)


@dataclass
class Alert:
    """Security alert"""
    timestamp: datetime
    severity: str  # info, warning, critical
    message: str
    ip_address: Optional[str] = None


class StatsCollector:
    """Collects statistics from XDP and AI engine"""

    def __init__(self):
        self.stats = TrafficStats()
        self.alerts: deque = deque(maxlen=100)
        self.history: deque = deque(maxlen=3600)  # 1 hour of history

        # BPF map paths
        self.bpf_stats_path = "/sys/fs/bpf/aidn/stats"
        self.bpf_whitelist_path = "/sys/fs/bpf/aidn/whitelist"
        self.bpf_blacklist_path = "/sys/fs/bpf/aidn/blacklist"

    def update(self):
        """Update statistics from system"""
        # Read from /proc/net for network stats
        self._read_network_stats()

        # Read from BPF maps if available
        self._read_bpf_stats()

        # Record history point
        self.history.append({
            'timestamp': time.time(),
            'pps': self.stats.packets_per_second,
            'bps': self.stats.bytes_per_second,
            'attack_level': self.stats.attack_level
        })

    def _read_network_stats(self):
        """Read network statistics from /proc"""
        try:
            with open('/proc/net/dev') as f:
                lines = f.readlines()

            for line in lines[2:]:  # Skip headers
                parts = line.split()
                if len(parts) >= 10:
                    iface = parts[0].rstrip(':')
                    if iface not in ('lo', 'docker0'):
                        # rx_bytes rx_packets
                        self.stats.bytes_per_second = int(parts[1])
                        self.stats.packets_per_second = int(parts[2])
                        break
        except Exception:
            pass

    def _read_bpf_stats(self):
        """Read statistics from BPF maps"""
        # This would read actual BPF map data
        # For now, check if maps exist
        if os.path.exists(self.bpf_stats_path):
            pass  # Read actual stats

    def add_alert(self, severity: str, message: str, ip: str = None):
        """Add a new alert"""
        alert = Alert(
            timestamp=datetime.now(),
            severity=severity,
            message=message,
            ip_address=ip
        )
        self.alerts.appendleft(alert)

    def get_attack_level(self) -> str:
        """Determine current attack level"""
        pps = self.stats.packets_per_second

        if pps >= 10000000:  # 10M pps
            return "critical"
        elif pps >= 1000000:  # 1M pps
            return "high"
        elif pps >= 100000:  # 100K pps
            return "medium"
        elif pps >= 10000:  # 10K pps
            return "low"
        return "none"


class Dashboard:
    """Terminal-based monitoring dashboard"""

    def __init__(self):
        self.collector = StatsCollector()
        self.running = False
        self.screen = None

        # Colors
        self.colors = {}

    def init_colors(self):
        """Initialize curses colors"""
        curses.start_color()
        curses.use_default_colors()

        curses.init_pair(1, curses.COLOR_GREEN, -1)   # OK
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # Warning
        curses.init_pair(3, curses.COLOR_RED, -1)     # Critical
        curses.init_pair(4, curses.COLOR_CYAN, -1)    # Info
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Header

        self.colors = {
            'ok': curses.color_pair(1),
            'warning': curses.color_pair(2),
            'critical': curses.color_pair(3),
            'info': curses.color_pair(4),
            'header': curses.color_pair(5)
        }

    def draw_header(self, y: int) -> int:
        """Draw dashboard header"""
        header = " AIDN - AI Defense Network Monitor "
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.screen.attron(self.colors['header'] | curses.A_BOLD)
        self.screen.addstr(y, 0, header.center(80))
        self.screen.attroff(self.colors['header'] | curses.A_BOLD)

        self.screen.addstr(y, 70, timestamp, self.colors['info'])

        return y + 2

    def draw_stats_box(self, y: int) -> int:
        """Draw traffic statistics box"""
        stats = self.collector.stats

        self.screen.addstr(y, 0, "=" * 80)
        y += 1
        self.screen.addstr(y, 0, " TRAFFIC STATISTICS", curses.A_BOLD)
        y += 1
        self.screen.addstr(y, 0, "=" * 80)
        y += 1

        # Format numbers with units
        pps = self._format_number(stats.packets_per_second) + " pps"
        bps = self._format_bytes(stats.bytes_per_second) + "/s"

        self.screen.addstr(y, 2, f"Packets/sec:  {pps:>15}")
        self.screen.addstr(y, 40, f"Bandwidth:  {bps:>15}")
        y += 1

        self.screen.addstr(y, 2, f"Active Conn:  {stats.active_connections:>15,}")
        self.screen.addstr(y, 40, f"Blocked IPs: {stats.blocked_ips:>15,}")
        y += 1

        self.screen.addstr(y, 2, f"Rate Limited: {stats.rate_limited_ips:>15,}")
        self.screen.addstr(y, 40, f"Whitelisted: {stats.whitelisted_ips:>15,}")
        y += 2

        return y

    def draw_attack_status(self, y: int) -> int:
        """Draw attack status indicator"""
        level = self.collector.get_attack_level()

        self.screen.addstr(y, 0, " ATTACK STATUS: ", curses.A_BOLD)

        if level == "none":
            color = self.colors['ok']
            status = "NORMAL"
        elif level == "low":
            color = self.colors['info']
            status = "LOW"
        elif level == "medium":
            color = self.colors['warning']
            status = "MEDIUM"
        elif level == "high":
            color = self.colors['warning'] | curses.A_BOLD
            status = "HIGH"
        else:  # critical
            color = self.colors['critical'] | curses.A_BOLD | curses.A_BLINK
            status = "CRITICAL"

        self.screen.addstr(y, 16, f" {status} ", color)
        y += 2

        return y

    def draw_alerts(self, y: int, max_height: int) -> int:
        """Draw recent alerts"""
        self.screen.addstr(y, 0, "=" * 80)
        y += 1
        self.screen.addstr(y, 0, " RECENT ALERTS", curses.A_BOLD)
        y += 1
        self.screen.addstr(y, 0, "=" * 80)
        y += 1

        alerts = list(self.collector.alerts)[:max_height - 3]

        if not alerts:
            self.screen.addstr(y, 2, "No alerts", self.colors['ok'])
            y += 1
        else:
            for alert in alerts:
                if y >= max_height - 1:
                    break

                if alert.severity == "critical":
                    color = self.colors['critical']
                elif alert.severity == "warning":
                    color = self.colors['warning']
                else:
                    color = self.colors['info']

                time_str = alert.timestamp.strftime("%H:%M:%S")
                msg = f"{time_str} [{alert.severity.upper():8}] {alert.message}"
                if alert.ip_address:
                    msg += f" ({alert.ip_address})"

                self.screen.addstr(y, 2, msg[:76], color)
                y += 1

        return y

    def draw_top_sources(self, y: int) -> int:
        """Draw top traffic sources"""
        self.screen.addstr(y, 0, "=" * 80)
        y += 1
        self.screen.addstr(y, 0, " TOP TRAFFIC SOURCES", curses.A_BOLD)
        y += 1
        self.screen.addstr(y, 0, "=" * 80)
        y += 1

        self.screen.addstr(y, 2, f"{'IP Address':<20} {'PPS':>12} {'BPS':>12} {'Status':>10}")
        y += 1
        self.screen.addstr(y, 0, "-" * 80)
        y += 1

        sources = self.collector.stats.top_sources[:10]
        if not sources:
            self.screen.addstr(y, 2, "No data available", self.colors['info'])
            y += 1
        else:
            for ip, pps, bps, status in sources:
                if status == "blocked":
                    color = self.colors['critical']
                elif status == "limited":
                    color = self.colors['warning']
                elif status == "trusted":
                    color = self.colors['ok']
                else:
                    color = curses.A_NORMAL

                self.screen.addstr(
                    y, 2,
                    f"{ip:<20} {self._format_number(pps):>12} "
                    f"{self._format_bytes(bps):>12} {status:>10}",
                    color
                )
                y += 1

        return y

    def draw_mini_graph(self, y: int, width: int = 60) -> int:
        """Draw ASCII traffic graph"""
        self.screen.addstr(y, 0, " TRAFFIC (last 60s)", curses.A_BOLD)
        y += 1

        # Get last 60 data points
        history = list(self.collector.history)[-60:]
        if len(history) < 2:
            self.screen.addstr(y, 0, "Collecting data...")
            return y + 1

        # Normalize to graph height
        pps_values = [h['pps'] for h in history]
        max_pps = max(pps_values) or 1
        graph_height = 5

        # Draw graph
        for row in range(graph_height):
            threshold = max_pps * (graph_height - row) / graph_height
            line = ""
            for pps in pps_values[-width:]:
                if pps >= threshold:
                    line += "█"
                elif pps >= threshold * 0.5:
                    line += "▄"
                else:
                    line += " "

            self.screen.addstr(y + row, 2, line, self.colors['info'])

        y += graph_height + 1

        # X-axis labels
        self.screen.addstr(y, 2, "-60s" + " " * (width - 8) + "now")
        y += 1

        return y

    def draw_help(self, y: int) -> int:
        """Draw help bar"""
        help_text = " q: Quit | r: Refresh | w: Whitelist IP | b: Blacklist IP | c: Clear alerts "
        self.screen.addstr(y, 0, help_text.center(80), self.colors['header'])
        return y + 1

    def _format_number(self, n: int) -> str:
        """Format large numbers with K/M/G suffix"""
        if n >= 1_000_000_000:
            return f"{n / 1_000_000_000:.1f}G"
        elif n >= 1_000_000:
            return f"{n / 1_000_000:.1f}M"
        elif n >= 1_000:
            return f"{n / 1_000:.1f}K"
        return str(n)

    def _format_bytes(self, b: int) -> str:
        """Format bytes with appropriate unit"""
        if b >= 1_000_000_000:
            return f"{b / 1_000_000_000:.1f} Gbps"
        elif b >= 1_000_000:
            return f"{b / 1_000_000:.1f} Mbps"
        elif b >= 1_000:
            return f"{b / 1_000:.1f} Kbps"
        return f"{b} bps"

    def run(self, screen):
        """Main dashboard loop"""
        self.screen = screen
        self.running = True

        # Setup
        curses.curs_set(0)  # Hide cursor
        self.screen.nodelay(True)  # Non-blocking input
        self.init_colors()

        # Start stats collector thread
        collector_thread = threading.Thread(target=self._collector_loop, daemon=True)
        collector_thread.start()

        while self.running:
            try:
                self.screen.clear()
                max_y, max_x = self.screen.getmaxyx()

                y = 0
                y = self.draw_header(y)
                y = self.draw_attack_status(y)
                y = self.draw_stats_box(y)

                if max_y > 25:
                    y = self.draw_mini_graph(y)

                if max_y > 35:
                    y = self.draw_top_sources(y)

                y = self.draw_alerts(y, max_y - 2)

                self.draw_help(max_y - 1)

                self.screen.refresh()

                # Handle input
                key = self.screen.getch()
                if key == ord('q'):
                    self.running = False
                elif key == ord('r'):
                    self.collector.update()

                time.sleep(0.5)  # Update every 500ms

            except curses.error:
                pass
            except KeyboardInterrupt:
                self.running = False

    def _collector_loop(self):
        """Background thread for stats collection"""
        while self.running:
            self.collector.update()
            time.sleep(1)


class WebDashboard:
    """Simple web-based dashboard API"""

    def __init__(self, port: int = 8080):
        self.port = port
        self.collector = StatsCollector()

    def get_stats_json(self) -> str:
        """Get current stats as JSON"""
        self.collector.update()

        return json.dumps({
            'timestamp': datetime.now().isoformat(),
            'traffic': {
                'pps': self.collector.stats.packets_per_second,
                'bps': self.collector.stats.bytes_per_second,
                'active_connections': self.collector.stats.active_connections
            },
            'protection': {
                'blocked_ips': self.collector.stats.blocked_ips,
                'rate_limited': self.collector.stats.rate_limited_ips,
                'whitelisted': self.collector.stats.whitelisted_ips,
                'attack_level': self.collector.get_attack_level()
            },
            'alerts': [
                {
                    'timestamp': a.timestamp.isoformat(),
                    'severity': a.severity,
                    'message': a.message,
                    'ip': a.ip_address
                }
                for a in list(self.collector.alerts)[:20]
            ]
        }, indent=2)


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AIDN Monitoring Dashboard")
    parser.add_argument('--web', action='store_true', help="Start web API")
    parser.add_argument('--port', type=int, default=8080, help="Web API port")
    parser.add_argument('--json', action='store_true', help="Output JSON stats")

    args = parser.parse_args()

    if args.json:
        dashboard = WebDashboard()
        print(dashboard.get_stats_json())
    elif args.web:
        print(f"Web dashboard would start on port {args.port}")
        # Would start HTTP server here
    else:
        # Terminal dashboard
        dashboard = Dashboard()
        curses.wrapper(dashboard.run)


if __name__ == "__main__":
    main()
