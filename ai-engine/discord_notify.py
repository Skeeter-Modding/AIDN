#!/usr/bin/env python3
"""
AIDN Discord Webhook Notifications
Sends real-time alerts to Discord for attacks, bans, and security events

Features:
- Rich embeds with attack details
- Severity-based color coding
- Rate limiting to prevent spam
- Batch notifications for mass events
"""

import json
import time
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import logging

logger = logging.getLogger("AIDN-Discord")

# Embed colors (Discord uses decimal color values)
COLORS = {
    'critical': 0xFF0000,   # Red
    'high': 0xFF6600,       # Orange
    'medium': 0xFFCC00,     # Yellow
    'low': 0x00CCFF,        # Light Blue
    'info': 0x00FF00,       # Green
    'blocked': 0xFF0000,    # Red
    'rate_limited': 0xFFCC00,  # Yellow
    'whitelisted': 0x00FF00,   # Green
    'learning': 0x9900FF,   # Purple
}

# Emoji for different event types
EMOJIS = {
    'attack': '🚨',
    'blocked': '🛑',
    'rate_limited': '⚠️',
    'whitelisted': '✅',
    'unblocked': '🔓',
    'learning': '📊',
    'startup': '🚀',
    'shutdown': '🔴',
    'warning': '⚠️',
    'info': 'ℹ️',
}


@dataclass
class DiscordNotification:
    """A notification to be sent to Discord"""
    title: str
    description: str
    color: int = COLORS['info']
    fields: List[Dict] = field(default_factory=list)
    footer: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    thumbnail_url: str = ""
    priority: int = 0  # Higher = more important


class DiscordRateLimiter:
    """Rate limiter to prevent Discord API abuse"""

    def __init__(self, max_per_minute: int = 30, max_per_hour: int = 500):
        self.max_per_minute = max_per_minute
        self.max_per_hour = max_per_hour
        self.minute_window: List[float] = []
        self.hour_window: List[float] = []
        self.lock = threading.Lock()

    def can_send(self) -> bool:
        """Check if we can send a notification"""
        now = time.time()

        with self.lock:
            # Clean old entries
            minute_ago = now - 60
            hour_ago = now - 3600

            self.minute_window = [t for t in self.minute_window if t > minute_ago]
            self.hour_window = [t for t in self.hour_window if t > hour_ago]

            # Check limits
            if len(self.minute_window) >= self.max_per_minute:
                return False
            if len(self.hour_window) >= self.max_per_hour:
                return False

            return True

    def record_send(self):
        """Record that a notification was sent"""
        now = time.time()
        with self.lock:
            self.minute_window.append(now)
            self.hour_window.append(now)


class DiscordNotifier:
    """
    Discord webhook notification system for AIDN
    """

    def __init__(self, webhook_url: str, server_name: str = "AIDN Server"):
        self.webhook_url = webhook_url
        self.server_name = server_name
        self.enabled = bool(webhook_url)

        # Rate limiting
        self.rate_limiter = DiscordRateLimiter()

        # Notification queue for batching
        self.queue: queue.Queue = queue.Queue()
        self.batch_interval = 5  # Batch notifications every 5 seconds

        # Deduplication
        self.recent_notifications: Dict[str, float] = {}
        self.dedup_window = 60  # Ignore duplicate notifications within 60 seconds

        # Start background worker
        if self.enabled:
            self._start_worker()

    def _start_worker(self):
        """Start background notification worker"""
        worker = threading.Thread(target=self._worker_loop, daemon=True)
        worker.start()

    def _worker_loop(self):
        """Background worker that sends batched notifications"""
        while True:
            try:
                notifications = []

                # Wait for first notification
                try:
                    notif = self.queue.get(timeout=self.batch_interval)
                    notifications.append(notif)
                except queue.Empty:
                    continue

                # Collect more notifications in batch window
                batch_end = time.time() + 1  # 1 second batch window
                while time.time() < batch_end:
                    try:
                        notif = self.queue.get_nowait()
                        notifications.append(notif)
                    except queue.Empty:
                        break

                # Send batched notifications
                if notifications:
                    self._send_batch(notifications)

            except Exception as e:
                logger.error(f"Discord worker error: {e}")
                time.sleep(5)

    def _send_batch(self, notifications: List[DiscordNotification]):
        """Send a batch of notifications"""
        if not self.rate_limiter.can_send():
            logger.warning("Discord rate limit reached, dropping notifications")
            return

        # Sort by priority and take top 10
        notifications.sort(key=lambda n: n.priority, reverse=True)
        notifications = notifications[:10]

        # Build embeds
        embeds = []
        for notif in notifications:
            embed = {
                "title": notif.title,
                "description": notif.description,
                "color": notif.color,
                "timestamp": notif.timestamp.isoformat(),
                "footer": {"text": notif.footer or f"AIDN • {self.server_name}"}
            }

            if notif.fields:
                embed["fields"] = notif.fields

            if notif.thumbnail_url:
                embed["thumbnail"] = {"url": notif.thumbnail_url}

            embeds.append(embed)

        # Send to Discord
        payload = {
            "username": "AIDN Defense",
            "avatar_url": "https://raw.githubusercontent.com/Skeeter-Modding/AIDN/main/docs/aidn-logo.png",
            "embeds": embeds
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            urlopen(req, timeout=10)
            self.rate_limiter.record_send()
            logger.debug(f"Sent {len(embeds)} Discord notification(s)")

        except HTTPError as e:
            logger.error(f"Discord webhook HTTP error: {e.code}")
        except URLError as e:
            logger.error(f"Discord webhook URL error: {e.reason}")
        except Exception as e:
            logger.error(f"Discord webhook error: {e}")

    def _should_send(self, dedup_key: str) -> bool:
        """Check if notification should be sent (deduplication)"""
        now = time.time()

        # Clean old entries
        self.recent_notifications = {
            k: v for k, v in self.recent_notifications.items()
            if now - v < self.dedup_window
        }

        # Check if recent duplicate
        if dedup_key in self.recent_notifications:
            return False

        self.recent_notifications[dedup_key] = now
        return True

    def _queue_notification(self, notification: DiscordNotification, dedup_key: str = None):
        """Queue a notification for sending"""
        if not self.enabled:
            return

        if dedup_key and not self._should_send(dedup_key):
            return

        self.queue.put(notification)

    # =========================================================================
    # Public API - Notification Methods
    # =========================================================================

    def notify_attack_detected(self, attack_type: str, severity: str,
                                source_ip: str, pps: int, details: str = ""):
        """Notify about a detected attack"""
        color = COLORS.get(severity, COLORS['medium'])
        emoji = EMOJIS['attack']

        notif = DiscordNotification(
            title=f"{emoji} Attack Detected: {attack_type}",
            description=f"A **{severity.upper()}** severity attack has been detected.",
            color=color,
            fields=[
                {"name": "Attack Type", "value": attack_type, "inline": True},
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
                {"name": "Traffic Rate", "value": f"{pps:,} pps", "inline": True},
            ],
            priority=10 if severity in ['critical', 'high'] else 5
        )

        if details:
            notif.fields.append({"name": "Details", "value": details, "inline": False})

        self._queue_notification(notif, f"attack:{source_ip}:{attack_type}")

    def notify_ip_blocked(self, ip: str, reason: str, duration: int,
                          attack_type: str = None, confidence: float = None):
        """Notify about an IP being blocked"""
        emoji = EMOJIS['blocked']

        # Format duration
        if duration >= 86400:
            duration_str = f"{duration // 86400} day(s)"
        elif duration >= 3600:
            duration_str = f"{duration // 3600} hour(s)"
        else:
            duration_str = f"{duration // 60} minute(s)"

        notif = DiscordNotification(
            title=f"{emoji} IP Blocked",
            description=f"An IP address has been blocked due to malicious activity.",
            color=COLORS['blocked'],
            fields=[
                {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "Duration", "value": duration_str, "inline": True},
                {"name": "Reason", "value": reason, "inline": False},
            ],
            priority=8
        )

        if attack_type:
            notif.fields.append({"name": "Attack Type", "value": attack_type, "inline": True})

        if confidence:
            notif.fields.append({"name": "Confidence", "value": f"{confidence:.1%}", "inline": True})

        self._queue_notification(notif, f"block:{ip}")

    def notify_ip_rate_limited(self, ip: str, current_pps: int, limit_pps: int):
        """Notify about an IP being rate limited"""
        emoji = EMOJIS['rate_limited']

        notif = DiscordNotification(
            title=f"{emoji} IP Rate Limited",
            description=f"An IP is being rate limited due to excessive traffic.",
            color=COLORS['rate_limited'],
            fields=[
                {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "Current Rate", "value": f"{current_pps:,} pps", "inline": True},
                {"name": "Limit", "value": f"{limit_pps:,} pps", "inline": True},
            ],
            priority=3
        )

        self._queue_notification(notif, f"ratelimit:{ip}")

    def notify_ip_whitelisted(self, ip: str, reason: str = "Auto-trusted"):
        """Notify about an IP being whitelisted"""
        emoji = EMOJIS['whitelisted']

        notif = DiscordNotification(
            title=f"{emoji} IP Whitelisted",
            description=f"An IP address has been added to the whitelist.",
            color=COLORS['whitelisted'],
            fields=[
                {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "Reason", "value": reason, "inline": True},
            ],
            priority=2
        )

        self._queue_notification(notif, f"whitelist:{ip}")

    def notify_ip_unblocked(self, ip: str, reason: str = "Ban expired"):
        """Notify about an IP being unblocked"""
        emoji = EMOJIS['unblocked']

        notif = DiscordNotification(
            title=f"{emoji} IP Unblocked",
            description=f"An IP address has been removed from the blocklist.",
            color=COLORS['info'],
            fields=[
                {"name": "IP Address", "value": f"`{ip}`", "inline": True},
                {"name": "Reason", "value": reason, "inline": True},
            ],
            priority=1
        )

        self._queue_notification(notif)

    def notify_attack_mitigated(self, attack_type: str, duration: int,
                                 blocked_ips: int, peak_pps: int):
        """Notify that an attack has been mitigated"""
        emoji = EMOJIS['info']

        # Format duration
        if duration >= 3600:
            duration_str = f"{duration // 3600}h {(duration % 3600) // 60}m"
        else:
            duration_str = f"{duration // 60}m {duration % 60}s"

        notif = DiscordNotification(
            title=f"{emoji} Attack Mitigated",
            description=f"An attack has been successfully mitigated.",
            color=COLORS['info'],
            fields=[
                {"name": "Attack Type", "value": attack_type, "inline": True},
                {"name": "Duration", "value": duration_str, "inline": True},
                {"name": "IPs Blocked", "value": str(blocked_ips), "inline": True},
                {"name": "Peak Traffic", "value": f"{peak_pps:,} pps", "inline": True},
            ],
            priority=7
        )

        self._queue_notification(notif)

    def notify_system_status(self, status: str, message: str):
        """Notify about system status changes"""
        if status == "startup":
            emoji = EMOJIS['startup']
            color = COLORS['info']
            title = f"{emoji} AIDN Started"
        elif status == "shutdown":
            emoji = EMOJIS['shutdown']
            color = COLORS['medium']
            title = f"{emoji} AIDN Stopped"
        elif status == "learning":
            emoji = EMOJIS['learning']
            color = COLORS['learning']
            title = f"{emoji} Learning Mode"
        else:
            emoji = EMOJIS['info']
            color = COLORS['info']
            title = f"{emoji} System Status"

        notif = DiscordNotification(
            title=title,
            description=message,
            color=color,
            priority=6 if status == "startup" else 4
        )

        self._queue_notification(notif)

    def notify_stats_summary(self, stats: Dict):
        """Send periodic stats summary"""
        emoji = EMOJIS['info']

        notif = DiscordNotification(
            title=f"{emoji} AIDN Status Summary",
            description=f"Current protection status for **{self.server_name}**",
            color=COLORS['info'],
            fields=[
                {"name": "Traffic", "value": f"{stats.get('pps', 0):,} pps", "inline": True},
                {"name": "Blocked IPs", "value": str(stats.get('blocked_ips', 0)), "inline": True},
                {"name": "Whitelisted", "value": str(stats.get('whitelisted_ips', 0)), "inline": True},
                {"name": "Attacks Today", "value": str(stats.get('attacks_today', 0)), "inline": True},
                {"name": "Attack Level", "value": stats.get('attack_level', 'None').upper(), "inline": True},
                {"name": "Uptime", "value": stats.get('uptime', 'Unknown'), "inline": True},
            ],
            priority=1
        )

        self._queue_notification(notif)

    def send_test(self) -> bool:
        """Send a test notification to verify webhook works"""
        if not self.enabled:
            return False

        notif = DiscordNotification(
            title="🧪 AIDN Test Notification",
            description="This is a test notification from AIDN. If you see this, Discord notifications are working correctly!",
            color=COLORS['info'],
            fields=[
                {"name": "Server", "value": self.server_name, "inline": True},
                {"name": "Status", "value": "✅ Connected", "inline": True},
            ],
            priority=10
        )

        # Send immediately (bypass queue for test)
        self._send_batch([notif])
        return True


# ============================================================================
# Standalone notification functions for shell scripts
# ============================================================================

def send_discord_notification(webhook_url: str, title: str, message: str,
                               color: str = "info", fields: Dict = None):
    """
    Send a single Discord notification (for use from shell scripts)

    Args:
        webhook_url: Discord webhook URL
        title: Notification title
        message: Notification message
        color: Color name (critical, high, medium, low, info)
        fields: Optional dict of field_name: field_value
    """
    if not webhook_url:
        return False

    embed = {
        "title": title,
        "description": message,
        "color": COLORS.get(color, COLORS['info']),
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": "AIDN Defense System"}
    }

    if fields:
        embed["fields"] = [
            {"name": k, "value": str(v), "inline": True}
            for k, v in fields.items()
        ]

    payload = {
        "username": "AIDN Defense",
        "embeds": [embed]
    }

    try:
        data = json.dumps(payload).encode('utf-8')
        req = Request(
            webhook_url,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        urlopen(req, timeout=10)
        return True
    except Exception as e:
        logger.error(f"Failed to send Discord notification: {e}")
        return False


def main():
    """CLI for testing Discord notifications"""
    import argparse

    parser = argparse.ArgumentParser(description="AIDN Discord Notifications")
    parser.add_argument('--webhook', required=True, help="Discord webhook URL")
    parser.add_argument('--test', action='store_true', help="Send test notification")
    parser.add_argument('--title', help="Notification title")
    parser.add_argument('--message', help="Notification message")
    parser.add_argument('--color', default='info', help="Color (critical/high/medium/low/info)")

    args = parser.parse_args()

    if args.test:
        notifier = DiscordNotifier(args.webhook, "Test Server")
        if notifier.send_test():
            print("✅ Test notification sent successfully!")
        else:
            print("❌ Failed to send test notification")
    elif args.title and args.message:
        if send_discord_notification(args.webhook, args.title, args.message, args.color):
            print("✅ Notification sent!")
        else:
            print("❌ Failed to send notification")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
