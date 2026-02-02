#!/usr/bin/env python3
"""
AIDN - AI Defense Network Engine
Real-time ML-based DDoS detection and mitigation

Features:
- Isolation Forest anomaly detection
- Player behavior learning (avoids false positives)
- Adaptive rate limiting
- Traffic fingerprinting
- Real-time threat assessment

Author: AIDN Project
License: Apache 2.0
"""

import os
import sys
import time
import json
import logging
import signal
import threading
import socket
import struct
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
import pickle

# ML imports
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Configuration
CONFIG_PATH = "/etc/aidn/ai-engine.conf"
DATA_PATH = "/var/lib/aidn"
LOG_PATH = "/var/log/aidn"
BPF_MAPS_PATH = "/sys/fs/bpf/aidn"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_PATH}/ai-engine.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AIDN-AI")


@dataclass
class TrafficFeatures:
    """Features extracted from traffic for ML analysis"""
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    avg_packet_size: float = 0.0
    syn_ratio: float = 0.0
    udp_ratio: float = 0.0
    port_diversity: float = 0.0
    packet_size_variance: float = 0.0
    inter_arrival_variance: float = 0.0
    connection_rate: float = 0.0
    payload_entropy: float = 0.0

    def to_array(self) -> np.ndarray:
        return np.array([
            self.packets_per_second,
            self.bytes_per_second,
            self.avg_packet_size,
            self.syn_ratio,
            self.udp_ratio,
            self.port_diversity,
            self.packet_size_variance,
            self.inter_arrival_variance,
            self.connection_rate,
            self.payload_entropy
        ])


@dataclass
class IPProfile:
    """Profile for tracking IP behavior over time"""
    ip_address: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    total_packets: int = 0
    total_bytes: int = 0
    total_connections: int = 0
    trust_score: float = 50.0  # 0-100, starts neutral
    anomaly_count: int = 0
    legitimate_sessions: int = 0
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    blacklist_expiry: Optional[datetime] = None
    recent_features: deque = field(default_factory=lambda: deque(maxlen=100))
    ports_accessed: Set[int] = field(default_factory=set)

    def update_trust(self, delta: float):
        """Update trust score with bounds"""
        self.trust_score = max(0.0, min(100.0, self.trust_score + delta))

    def is_trusted(self) -> bool:
        """Check if IP has earned trust through good behavior"""
        return self.trust_score >= 70.0 and self.legitimate_sessions >= 3

    def should_auto_whitelist(self) -> bool:
        """Check if IP should be auto-whitelisted"""
        age = (datetime.now() - self.first_seen).total_seconds()
        return (
            self.trust_score >= 85.0 and
            self.legitimate_sessions >= 10 and
            self.anomaly_count == 0 and
            age > 3600  # At least 1 hour of good behavior
        )


@dataclass
class ThreatAssessment:
    """Result of threat analysis for an IP"""
    ip_address: str
    threat_level: str  # "none", "low", "medium", "high", "critical"
    confidence: float  # 0.0 - 1.0
    anomaly_score: float
    reasons: List[str] = field(default_factory=list)
    recommended_action: str = "monitor"  # "monitor", "rate_limit", "challenge", "block"

    def should_block(self) -> bool:
        """Only block with high confidence to avoid false positives"""
        return (
            self.threat_level in ["high", "critical"] and
            self.confidence >= 0.85
        )

    def should_rate_limit(self) -> bool:
        return (
            self.threat_level in ["medium", "high"] and
            self.confidence >= 0.70
        )


class AdaptiveRateLimiter:
    """
    Adaptive rate limiting that learns normal traffic patterns
    Avoids false positives by adjusting limits based on learned baseline
    """

    def __init__(self):
        self.baseline_pps: float = 1000.0  # Packets per second baseline
        self.baseline_bps: float = 1000000.0  # Bytes per second baseline
        self.current_multiplier: float = 1.0
        self.learning_rate: float = 0.01
        self.history: deque = deque(maxlen=1000)
        self.attack_mode: bool = False

        # Per-protocol limits (learned over time)
        self.limits = {
            'tcp': {'pps': 5000, 'bps': 10000000},
            'udp': {'pps': 10000, 'bps': 50000000},  # Higher for game traffic
            'icmp': {'pps': 50, 'bps': 50000},
            'syn': {'pps': 200, 'bps': 100000},
        }

        # Game port special handling (very permissive for legitimate players)
        self.game_ports = set(range(2001, 2003)) | {17777, 19999}

    def update_baseline(self, current_pps: float, current_bps: float):
        """Update baseline using exponential moving average"""
        if not self.attack_mode:
            self.baseline_pps = (1 - self.learning_rate) * self.baseline_pps + \
                               self.learning_rate * current_pps
            self.baseline_bps = (1 - self.learning_rate) * self.baseline_bps + \
                               self.learning_rate * current_bps
            self.history.append((current_pps, current_bps, time.time()))

    def get_dynamic_limit(self, protocol: str, is_game_traffic: bool = False) -> Tuple[int, int]:
        """Get current rate limits adjusted for conditions"""
        base_limits = self.limits.get(protocol, self.limits['tcp'])

        # Game traffic gets 5x higher limits
        if is_game_traffic:
            multiplier = 5.0
        elif self.attack_mode:
            multiplier = 0.5  # Stricter during attacks
        else:
            multiplier = self.current_multiplier

        return (
            int(base_limits['pps'] * multiplier),
            int(base_limits['bps'] * multiplier)
        )

    def detect_attack_mode(self, current_pps: float) -> bool:
        """Detect if we're under attack based on traffic patterns"""
        if len(self.history) < 100:
            return False

        # Calculate standard deviation of recent traffic
        recent_pps = [h[0] for h in list(self.history)[-100:]]
        mean_pps = np.mean(recent_pps)
        std_pps = np.std(recent_pps)

        # Attack if current traffic is 5+ std deviations above mean
        if std_pps > 0 and (current_pps - mean_pps) / std_pps > 5:
            self.attack_mode = True
            return True

        # Or if traffic is 10x baseline
        if current_pps > self.baseline_pps * 10:
            self.attack_mode = True
            return True

        self.attack_mode = False
        return False


class TrafficAnalyzer:
    """
    Analyzes traffic patterns using ML to detect anomalies
    Focuses on avoiding false positives through confidence scoring
    """

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.training_data: List[np.ndarray] = []
        self.is_trained: bool = False
        self.min_training_samples: int = 1000

        # Contamination rate - expect very few anomalies in normal traffic
        # Low value = fewer false positives
        self.contamination = 0.001

        self._load_model()

    def _load_model(self):
        """Load pre-trained model if exists"""
        model_path = Path(DATA_PATH) / "anomaly_model.pkl"
        scaler_path = Path(DATA_PATH) / "scaler.pkl"

        if model_path.exists() and scaler_path.exists():
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.is_trained = True
                logger.info("Loaded pre-trained anomaly detection model")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

    def save_model(self):
        """Save trained model"""
        if not self.is_trained:
            return

        Path(DATA_PATH).mkdir(parents=True, exist_ok=True)
        model_path = Path(DATA_PATH) / "anomaly_model.pkl"
        scaler_path = Path(DATA_PATH) / "scaler.pkl"

        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        logger.info("Saved anomaly detection model")

    def add_training_sample(self, features: TrafficFeatures):
        """Add a sample of known-good traffic for training"""
        self.training_data.append(features.to_array())

        # Auto-train when enough samples collected
        if len(self.training_data) >= self.min_training_samples and not self.is_trained:
            self._train_model()

    def _train_model(self):
        """Train the anomaly detection model"""
        if len(self.training_data) < self.min_training_samples:
            logger.warning("Not enough training data")
            return

        logger.info(f"Training anomaly detection model with {len(self.training_data)} samples")

        X = np.array(self.training_data)
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
            warm_start=True  # Allow incremental training
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        self.save_model()
        logger.info("Model training complete")

    def analyze(self, features: TrafficFeatures) -> Tuple[float, float]:
        """
        Analyze traffic features and return (anomaly_score, confidence)

        anomaly_score: -1.0 to 1.0 (negative = more anomalous)
        confidence: 0.0 to 1.0 (how confident we are in the score)
        """
        if not self.is_trained:
            # In learning mode, be very permissive
            return 0.0, 0.0

        X = features.to_array().reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        # Get anomaly score (-1 = anomaly, 1 = normal)
        score = self.model.score_samples(X_scaled)[0]

        # Convert to 0-1 range where 1 = definitely anomalous
        anomaly_score = max(0.0, -score)

        # Confidence based on how extreme the score is
        confidence = min(1.0, abs(score) / 0.5)

        return anomaly_score, confidence

    def retrain_incremental(self, new_samples: List[TrafficFeatures]):
        """Incrementally update model with new known-good samples"""
        if not self.is_trained:
            for sample in new_samples:
                self.add_training_sample(sample)
            return

        # Add new samples and retrain
        for sample in new_samples:
            self.training_data.append(sample.to_array())

        # Keep training data bounded
        if len(self.training_data) > 100000:
            self.training_data = self.training_data[-100000:]

        self._train_model()


class PlayerBehaviorTracker:
    """
    Tracks legitimate player behavior to avoid false positives
    Players who exhibit consistent game-like behavior get trusted
    """

    def __init__(self):
        self.profiles: Dict[str, IPProfile] = {}
        self.session_patterns: Dict[str, List[dict]] = defaultdict(list)

        # Load saved profiles
        self._load_profiles()

    def _load_profiles(self):
        """Load saved player profiles"""
        profile_path = Path(DATA_PATH) / "player_profiles.json"
        if profile_path.exists():
            try:
                with open(profile_path) as f:
                    data = json.load(f)
                for ip, profile_data in data.items():
                    profile = IPProfile(ip_address=ip)
                    profile.trust_score = profile_data.get('trust_score', 50.0)
                    profile.legitimate_sessions = profile_data.get('legitimate_sessions', 0)
                    profile.anomaly_count = profile_data.get('anomaly_count', 0)
                    profile.is_whitelisted = profile_data.get('is_whitelisted', False)
                    self.profiles[ip] = profile
                logger.info(f"Loaded {len(self.profiles)} player profiles")
            except Exception as e:
                logger.warning(f"Failed to load profiles: {e}")

    def save_profiles(self):
        """Save player profiles"""
        Path(DATA_PATH).mkdir(parents=True, exist_ok=True)
        profile_path = Path(DATA_PATH) / "player_profiles.json"

        data = {}
        for ip, profile in self.profiles.items():
            data[ip] = {
                'trust_score': profile.trust_score,
                'legitimate_sessions': profile.legitimate_sessions,
                'anomaly_count': profile.anomaly_count,
                'is_whitelisted': profile.is_whitelisted,
                'total_packets': profile.total_packets,
                'total_connections': profile.total_connections
            }

        with open(profile_path, 'w') as f:
            json.dump(data, f, indent=2)

    def get_or_create_profile(self, ip: str) -> IPProfile:
        """Get existing profile or create new one"""
        if ip not in self.profiles:
            self.profiles[ip] = IPProfile(ip_address=ip)
        return self.profiles[ip]

    def record_activity(self, ip: str, packets: int, bytes_count: int,
                       ports: Set[int], is_game_traffic: bool):
        """Record activity for an IP"""
        profile = self.get_or_create_profile(ip)
        profile.last_seen = datetime.now()
        profile.total_packets += packets
        profile.total_bytes += bytes_count
        profile.ports_accessed.update(ports)

        # Game traffic increases trust
        if is_game_traffic:
            profile.update_trust(0.1)

        # Check for auto-whitelist
        if profile.should_auto_whitelist() and not profile.is_whitelisted:
            profile.is_whitelisted = True
            logger.info(f"Auto-whitelisted trusted player: {ip}")

    def record_legitimate_session(self, ip: str):
        """Record completion of a legitimate game session"""
        profile = self.get_or_create_profile(ip)
        profile.legitimate_sessions += 1
        profile.update_trust(5.0)  # Significant trust boost
        logger.debug(f"Legitimate session recorded for {ip}, trust: {profile.trust_score}")

    def record_anomaly(self, ip: str, severity: float):
        """Record anomalous behavior"""
        profile = self.get_or_create_profile(ip)
        profile.anomaly_count += 1
        profile.update_trust(-severity * 10)  # Reduce trust based on severity

    def is_known_player(self, ip: str) -> bool:
        """Check if IP is a known legitimate player"""
        profile = self.profiles.get(ip)
        return profile is not None and profile.is_trusted()

    def get_trust_score(self, ip: str) -> float:
        """Get trust score for IP"""
        profile = self.profiles.get(ip)
        return profile.trust_score if profile else 50.0


class ThreatIntelligence:
    """
    Combines all analysis to make threat decisions
    Prioritizes avoiding false positives for legitimate players
    """

    def __init__(self):
        self.analyzer = TrafficAnalyzer()
        self.rate_limiter = AdaptiveRateLimiter()
        self.player_tracker = PlayerBehaviorTracker()

        # Threat thresholds (tuned to minimize false positives)
        self.thresholds = {
            'anomaly_low': 0.3,
            'anomaly_medium': 0.5,
            'anomaly_high': 0.7,
            'anomaly_critical': 0.9,
            'min_confidence_for_action': 0.7,
            'min_confidence_for_block': 0.9
        }

    def assess_threat(self, ip: str, features: TrafficFeatures) -> ThreatAssessment:
        """
        Comprehensive threat assessment for an IP
        Returns assessment with recommended action
        """
        assessment = ThreatAssessment(
            ip_address=ip,
            threat_level="none",
            confidence=0.0,
            anomaly_score=0.0
        )

        # Check if known trusted player - be very lenient
        profile = self.player_tracker.profiles.get(ip)
        if profile:
            if profile.is_whitelisted:
                assessment.recommended_action = "allow"
                return assessment

            if profile.is_trusted():
                # Trusted players get benefit of doubt
                assessment.confidence *= 0.5  # Reduce confidence in anomaly

        # Get anomaly score from ML model
        anomaly_score, confidence = self.analyzer.analyze(features)
        assessment.anomaly_score = anomaly_score
        assessment.confidence = confidence

        # Adjust confidence based on trust score
        if profile:
            trust_factor = profile.trust_score / 100.0
            assessment.confidence *= (1.0 - trust_factor * 0.5)

        # Determine threat level
        if anomaly_score >= self.thresholds['anomaly_critical']:
            assessment.threat_level = "critical"
            assessment.reasons.append("Extremely anomalous traffic pattern")
        elif anomaly_score >= self.thresholds['anomaly_high']:
            assessment.threat_level = "high"
            assessment.reasons.append("Highly anomalous traffic")
        elif anomaly_score >= self.thresholds['anomaly_medium']:
            assessment.threat_level = "medium"
            assessment.reasons.append("Moderately anomalous traffic")
        elif anomaly_score >= self.thresholds['anomaly_low']:
            assessment.threat_level = "low"
            assessment.reasons.append("Slightly unusual traffic")

        # Determine recommended action
        if assessment.should_block():
            assessment.recommended_action = "block"
        elif assessment.should_rate_limit():
            assessment.recommended_action = "rate_limit"
        elif assessment.threat_level != "none":
            assessment.recommended_action = "monitor"
        else:
            assessment.recommended_action = "allow"

        return assessment

    def process_event(self, event: dict) -> Optional[ThreatAssessment]:
        """Process a suspicious event from XDP"""
        ip = event.get('src_ip')
        if not ip:
            return None

        # Build features from event
        features = TrafficFeatures(
            packets_per_second=event.get('pps', 0),
            bytes_per_second=event.get('bps', 0),
            syn_ratio=event.get('syn_ratio', 0),
            udp_ratio=event.get('udp_ratio', 0)
        )

        return self.assess_threat(ip, features)


class AIDNEngine:
    """
    Main AIDN AI Engine
    Coordinates all components for real-time DDoS defense
    """

    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.running = False
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'ips_rate_limited': 0,
            'false_positive_corrections': 0
        }

        # Event processing queue
        self.event_queue: deque = deque(maxlen=10000)

        # BPF map file descriptors
        self.bpf_maps = {}

        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, signum, frame):
        """Graceful shutdown"""
        logger.info("Shutting down AIDN Engine...")
        self.running = False
        self.threat_intel.player_tracker.save_profiles()
        self.threat_intel.analyzer.save_model()
        sys.exit(0)

    def _open_bpf_maps(self):
        """Open BPF maps for communication with XDP"""
        map_names = ['whitelist', 'blacklist', 'config', 'stats', 'events']
        for name in map_names:
            path = f"{BPF_MAPS_PATH}/{name}"
            if os.path.exists(path):
                try:
                    # Open pinned BPF map
                    self.bpf_maps[name] = path
                    logger.info(f"Opened BPF map: {name}")
                except Exception as e:
                    logger.warning(f"Failed to open BPF map {name}: {e}")

    def update_xdp_whitelist(self, ip: str, add: bool = True):
        """Update XDP whitelist via BPF map"""
        # This would interact with the BPF maps
        # Implementation depends on bpf library being used
        logger.info(f"{'Adding' if add else 'Removing'} {ip} {'to' if add else 'from'} XDP whitelist")

    def update_xdp_blacklist(self, ip: str, duration_seconds: int = 3600):
        """Update XDP blacklist via BPF map"""
        logger.info(f"Adding {ip} to XDP blacklist for {duration_seconds}s")

    def process_threat(self, assessment: ThreatAssessment):
        """Take action based on threat assessment"""
        ip = assessment.ip_address

        if assessment.recommended_action == "block":
            if assessment.confidence >= 0.9:  # Very high confidence required
                self.update_xdp_blacklist(ip, 3600)  # 1 hour block
                self.stats['ips_blocked'] += 1
                logger.warning(f"BLOCKED {ip}: {', '.join(assessment.reasons)} "
                             f"(confidence: {assessment.confidence:.2f})")
            else:
                # Not confident enough, just rate limit
                logger.info(f"Would block {ip} but confidence too low "
                          f"({assessment.confidence:.2f}), rate limiting instead")
                self.stats['ips_rate_limited'] += 1

        elif assessment.recommended_action == "rate_limit":
            self.stats['ips_rate_limited'] += 1
            logger.info(f"Rate limiting {ip}: {', '.join(assessment.reasons)}")

        elif assessment.recommended_action == "monitor":
            logger.debug(f"Monitoring {ip}: threat_level={assessment.threat_level}")

    def learning_mode_loop(self):
        """
        Learning mode: collect traffic samples without blocking
        Used initially to learn normal traffic patterns
        """
        logger.info("Starting in LEARNING MODE - collecting baseline traffic patterns")
        logger.info("No traffic will be blocked during learning phase")

        samples_collected = 0
        target_samples = 10000

        while self.running and samples_collected < target_samples:
            # Collect traffic samples
            # In real implementation, this reads from BPF ring buffer
            time.sleep(0.1)

            # Simulate collecting a sample
            features = TrafficFeatures(
                packets_per_second=np.random.normal(500, 100),
                bytes_per_second=np.random.normal(500000, 100000),
                avg_packet_size=np.random.normal(500, 100),
                syn_ratio=np.random.normal(0.05, 0.02),
                udp_ratio=np.random.normal(0.6, 0.1),
            )
            self.threat_intel.analyzer.add_training_sample(features)
            samples_collected += 1

            if samples_collected % 1000 == 0:
                logger.info(f"Learning progress: {samples_collected}/{target_samples} samples")

        logger.info("Learning phase complete, switching to protection mode")

    def protection_loop(self):
        """
        Main protection loop: analyze traffic and take action
        """
        logger.info("Starting PROTECTION MODE")

        while self.running:
            # Process events from queue
            while self.event_queue:
                event = self.event_queue.popleft()
                self.stats['events_processed'] += 1

                assessment = self.threat_intel.process_event(event)
                if assessment and assessment.threat_level != "none":
                    self.stats['threats_detected'] += 1
                    self.process_threat(assessment)

            # Periodic tasks
            time.sleep(0.01)  # 10ms loop

    def run(self):
        """Main entry point"""
        logger.info("="*60)
        logger.info("AIDN - AI Defense Network Engine Starting")
        logger.info("="*60)

        # Create directories
        Path(DATA_PATH).mkdir(parents=True, exist_ok=True)
        Path(LOG_PATH).mkdir(parents=True, exist_ok=True)

        self.running = True

        # Open BPF maps
        self._open_bpf_maps()

        # Check if we need learning mode
        if not self.threat_intel.analyzer.is_trained:
            self.learning_mode_loop()

        # Main protection loop
        self.protection_loop()


class AIDNDaemon:
    """
    Daemon wrapper for AIDN Engine
    Handles proper daemonization and service management
    """

    def __init__(self):
        self.engine = AIDNEngine()
        self.pidfile = "/var/run/aidn-engine.pid"

    def start(self):
        """Start the daemon"""
        # Check if already running
        if os.path.exists(self.pidfile):
            with open(self.pidfile) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                logger.error(f"AIDN Engine already running (PID: {pid})")
                sys.exit(1)
            except OSError:
                os.remove(self.pidfile)

        # Write PID file
        with open(self.pidfile, 'w') as f:
            f.write(str(os.getpid()))

        try:
            self.engine.run()
        finally:
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)

    def stop(self):
        """Stop the daemon"""
        if not os.path.exists(self.pidfile):
            logger.error("AIDN Engine not running")
            return

        with open(self.pidfile) as f:
            pid = int(f.read().strip())

        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("AIDN Engine stopped")
        except OSError as e:
            logger.error(f"Failed to stop: {e}")

    def status(self):
        """Check daemon status"""
        if not os.path.exists(self.pidfile):
            print("AIDN Engine: not running")
            return

        with open(self.pidfile) as f:
            pid = int(f.read().strip())

        try:
            os.kill(pid, 0)
            print(f"AIDN Engine: running (PID: {pid})")
        except OSError:
            print("AIDN Engine: not running (stale PID file)")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AIDN AI Defense Network Engine")
    parser.add_argument('command', choices=['start', 'stop', 'status', 'run'],
                       help="Command to execute")
    parser.add_argument('--debug', action='store_true', help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    daemon = AIDNDaemon()

    if args.command == 'start':
        daemon.start()
    elif args.command == 'stop':
        daemon.stop()
    elif args.command == 'status':
        daemon.status()
    elif args.command == 'run':
        # Run in foreground
        daemon.engine.run()


if __name__ == "__main__":
    main()
