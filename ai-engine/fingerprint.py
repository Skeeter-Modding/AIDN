#!/usr/bin/env python3
"""
AIDN Traffic Fingerprinting Module
Identifies attack patterns and legitimate player behavior signatures

This module creates "fingerprints" of traffic patterns to:
1. Identify known attack tools/botnets
2. Recognize legitimate game client behavior
3. Detect protocol anomalies
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter
import numpy as np


@dataclass
class PacketFingerprint:
    """Fingerprint of a single packet's characteristics"""
    size_bucket: int  # Packet size rounded to nearest 64 bytes
    ttl_bucket: int  # TTL rounded to nearest 8
    tcp_options_hash: str  # Hash of TCP options if present
    payload_prefix_hash: str  # Hash of first 32 bytes of payload
    protocol: int
    flags: int  # TCP flags or 0


@dataclass
class SessionFingerprint:
    """Fingerprint of a session/flow's behavior"""
    ip_address: str
    avg_packet_size: float
    packet_size_variance: float
    avg_inter_arrival_ms: float
    inter_arrival_variance: float
    port_pattern: str  # Encoded port usage pattern
    protocol_mix: Dict[int, float] = field(default_factory=dict)
    tcp_flag_sequence: List[int] = field(default_factory=list)
    payload_entropy: float = 0.0

    def to_hash(self) -> str:
        """Generate unique hash for this fingerprint"""
        data = f"{self.avg_packet_size:.0f}:{self.packet_size_variance:.0f}:" \
               f"{self.avg_inter_arrival_ms:.0f}:{self.port_pattern}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


class AttackSignatureDB:
    """
    Database of known attack signatures
    Used to quickly identify known attack tools
    """

    def __init__(self):
        self.signatures: Dict[str, dict] = {}
        self._load_default_signatures()

    def _load_default_signatures(self):
        """Load known attack tool signatures"""

        # LOIC (Low Orbit Ion Cannon) signature
        self.signatures['loic'] = {
            'name': 'LOIC',
            'description': 'Low Orbit Ion Cannon DDoS tool',
            'indicators': {
                'packet_sizes': [64, 128],  # Common LOIC packet sizes
                'port_pattern': 'single',  # Targets single port
                'payload_pattern': b'LOIC',  # Sometimes in payload
                'inter_arrival': (0, 5),  # Very fast
            },
            'severity': 'high'
        }

        # HOIC (High Orbit Ion Cannon) signature
        self.signatures['hoic'] = {
            'name': 'HOIC',
            'description': 'High Orbit Ion Cannon HTTP flooder',
            'indicators': {
                'protocol': 6,  # TCP
                'port_pattern': 'http',  # HTTP ports
                'user_agent_pattern': 'random',
                'inter_arrival': (0, 10),
            },
            'severity': 'high'
        }

        # Mirai botnet signature
        self.signatures['mirai'] = {
            'name': 'Mirai',
            'description': 'Mirai botnet DDoS',
            'indicators': {
                'protocol': 17,  # UDP
                'payload_entropy': (0.0, 2.0),  # Low entropy (repetitive)
                'packet_sizes': range(0, 128),
                'ttl_variance': (0, 5),  # Consistent TTL
            },
            'severity': 'critical'
        }

        # DNS amplification signature
        self.signatures['dns_amp'] = {
            'name': 'DNS Amplification',
            'description': 'DNS amplification attack',
            'indicators': {
                'protocol': 17,  # UDP
                'src_port': 53,  # DNS
                'packet_sizes': range(512, 4096),  # Large responses
                'payload_pattern': b'\x00\x00\x81\x80',  # DNS response
            },
            'severity': 'critical'
        }

        # NTP amplification signature
        self.signatures['ntp_amp'] = {
            'name': 'NTP Amplification',
            'description': 'NTP monlist amplification attack',
            'indicators': {
                'protocol': 17,  # UDP
                'src_port': 123,  # NTP
                'packet_sizes': range(440, 500),  # NTP response size
            },
            'severity': 'critical'
        }

        # SYN flood signature
        self.signatures['syn_flood'] = {
            'name': 'SYN Flood',
            'description': 'TCP SYN flood attack',
            'indicators': {
                'protocol': 6,  # TCP
                'tcp_flags': 0x02,  # SYN only
                'packet_sizes': [40, 60],  # SYN packet sizes
                'inter_arrival': (0, 1),  # Very fast
                'no_ack': True,  # No ACK responses
            },
            'severity': 'high'
        }

        # UDP flood signature
        self.signatures['udp_flood'] = {
            'name': 'UDP Flood',
            'description': 'Generic UDP flood',
            'indicators': {
                'protocol': 17,  # UDP
                'packet_size_variance': (0, 50),  # Consistent sizes
                'inter_arrival': (0, 5),  # Fast
                'random_ports': True,
            },
            'severity': 'high'
        }


class GameClientFingerprinter:
    """
    Fingerprints legitimate game client behavior
    Used to identify real players vs bots/attacks
    """

    def __init__(self):
        # Known game client patterns
        self.game_patterns = {
            'arma_reforger': {
                'ports': {2001, 2002, 17777, 19999},
                'protocol': 17,  # UDP
                'packet_sizes': range(50, 1400),
                'inter_arrival_range': (10, 200),  # 10-200ms typical
                'session_duration': (60, 14400),  # 1 min to 4 hours
                'bidirectional': True,
            }
        }

        # Learned player fingerprints
        self.known_players: Dict[str, SessionFingerprint] = {}

    def analyze_session(self, packets: List[dict]) -> SessionFingerprint:
        """Analyze a series of packets to create session fingerprint"""
        if not packets:
            return None

        sizes = [p.get('size', 0) for p in packets]
        times = [p.get('timestamp', 0) for p in packets]

        # Calculate inter-arrival times
        inter_arrivals = []
        for i in range(1, len(times)):
            inter_arrivals.append((times[i] - times[i-1]) * 1000)  # ms

        # Create fingerprint
        fp = SessionFingerprint(
            ip_address=packets[0].get('src_ip', ''),
            avg_packet_size=np.mean(sizes) if sizes else 0,
            packet_size_variance=np.var(sizes) if sizes else 0,
            avg_inter_arrival_ms=np.mean(inter_arrivals) if inter_arrivals else 0,
            inter_arrival_variance=np.var(inter_arrivals) if inter_arrivals else 0,
            port_pattern=self._encode_port_pattern(packets)
        )

        return fp

    def _encode_port_pattern(self, packets: List[dict]) -> str:
        """Encode port usage pattern"""
        ports = [p.get('dst_port', 0) for p in packets]
        unique_ports = len(set(ports))

        if unique_ports == 1:
            return 'single'
        elif unique_ports <= 5:
            return 'few'
        elif unique_ports <= 50:
            return 'moderate'
        else:
            return 'many'

    def is_game_client(self, fingerprint: SessionFingerprint,
                       game: str = 'arma_reforger') -> Tuple[bool, float]:
        """
        Check if fingerprint matches game client behavior
        Returns (is_match, confidence)
        """
        if game not in self.game_patterns:
            return False, 0.0

        pattern = self.game_patterns[game]
        confidence = 0.0
        checks = 0
        matches = 0

        # Check packet size range
        checks += 1
        if (pattern['packet_sizes'].start <= fingerprint.avg_packet_size <=
            pattern['packet_sizes'].stop):
            matches += 1

        # Check inter-arrival time
        checks += 1
        min_ia, max_ia = pattern['inter_arrival_range']
        if min_ia <= fingerprint.avg_inter_arrival_ms <= max_ia:
            matches += 1

        # Check port pattern (game clients use few ports)
        checks += 1
        if fingerprint.port_pattern in ['single', 'few']:
            matches += 1

        confidence = matches / checks if checks > 0 else 0.0

        return confidence >= 0.6, confidence

    def learn_player(self, ip: str, fingerprint: SessionFingerprint):
        """Learn a verified player's fingerprint"""
        self.known_players[ip] = fingerprint

    def is_known_player(self, ip: str, fingerprint: SessionFingerprint) -> Tuple[bool, float]:
        """Check if fingerprint matches known player"""
        if ip not in self.known_players:
            return False, 0.0

        known = self.known_players[ip]

        # Compare fingerprints
        similarity = self._compare_fingerprints(known, fingerprint)

        return similarity >= 0.7, similarity

    def _compare_fingerprints(self, fp1: SessionFingerprint,
                              fp2: SessionFingerprint) -> float:
        """Compare two fingerprints, return similarity 0-1"""
        scores = []

        # Packet size similarity
        if fp1.avg_packet_size > 0:
            size_diff = abs(fp1.avg_packet_size - fp2.avg_packet_size)
            size_sim = max(0, 1 - size_diff / fp1.avg_packet_size)
            scores.append(size_sim)

        # Inter-arrival similarity
        if fp1.avg_inter_arrival_ms > 0:
            ia_diff = abs(fp1.avg_inter_arrival_ms - fp2.avg_inter_arrival_ms)
            ia_sim = max(0, 1 - ia_diff / fp1.avg_inter_arrival_ms)
            scores.append(ia_sim)

        # Port pattern match
        if fp1.port_pattern == fp2.port_pattern:
            scores.append(1.0)
        else:
            scores.append(0.5)

        return np.mean(scores) if scores else 0.0


class TrafficClassifier:
    """
    Classifies traffic into categories:
    - Legitimate player
    - Suspicious
    - Known attack pattern
    """

    def __init__(self):
        self.attack_db = AttackSignatureDB()
        self.game_fp = GameClientFingerprinter()

    def classify(self, session_data: dict) -> dict:
        """
        Classify a traffic session
        Returns classification with confidence
        """
        result = {
            'classification': 'unknown',
            'confidence': 0.0,
            'attack_type': None,
            'is_player': False,
            'details': []
        }

        # Extract fingerprint from session data
        packets = session_data.get('packets', [])
        if not packets:
            return result

        fingerprint = self.game_fp.analyze_session(packets)
        ip = session_data.get('ip', '')

        # Check if known player first
        is_known, known_conf = self.game_fp.is_known_player(ip, fingerprint)
        if is_known:
            result['classification'] = 'legitimate_player'
            result['confidence'] = known_conf
            result['is_player'] = True
            result['details'].append(f"Known player match (conf: {known_conf:.2f})")
            return result

        # Check if matches game client pattern
        is_game, game_conf = self.game_fp.is_game_client(fingerprint)
        if is_game:
            result['classification'] = 'probable_player'
            result['confidence'] = game_conf
            result['is_player'] = True
            result['details'].append(f"Game client pattern match (conf: {game_conf:.2f})")
            return result

        # Check against attack signatures
        attack_match = self._match_attack_signatures(session_data)
        if attack_match:
            result['classification'] = 'attack'
            result['confidence'] = attack_match['confidence']
            result['attack_type'] = attack_match['signature']
            result['details'].append(f"Attack pattern: {attack_match['signature']}")
            return result

        # Unknown - needs further analysis
        result['classification'] = 'suspicious'
        result['confidence'] = 0.5
        result['details'].append("Does not match known patterns")

        return result

    def _match_attack_signatures(self, session_data: dict) -> Optional[dict]:
        """Check session against known attack signatures"""
        best_match = None
        best_score = 0.0

        for sig_name, signature in self.attack_db.signatures.items():
            score = self._score_signature_match(session_data, signature)
            if score > best_score and score >= 0.6:
                best_score = score
                best_match = {
                    'signature': sig_name,
                    'confidence': score,
                    'severity': signature['severity']
                }

        return best_match

    def _score_signature_match(self, session_data: dict, signature: dict) -> float:
        """Score how well session matches an attack signature"""
        indicators = signature.get('indicators', {})
        matches = 0
        checks = 0

        packets = session_data.get('packets', [])
        if not packets:
            return 0.0

        # Check protocol
        if 'protocol' in indicators:
            checks += 1
            if any(p.get('protocol') == indicators['protocol'] for p in packets):
                matches += 1

        # Check packet sizes
        if 'packet_sizes' in indicators:
            checks += 1
            sizes = [p.get('size', 0) for p in packets]
            avg_size = np.mean(sizes)
            expected = indicators['packet_sizes']
            if isinstance(expected, range):
                if expected.start <= avg_size <= expected.stop:
                    matches += 1
            elif isinstance(expected, list):
                if any(abs(avg_size - s) < 20 for s in expected):
                    matches += 1

        # Check inter-arrival time
        if 'inter_arrival' in indicators:
            checks += 1
            times = [p.get('timestamp', 0) for p in packets]
            if len(times) > 1:
                ia = [(times[i] - times[i-1]) * 1000 for i in range(1, len(times))]
                avg_ia = np.mean(ia)
                min_ia, max_ia = indicators['inter_arrival']
                if min_ia <= avg_ia <= max_ia:
                    matches += 1

        return matches / checks if checks > 0 else 0.0


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * np.log2(p)

    return entropy


def hash_tcp_options(options: bytes) -> str:
    """Create hash of TCP options for fingerprinting"""
    return hashlib.sha256(options).hexdigest()[:8]
