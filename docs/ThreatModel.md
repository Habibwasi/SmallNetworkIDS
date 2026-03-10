# Threat Model: SmallNetworkIDS

## 1. System Overview
A lightweight intrusion detection system for small networks that monitors traffic to detect port scans and DDoS-like floods using ML-based anomaly detection.

## 2. Assets to Protect
| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Network Traffic Data | Raw packets and flow statistics | Medium |
| ML Model | Trained ONNX model for anomaly detection | Medium |
| Alert Logs | Historical detection events | Low-Medium |
| Baseline Data | Normal traffic patterns | Low |
| Configuration | Thresholds, firewall rules | Medium |

## 3. Trust Boundaries
```
┌─────────────────────────────────────────────────────┐
│ Untrusted Zone (Internet)                           │
└─────────────────────────────────────────────────────┘
                        │
                   [Firewall]
                        │
┌─────────────────────────────────────────────────────┐
│ Semi-Trusted Zone (Local Network)                   │
│   • IoT Devices                                     │
│   • Workstations                                    │
└─────────────────────────────────────────────────────┘
                        │
               [Network Tap/Mirror]
                        │
┌─────────────────────────────────────────────────────┐
│ Trusted Zone (IDS Host)                             │
│   • Packet Sniffer                                  │
│   • ML Engine                                       │
│   • Alert Manager                                   │
│   • Dashboard                                       │
└─────────────────────────────────────────────────────┘
```

## 4. Threat Analysis (STRIDE)

### 4.1 Spoofing
| Threat | Description | Mitigation |
|--------|-------------|------------|
| T1 | Attacker spoofs source IP to evade detection | Track flows by multiple attributes, not just IP |
| T2 | Malicious device impersonates trusted host | MAC-IP binding verification |

### 4.2 Tampering
| Threat | Description | Mitigation |
|--------|-------------|------------|
| T3 | Attacker modifies packets to avoid detection signatures | Use behavioral analysis, not just signatures |
| T4 | Tampering with ML model file | Integrity checks (hash verification) on model load |
| T5 | Log manipulation to hide evidence | Append-only logs with checksums |

### 4.3 Repudiation
| Threat | Description | Mitigation |
|--------|-------------|------------|
| T6 | Attacker denies malicious activity | Timestamped logs with packet hashes |

### 4.4 Information Disclosure
| Threat | Description | Mitigation |
|--------|-------------|------------|
| T7 | Captured traffic exposes sensitive data | Minimal data retention, secure storage |
| T8 | Model extraction reveals detection logic | Restrict access to model files |

### 4.5 Denial of Service
| Threat | Description | Mitigation |
|--------|-------------|------------|
| T9 | Traffic flood overwhelms IDS processing | Rate limiting, sampling under load |
| T10 | Resource exhaustion via malformed packets | Input validation, bounded buffers |

### 4.6 Elevation of Privilege
| Threat | Description | Mitigation |
|--------|-------------|------------|
| T11 | Exploit in packet parser leads to code execution | Run with minimal privileges, sandboxing |
| T12 | Dashboard access grants config changes | Role-based access control |

## 5. Attack Scenarios (Targeted by IDS)

### 5.1 Port Scan Detection
**Indicators:**
- High rate of SYN packets to different ports
- Low packets-per-flow ratio
- Sequential or random port probing patterns

**Features to Extract:**
- Unique destination ports per source IP per time window
- SYN/ACK ratio
- Connection success rate

### 5.2 DDoS Flood Detection
**Indicators:**
- Abnormal traffic volume (bytes/sec, packets/sec)
- Many sources targeting single destination
- Unusual protocol distribution

**Features to Extract:**
- Packets per second per destination
- Bytes per second
- Source IP entropy
- Protocol distribution deviation

## 6. Security Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| SR1 | IDS must run with least privilege (no root unless capturing) | High |
| SR2 | ML model integrity verified at startup | Medium |
| SR3 | Logs must be tamper-evident | Medium |
| SR4 | Dashboard requires authentication | High |
| SR5 | Sensitive config encrypted at rest | Medium |
| SR6 | Graceful degradation under high load | High |

## 7. Risk Matrix

| Threat | Likelihood | Impact | Risk Level |
|--------|------------|--------|------------|
| T9 (DoS on IDS) | High | High | **Critical** |
| T11 (Parser exploit) | Medium | High | **High** |
| T1 (IP Spoofing) | High | Medium | **High** |
| T4 (Model tampering) | Low | High | Medium |
| T7 (Data exposure) | Medium | Medium | Medium |

## 8. Assumptions
1. Network tap/mirror port is properly configured
2. IDS host is on isolated management network segment
3. Attacker cannot directly access IDS host
4. Traffic volume stays within hardware capability