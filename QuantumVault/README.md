# QuantumVault — QKD R&D Infrastructure Platform

> **Quantum Key Distribution & Post-Quantum Cryptography Research Platform for Financial Institutions**
>
> An enterprise-grade simulation, analysis, and R&D platform covering QKD protocols, post-quantum cryptography migration, threat intelligence, and ETSI-compliant key management — built for PE firms, investment banks, and quantitative finance institutions navigating the post-quantum transition.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Why This Exists — The Problem](#2-why-this-exists--the-problem)
3. [Architecture](#3-architecture)
4. [Project Structure](#4-project-structure)
5. [Core Modules](#5-core-modules)
   - [5.1 QKD Protocols](#51-qkd-protocols)
   - [5.2 Post-Quantum Cryptography](#52-post-quantum-cryptography)
   - [5.3 Threat Intelligence](#53-threat-intelligence)
   - [5.4 Network Design](#54-network-design)
   - [5.5 Key Management System](#55-key-management-system)
   - [5.6 Reporting & Roadmap](#56-reporting--roadmap)
6. [REST API](#6-rest-api)
7. [Streamlit Dashboard](#7-streamlit-dashboard)
8. [Installation & Setup](#8-installation--setup)
9. [Running the Platform](#9-running-the-platform)
10. [Testing](#10-testing)
11. [Configuration](#11-configuration)
12. [Security Concepts Reference](#12-security-concepts-reference)
13. [Monetization Model](#13-monetization-model)
14. [Roadmap to Production](#14-roadmap-to-production)
15. [Tech Stack](#15-tech-stack)

---

## 1. Overview

QuantumVault is a zero-cost-to-build, SaaS-ready R&D platform that lets financial institutions:

- **Simulate** all major QKD protocols (BB84, E91, MDI-QKD) with realistic hardware models
- **Assess** their exposure to the Harvest Now, Decrypt Later (HNDL) threat
- **Plan** post-quantum cryptography (PQC) migrations aligned to NIST FIPS 203/204/205/206
- **Design** QKD network topologies for multi-site financial infrastructure
- **Operate** an ETSI GS QKD 014-compliant key management simulation
- **Generate** board-level deployment roadmaps with ROI projections

Everything runs in pure Python using open-source libraries — no paid APIs, no cloud dependencies, no upfront cost to operate.

---

## 2. Why This Exists — The Problem

### The HNDL Threat

Nation-state adversaries are actively harvesting encrypted financial data today with the explicit intent of decrypting it once a Cryptographically Relevant Quantum Computer (CRQC) becomes available. This is known as **Harvest Now, Decrypt Later (HNDL)**.

- A CRQC running **Shor's Algorithm** will break RSA-2048 and ECC-256 — the backbone of today's financial cryptography
- The US Intelligence Community assesses Q-Day somewhere between **2030 and 2040**
- **DORA**, **CNSA 2.0**, and **NIST SP 800-208** already mandate PQC migration planning
- Most financial institutions have **zero visibility** into their quantum cryptographic exposure

### The Gap

Mid-market financial firms — hedge funds, regional banks, boutique investment banks, exchanges — have no accessible tool to:
- Quantify their HNDL exposure in dollar terms
- Simulate QKD and understand its hardware requirements
- Generate a phased PQC migration plan against their actual cryptographic inventory
- Produce board-ready quantum security roadmaps

QuantumVault fills this gap.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    QuantumVault Platform                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────────────┐    ┌──────────────────────────────┐  │
│   │   Streamlit Dashboard │    │     FastAPI REST Backend     │  │
│   │   (localhost:8502)    │    │     (localhost:8000)         │  │
│   │   11 interactive tabs │    │     35 endpoints             │  │
│   └──────────┬───────────┘    └──────────────┬───────────────┘  │
│              │                               │                  │
│              └───────────────┬───────────────┘                  │
│                              │                                  │
│   ┌──────────────────────────▼────────────────────────────────┐ │
│   │                     Core Engine                           │ │
│   │                                                           │ │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐ │ │
│   │  │   QKD    │ │   PQC    │ │  Threat  │ │   Network   │ │ │
│   │  │Protocols │ │  Crypto  │ │  Engine  │ │   Design    │ │ │
│   │  │ BB84     │ │ Kyber    │ │  HNDL    │ │  Topology   │ │ │
│   │  │ E91      │ │Dilithium │ │  Q-Day   │ │  Repeater   │ │ │
│   │  │ MDI-QKD  │ │ FALCON   │ │  Audit   │ │             │ │ │
│   │  │ Channel  │ │Migration │ │          │ │             │ │ │
│   │  └──────────┘ └──────────┘ └──────────┘ └─────────────┘ │ │
│   │                                                           │ │
│   │  ┌──────────────────────┐  ┌──────────────────────────┐  │ │
│   │  │  Key Management      │  │  Reporting & Roadmap     │  │ │
│   │  │  ETSI GS QKD 014     │  │  Institution Profiles    │  │ │
│   │  │  KMS Simulation      │  │  ROI Projections         │  │ │
│   │  └──────────────────────┘  └──────────────────────────┘  │ │
│   └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Project Structure

```
QuantumVault/
│
├── main.py                          # FastAPI entry point — 35 routes
├── dashboard.py                     # Streamlit dashboard — 11 tabs
├── requirements.txt                 # All Python dependencies
├── .env.example                     # Environment variable template
│
├── core/                            # All business logic
│   ├── qkd/                         # QKD protocol simulators
│   │   ├── bb84.py                  # BB84 protocol + attack simulation
│   │   ├── e91.py                   # E91 entanglement-based QKD
│   │   ├── mdi_qkd.py               # MDI-QKD with untrusted relay
│   │   └── channel.py               # Quantum channel + hardware models
│   │
│   ├── pqc/                         # Post-quantum cryptography
│   │   ├── kyber.py                 # CRYSTALS-Kyber KEM (NIST FIPS 203)
│   │   ├── dilithium.py             # CRYSTALS-Dilithium + FALCON sigs
│   │   └── migration.py             # PQC migration engine
│   │
│   ├── threat/                      # Threat intelligence
│   │   ├── hndl.py                  # HNDL risk engine
│   │   ├── qday.py                  # Q-Day timeline model
│   │   └── crypto_audit.py          # Cryptographic infrastructure auditor
│   │
│   ├── network/                     # QKD network design
│   │   ├── topology.py              # Network topology modeler
│   │   └── repeater.py              # Trusted relay chain designer
│   │
│   ├── key_management/              # Key management system
│   │   └── qkd_kms.py               # ETSI GS QKD 014 compliant KMS
│   │
│   └── reporting/                   # Roadmap generation
│       └── roadmap.py               # Deployment roadmap generator
│
├── api/                             # FastAPI route handlers
│   ├── routes/
│   │   ├── qkd.py                   # 8 QKD endpoints
│   │   ├── threat.py                # 5 threat endpoints
│   │   ├── pqc.py                   # 6 PQC endpoints
│   │   └── reporting.py             # 9 reporting + KMS endpoints
│   └── models/
│       └── schemas.py               # All Pydantic v2 request/response models
│
└── tests/                           # Test suite — 64 tests total
    ├── test_bb84.py                 # 15 BB84 protocol tests
    ├── test_hndl.py                 # 23 HNDL / Q-Day / audit tests
    └── test_pqc.py                  # 26 PQC algorithm tests
```

---

## 5. Core Modules

### 5.1 QKD Protocols

#### `core/qkd/bb84.py` — BB84 Protocol Simulator

The foundational quantum key distribution protocol (Bennett & Brassard, 1984). Two parties (Alice and Bob) exchange quantum bits encoded in two conjugate bases to establish a secret key. Any eavesdropper introduces detectable errors.

**Key Classes:**
- `BB84Simulator` — full protocol simulation including quantum channel propagation, basis sifting, error estimation, error correction, and privacy amplification
- `QuantumChannel` — configurable channel with distance, detector efficiency, dark count rate, and attack type
- `AttackType` — enum: `NONE`, `INTERCEPT_RESEND`, `PHOTON_NUMBER_SPLITTING`
- `BB84Result` — dataclass with all output metrics

**Key Methods:**
| Method | Description |
|--------|-------------|
| `run(n_qubits, channel)` | Run a full BB84 simulation |
| `sweep_distance(n_qubits, distances)` | Key rate vs. distance sweep |
| `sweep_attack(n_qubits, channel)` | Compare all three attack types |

**Core Parameters:**
| Parameter | Value | Notes |
|-----------|-------|-------|
| QBER security threshold | 11% | Above this = eavesdropper detected |
| Privacy amplification | SHA3-256 (Toeplitz approx.) | Removes Eve's partial information |
| Error correction leakage | ~1.16 × h(QBER) | Cascade protocol approximation |
| Intercept-Resend QBER penalty | +25% per intercepted qubit | Forces Eve's hand |

**Example Output:**
```python
result.qber                    # 0.0100  (1% QBER — clean channel)
result.secure_key_rate_bps     # 85,432  (bits/sec at 50km)
result.secure                  # True
result.privacy_amplified_key_length  # 1,243 bits
```

---

#### `core/qkd/e91.py` — E91 Entanglement-Based QKD

Ekert's 1991 protocol using entangled EPR (Einstein-Podolsky-Rosen) pairs. Security is guaranteed by Bell inequality violations — if the quantum correlations violate the CHSH inequality (|S| > 2), no eavesdropper has tampered with the channel.

**Key Classes:**
- `E91Simulator` — full EPR pair generation, measurement in multiple bases, Bell parameter computation, key extraction
- `E91Result` — with Bell parameter S, CHSH violation flag, QBER, and secure key output

**Measurement Settings:**
- Alice: 0°, 45°
- Bob: 22.5°, 67.5°
- Quantum correlations: E(a, b) = −cos(a − b) (singlet state)

**Bell Parameter:**
`S = E(a₀,b₀) − E(a₀,b₁) + E(a₁,b₀) + E(a₁,b₁)`

- Classical limit: |S| ≤ 2.0
- Tsirelson bound (max quantum): 2√2 ≈ 2.828
- Eavesdropping reduces |S| toward classical bound

**Key Method:**
```python
result = E91Simulator().run(
    n_pairs=10000,
    distance_km=50.0,
    entanglement_fidelity=0.97,
    eavesdropping=False
)
result.bell_parameter_s    # e.g. 2.74
result.bell_violated       # True — quantum channel confirmed secure
```

---

#### `core/qkd/mdi_qkd.py` — MDI-QKD (Measurement Device Independent)

An advanced QKD protocol where both Alice and Bob send photons to an untrusted third party (Charlie) who performs a Bell State Measurement (BSM). Security holds even if Charlie is fully controlled by an adversary — eliminating detector side-channel attacks.

**Key Classes:**
- `MDIQKDSimulator` — full simulation including BSM success probability, channel losses for both legs, QBER estimation
- `MDIQKDResult` — with `detector_attack_immune=True` always, regardless of Charlie's integrity

**Key Properties:**
- BSM success probability: 0.5 (linear optics limit)
- Charlie can be malicious: security proof still holds
- Eliminates all detector-side attacks (the #1 practical QKD attack vector)

```python
result = MDIQKDSimulator().run(
    n_pulses=50000,
    alice_distance_km=25.0,
    bob_distance_km=25.0,
    charlie_is_malicious=True   # does not matter
)
result.detector_attack_immune   # always True
result.secure_key_rate_bps      # key rate accounting for total path loss
```

---

#### `core/qkd/channel.py` — Quantum Channel & Hardware Models

Computes achievable secure key rates using the Devetak-Winter / GLLP formula for realistic channel and hardware parameters.

**Channel Mediums (`ChannelMedium` enum):**
| Medium | Loss (dB/km) |
|--------|-------------|
| `FIBER_SMF28` | 0.20 |
| `FIBER_ULTRA_LOW_LOSS` | 0.16 |
| `FREE_SPACE` | 0.03 |
| `UNDERWATER` | 0.04 |

**Hardware Profiles (`HARDWARE_PROFILES` dict):**
| Profile Key | Vendor | Clock Rate | Detector Efficiency |
|------------|--------|-----------|-------------------|
| `toshiba_qkd` | Toshiba | 1 GHz | 0.85 |
| `idq_clavis3` | ID Quantique | 2.5 GHz | 0.90 |
| `quantinuum_h1` | Quantinuum | 100 MHz | 0.75 |
| `research_grade` | Generic | 10 MHz | 0.60 |

**Key Methods:**
| Method | Description |
|--------|-------------|
| `analyze(hardware_key, medium, distance_km, additional_loss_db)` | Full channel capacity analysis |
| `sweep_hardware_comparison(distance_km)` | Compare all 4 hardware profiles at a given distance |
| `_max_viable_distance(hw, medium)` | Binary search for max QKD range (non-recursive) |
| `_is_viable(hw, medium, distance_km)` | Direct viability check without `analyze()` recursion |

---

### 5.2 Post-Quantum Cryptography

#### `core/pqc/kyber.py` — CRYSTALS-Kyber KEM (NIST FIPS 203)

Simulation of the CRYSTALS-Kyber Key Encapsulation Mechanism — the NIST-selected post-quantum public-key encryption standard based on Module Learning With Errors (MLWE).

**Parameter Sets:**
| Variant | Security Level | Public Key | Secret Key | Ciphertext |
|---------|---------------|------------|------------|------------|
| Kyber-512 | 128-bit (NIST Level 1) | 800 bytes | 1,632 bytes | 768 bytes |
| Kyber-768 | 192-bit (NIST Level 3) | 1,184 bytes | 2,400 bytes | 1,088 bytes |
| Kyber-1024 | 256-bit (NIST Level 5) | 1,568 bytes | 3,168 bytes | 1,568 bytes |

**Performance vs RSA-2048:**
| Operation | Kyber-768 | RSA-2048 | Speedup |
|-----------|-----------|----------|---------|
| Key Generation | 0.032 ms | 250 ms | 7,800× |
| Encapsulation | 0.041 ms | 0.18 ms | 4.4× |
| Decapsulation | 0.038 ms | 1.20 ms | 31.6× |

**Key Fix — Deterministic KEM Simulation:**
The `encapsulate()` method encodes ephemeral message `m` as the first 32 bytes of the ciphertext so `decapsulate()` can recover it deterministically, producing the same `shared_secret` from both sides:
```
ciphertext = m || SHA3-SHAKE256(r || pk)[:(ct_size - 32)]
shared_secret = SHA3-256(K || ciphertext)
```

---

#### `core/pqc/dilithium.py` — CRYSTALS-Dilithium + FALCON (NIST FIPS 204 / 206)

Simulation of two NIST-selected post-quantum digital signature schemes.

**CRYSTALS-Dilithium Parameter Sets (FIPS 204):**
| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|---------------|------------|------------|-----------|
| Dilithium2 | 128-bit | 1,312 bytes | 2,528 bytes | 2,420 bytes |
| Dilithium3 | 192-bit | 1,952 bytes | 4,000 bytes | 3,293 bytes |
| Dilithium5 | 256-bit | 2,592 bytes | 4,864 bytes | 4,595 bytes |

**FALCON Parameter Sets (FIPS 206):**
| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|---------------|------------|------------|-----------|
| FALCON-512 | 128-bit | 897 bytes | 1,281 bytes | 666 bytes (avg) |
| FALCON-1024 | 256-bit | 1,793 bytes | 2,305 bytes | 1,280 bytes (avg) |

FALCON produces significantly smaller signatures than Dilithium, making it preferred for bandwidth-constrained financial messaging protocols.

---

#### `core/pqc/migration.py` — PQC Migration Engine

Assesses an institution's cryptographic asset inventory and generates a prioritised migration plan to NIST-approved PQC algorithms.

**Vulnerability Classification (`ALGORITHM_VULNERABILITY`):**
| Algorithm | Quantum Vulnerable | Recommended Replacement |
|-----------|-------------------|------------------------|
| RSA-2048 | Yes (Shor) | Kyber-768 + Dilithium3 |
| ECC P-256 | Yes (Shor) | Kyber-768 + Dilithium3 |
| ECDH | Yes (Shor) | Kyber-1024 |
| AES-256 | Partial (Grover) | AES-256 (key size sufficient) |
| SHA-256 | Partial (Grover) | SHA-384 or SHA-512 |
| AES-128 | Yes (Grover) | AES-256 |

**Risk Scoring Model:**
| Factor | Max Points | Description |
|--------|-----------|-------------|
| Quantum vulnerability | 40 | Is the algorithm breakable by Shor/Grover? |
| Data sensitivity | 30 | Classification level of protected data |
| Retention risk | 20 | Data lifetime × years to Q-Day |
| Volume | 10 | Scale of deployment |

**Migration Urgency Levels:** `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `NONE`

---

### 5.3 Threat Intelligence

#### `core/threat/hndl.py` — HNDL Risk Engine

Quantifies a financial institution's exposure to Harvest Now, Decrypt Later attacks in dollar terms.

**Data Categories (`DataCategory` enum):**
| Category | Value per GB | Retention |
|----------|-------------|-----------|
| `algo_source_code` | $100M/GB | 15 years |
| `risk_models` | $50M/GB | 12 years |
| `trading_positions` | $25M/GB | 7 years |
| `client_pii` | $5M/GB | 10 years |
| `market_data_feeds` | $1M/GB | 5 years |
| `communications` | $500K/GB | 7 years |

**Q-Day Scenarios used in HNDL scoring:**
| Scenario | Year | Probability |
|----------|------|------------|
| Black Swan | 2031 | 5% |
| Optimistic | 2034 | 15% |
| Base Case | 2038 | 50% |
| Conservative | 2043 | 25% |

**HNDL Sub-Score Breakdown:**
- Quantum vulnerability: 50 points
- Data retention risk: 30 points
- Adversary capture likelihood: 20 points

---

#### `core/threat/qday.py` — Q-Day Timeline Model

Models the probability distribution of when a CRQC capable of breaking RSA-2048 will exist.

**Quantum Hardware Roadmaps tracked:**
- IBM (superconducting, error rate improving)
- Google (superconducting, surface code focus)
- Quantinuum (trapped ion, highest current fidelity)
- IonQ (trapped ion)
- Microsoft (topological qubits — if breakthrough achieved)

**CRQC Requirements (Gidney & Ekerå, 2021):**
- Algorithm: Shor's Algorithm for RSA-2048 factoring
- Logical qubits required: **4,099**
- Physical qubits required (with surface code): **~1,000,000**
- Runtime: ~8 hours on a fault-tolerant machine

**Q-Day Probability Distribution:**
| Scenario | Year | Weight |
|----------|------|--------|
| Black Swan | 2031 | 5% |
| Optimistic | 2034 | 15% |
| Base Case | 2038 | 50% |
| Conservative | 2043 | 25% |
| Very Conservative | 2055 | 5% |

---

#### `core/threat/crypto_audit.py` — Cryptographic Infrastructure Auditor

Audits TLS cipher suites and cryptographic configurations across an institution's systems.

**Cipher Suite Ratings:**
| Rating | Examples | Action |
|--------|---------|--------|
| `QUANTUM_SAFE` | TLS_AES_256_GCM_SHA384 | No action needed |
| `HYBRID_READY` | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | Plan migration |
| `CLASSICAL_WEAK` | TLS_RSA_WITH_AES_256_GCM_SHA384 | Migrate soon |
| `BROKEN` | TLS_RSA_WITH_3DES_EDE_CBC_SHA | Immediate action |

**Grading Scale:**
| Vulnerability Score | Grade |
|--------------------|-------|
| 0–35 | A+ / A |
| 36–55 | B |
| 56–70 | C |
| 71–85 | D |
| 86–100 | F |

**Compliance Frameworks assessed:** CNSA 2.0, FIPS 140-3, PCI-DSS 4.0, DORA, NIST SP 800-208

---

### 5.4 Network Design

#### `core/network/topology.py` — QKD Network Topology Modeler

Designs QKD networks across multiple financial office locations using real-world geo-coordinates.

**Topology Types:**
- `ring` — each node connected to next; resilient, suitable for circular hub-and-spoke
- `star` — all nodes connect to a central hub; lowest cost, single point of failure
- `mesh` — all-to-all links; maximum resilience, highest cost

**Cost Model:**
- Fiber deployment: $50,000/km
- QKD hardware per node-pair: $200,000
- Link viability: based on QBER threshold and hardware profile key rate

**Output Metrics:**
- Viable links vs. total links
- Total infrastructure cost (USD)
- Network resilience score (0–100)
- Per-link: distance, QBER, secure key rate, channel loss, cost

---

#### `core/network/repeater.py` — Trusted Relay Chain Designer

Designs multi-hop QKD chains for long-distance connections beyond the direct QKD range (typically 100–300km for fiber).

**Key Concept — Trusted Relay Nodes:**
Intermediate nodes that decrypt and re-encrypt keys classically. They must be physically secured (unlike quantum repeaters). Each additional relay node reduces end-to-end availability: `A_total = 0.999^n_nodes`.

**Comparison: Trusted Relay vs Alternatives:**
| Technology | Range | Cost | Maturity |
|-----------|-------|------|---------|
| Trusted relay | Unlimited | Medium | Commercial today |
| Satellite QKD | Global | Very high | Micius demonstrated |
| Quantum repeater | Unlimited | Extreme | 10–15 years away |

---

### 5.5 Key Management System

#### `core/key_management/qkd_kms.py` — ETSI GS QKD 014 KMS

A full simulation of the ETSI GS QKD 014 Key Delivery API standard — the industry standard interface between QKD hardware and applications.

**ETSI API Endpoints simulated:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/{slave_sae_id}/enc_keys` | GET | Encryptor requests keys |
| `/{slave_sae_id}/dec_keys` | POST | Decryptor retrieves keys by ID |
| `/{slave_sae_id}/status` | GET | KMS health and capacity |
| `/{link_id}/rotate` | POST | Force key rotation |
| `/stats` | GET | Full KMS statistics |

**Key Lifecycle:**
```
FRESH → RESERVED (enc_keys called) → CONSUMED (dec_keys called)
      → EXPIRED  (TTL exceeded)
      → COMPROMISED (security event)
```

**Key Use Purposes:** `AES_REKEY`, `OTP_ENCRYPTION`, `HMAC_AUTH`, `KDF_SEED`, `TLS_MASTER`

---

### 5.6 Reporting & Roadmap

#### `core/reporting/roadmap.py` — Deployment Roadmap Generator

Generates a phased QKD + PQC deployment roadmap tailored to institution type.

**Institution Profiles:**
| Profile | Type | Daily Key Volume | Risk Level |
|---------|------|-----------------|-----------|
| `tier1_bank` | Tier 1 Bank | 500,000 keys | Critical |
| `hedge_fund` | Hedge Fund | 50,000 keys | High |
| `exchange` | Stock Exchange | 1,000,000 keys | Critical |
| `custodian` | Custodian Bank | 200,000 keys | High |
| `boutique_ib` | Boutique IB | 10,000 keys | Medium |

**4-Phase Deployment Plan:**
| Phase | Duration | Deliverables |
|-------|----------|-------------|
| 1 — Foundation PQC | 3 months | Kyber/Dilithium TLS, code signing migration |
| 2 — PKI Migration | 4 months | CA infrastructure, certificate pipeline |
| 3 — QKD Pilot | 6 months | 2-node QKD link, ETSI KMS integration |
| 4 — Full Deployment | 9 months | Multi-site QKD mesh, hybrid key management |

**ROI Model:**
`ROI = (Expected Breach Cost × Annual Probability × Risk Reduction %) / Total Investment`

---

## 6. REST API

The FastAPI backend runs on **port 8000** with auto-generated interactive documentation.

**Documentation URLs:**
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

### QKD Endpoints (`/api/v1/qkd/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/bb84/simulate` | Run BB84 protocol simulation |
| POST | `/bb84/sweep-distance` | Key rate vs distance analysis |
| POST | `/bb84/sweep-attack` | Simulate all attack types |
| POST | `/e91/simulate` | Run E91 entanglement simulation |
| POST | `/mdi-qkd/simulate` | Run MDI-QKD simulation |
| POST | `/channel/analyze` | Analyze channel capacity |
| GET | `/hardware/profiles` | List all hardware profiles |
| POST | `/hardware/compare` | Compare hardware at given distance |

### Threat Endpoints (`/api/v1/threat/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/hndl/assess` | HNDL risk assessment for a portfolio |
| GET | `/qday/timeline` | Q-Day probability timeline |
| GET | `/qday/probability-density` | Q-Day probability density curve |
| POST | `/crypto-audit/institution` | Audit institution cipher suites |
| GET | `/data-categories` | List financial data categories |

### PQC Endpoints (`/api/v1/pqc/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/kyber/benchmark` | Benchmark Kyber vs RSA-2048 |
| POST | `/kyber/keygen` | Generate a Kyber keypair |
| POST | `/dilithium/benchmark` | Benchmark Dilithium vs ECDSA |
| GET | `/falcon/signature-comparison` | Compare all signature scheme sizes |
| POST | `/migration/plan` | Generate PQC migration plan |
| GET | `/algorithms/support-matrix` | NIST PQC algorithm support matrix |

### Reporting & KMS Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/roadmap/generate` | Generate deployment roadmap |
| GET | `/api/v1/roadmap/institution-types` | List institution profiles |
| POST | `/api/v1/network/topology/analyze` | Analyze QKD network topology |
| POST | `/api/v1/network/repeater/design` | Design trusted relay chain |
| POST | `/api/v1/keys/{sae_id}/generate` | Generate QKD keys (ETSI) |
| GET | `/api/v1/keys/{sae_id}/enc_keys` | Retrieve keys for encryption |
| GET | `/api/v1/keys/{sae_id}/status` | KMS status |
| POST | `/api/v1/keys/{link_id}/rotate` | Rotate keys |
| GET | `/api/v1/keys/stats` | Full KMS statistics |

### Example API Calls

**Run a BB84 simulation:**
```bash
curl -X POST http://localhost:8000/api/v1/qkd/bb84/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "num_qubits": 10000,
    "distance_km": 50,
    "attack_type": "intercept_resend"
  }'
```

**Assess HNDL risk:**
```bash
curl -X POST http://localhost:8000/api/v1/threat/hndl/assess \
  -H "Content-Type: application/json" \
  -d '{
    "institution_name": "AlphaCap Partners",
    "data_assets": [
      {
        "name": "HFT Algorithm v3",
        "category": "algo_source_code",
        "size_gb": 5,
        "encrypted_with": "RSA-2048",
        "retention_years": 15
      }
    ]
  }'
```

**Generate a deployment roadmap:**
```bash
curl -X POST http://localhost:8000/api/v1/roadmap/generate \
  -H "Content-Type: application/json" \
  -d '{
    "institution_type": "hedge_fund",
    "institution_name": "Quantum Capital",
    "num_locations": 3,
    "daily_key_volume": 50000
  }'
```

---

## 7. Streamlit Dashboard

The interactive dashboard runs on **port 8502** and provides a no-code interface to every module.

**URL: `http://localhost:8502`**

### Tab Overview

| Tab | Module | What You Can Do |
|-----|--------|----------------|
| **BB84 Protocol** | `core/qkd/bb84.py` | Adjust qubit count, distance, detector params, pick attack type. See QBER, key rate, protocol funnel chart |
| **E91 Protocol** | `core/qkd/e91.py` | Configure EPR pairs, fidelity, eavesdropping fraction. View Bell parameter gauge |
| **MDI-QKD** | `core/qkd/mdi_qkd.py` | Set Alice/Bob/Charlie distances, toggle malicious relay. View topology diagram |
| **Channel Analysis** | `core/qkd/channel.py` | Pick hardware profile, channel medium, distance. Compare all hardware side-by-side |
| **HNDL Threat** | `core/threat/hndl.py` | Pre-loaded financial portfolio, assess HNDL exposure. Dollar-value risk per asset |
| **Q-Day Timeline** | `core/threat/qday.py` | View Q-Day probability distribution and density curve |
| **PQC Algorithms** | `core/pqc/kyber.py` + `dilithium.py` | Benchmark Kyber vs RSA, Dilithium vs ECDSA, signature size comparisons |
| **Crypto Auditor** | `core/threat/crypto_audit.py` | Audit pre-built financial system profiles. View A+–F grades and recommendations |
| **Network Topology** | `core/network/topology.py` | Design ring/star/mesh QKD networks for 2–4 global offices. View geo map |
| **Deployment Roadmap** | `core/reporting/roadmap.py` | Pick institution type, get 4-phase deployment plan with cost and ROI |
| **KMS (ETSI QKD 014)** | `core/key_management/qkd_kms.py` | Initialize KMS, generate keys, consume keys, view lifecycle stats |

---

## 8. Installation & Setup

### Prerequisites
- Python 3.10 or higher (tested on Python 3.13.1)
- pip

### Steps

```bash
# 1. Clone or navigate to the project
cd "d:/Risk Management/QuantumVault"

# 2. (Recommended) Create a virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # macOS/Linux

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Copy environment config
cp .env.example .env
# Edit .env as needed (defaults work for local development)

# 5. Run the test suite to verify everything works
python -m pytest tests/ -v
# Expected: 64 passed
```

---

## 9. Running the Platform

You need two terminal windows — one for the API, one for the dashboard.

### Terminal 1 — FastAPI Backend

```bash
cd "d:/Risk Management/QuantumVault"
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Output:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

### Terminal 2 — Streamlit Dashboard

```bash
cd "d:/Risk Management/QuantumVault"
python -m streamlit run dashboard.py --server.port 8502
```

Output:
```
  Local URL: http://localhost:8502
  Network URL: http://10.x.x.x:8502
```

### Access Points

| Interface | URL |
|-----------|-----|
| Dashboard | http://localhost:8502 |
| API Swagger UI | http://localhost:8000/docs |
| API ReDoc | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/health |
| Root Info | http://localhost:8000/ |

---

## 10. Testing

The test suite contains **64 tests** across 3 files.

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_bb84.py -v
python -m pytest tests/test_hndl.py -v
python -m pytest tests/test_pqc.py -v

# Run with coverage (if pytest-cov installed)
python -m pytest tests/ --cov=core --cov-report=term-missing
```

### Test Coverage

**`tests/test_bb84.py` — 15 tests:**
- `TestBB84Basics` — key generation, QBER computation, sifting efficiency
- `TestBB84InterceptResendAttack` — eavesdropper detection, QBER elevation
- `TestBB84DistanceSweep` — key rate degradation with distance
- `TestBB84PrivacyAmplification` — post-processing key reduction
- `TestQuantumChannel` — channel model validation

**`tests/test_hndl.py` — 23 tests:**
- `TestHNDLRiskEngine` — exposure scoring, portfolio aggregation, dollar risk
- `TestQDayTimeline` — probability distribution, scenario modeling, hardware roadmap
- `TestCryptoAuditor` — cipher suite grading, compliance checking, recommendation generation

**`tests/test_pqc.py` — 26 tests:**
- `TestKyber` — keygen, encap/decap round-trip, shared secret equivalence, parameter sizes
- `TestDilithium` — keygen, sign, verify, parameter validation
- `TestFALCON` — keygen, sign, verify, signature size comparison
- `TestMigrationEngine` — asset risk scoring, migration plan generation, urgency classification

---

## 11. Configuration

Copy `.env.example` to `.env` and configure as needed:

```bash
# Server
PORT=8000
HOST=0.0.0.0
DEBUG=true

# ETSI KMS
KMS_MASTER_SAE_ID=quantumvault_kms_master_01
KMS_DEFAULT_KEY_SIZE_BITS=256
KMS_DEFAULT_TTL_SECONDS=3600

# API Security (change in production)
API_SECRET_KEY=your_secret_key_here_min_32_chars
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

**Optional integrations** (uncomment in `.env` when ready):
- `DATABASE_URL` — PostgreSQL for persistent KMS storage
- `STRIPE_SECRET_KEY` — SaaS billing
- `IDQ_CLAVIS_HOST` / `TOSHIBA_QKD_HOST` — real QKD hardware integration

---

## 12. Security Concepts Reference

| Term | Definition |
|------|-----------|
| **QKD** | Quantum Key Distribution — uses quantum mechanics to distribute cryptographic keys with information-theoretic security |
| **QBER** | Quantum Bit Error Rate — fraction of bits that differ between Alice and Bob after transmission. Above 11% indicates eavesdropping |
| **HNDL** | Harvest Now, Decrypt Later — adversary stores today's encrypted data to decrypt after Q-Day |
| **Q-Day** | The day a CRQC capable of breaking RSA/ECC via Shor's Algorithm becomes operational |
| **CRQC** | Cryptographically Relevant Quantum Computer — requires ~1M physical qubits for RSA-2048 |
| **PQC** | Post-Quantum Cryptography — classical algorithms (lattice-based, hash-based) resistant to quantum attacks |
| **CRYSTALS-Kyber** | NIST FIPS 203 — lattice KEM (key exchange), replaces RSA/ECDH |
| **CRYSTALS-Dilithium** | NIST FIPS 204 — lattice signatures, replaces RSA/ECDSA signatures |
| **FALCON** | NIST FIPS 206 — lattice signatures, smaller than Dilithium, suitable for constrained environments |
| **SPHINCS+** | NIST FIPS 205 — hash-based signatures, conservative/stateless |
| **Shor's Algorithm** | Quantum algorithm that factors integers in polynomial time, breaking RSA and DSA |
| **Grover's Algorithm** | Quantum algorithm giving quadratic speedup for search — halves effective AES key size |
| **MDI-QKD** | Measurement Device Independent QKD — secure even if detectors are fully compromised |
| **BSM** | Bell State Measurement — joint quantum measurement of two photons used in MDI-QKD |
| **ETSI GS QKD 014** | European standard for the interface between QKD hardware and key consumers |
| **MLWE** | Module Learning With Errors — the hard mathematical problem underlying Kyber/Dilithium |
| **Privacy Amplification** | Universal hashing step that reduces Eve's knowledge of the key to negligible |
| **Cascade Protocol** | Interactive error correction protocol for QKD; leakage ≈ 1.16 × h(QBER) |
| **Trusted Relay** | Classical intermediate node for long-distance QKD; requires physical security guarantee |
| **CNSA 2.0** | NSA's Commercial National Security Algorithm Suite 2.0 — mandates PQC for US national security systems |
| **DORA** | EU Digital Operational Resilience Act — mandates quantum-safe cryptography planning for financial entities |

---

## 13. Monetization Model

QuantumVault is designed as a zero-build-cost SaaS platform. The operator pays nothing to run it; clients pay for access.

### Pricing Tiers

| Tier | Price | Target | Features |
|------|-------|--------|---------|
| **Analyst** | $500/month | Research teams | Dashboard access, all simulations, report export |
| **Professional** | $2,500/month | Risk/compliance teams | API access (10K calls/mo), PQC migration plans, HNDL reports |
| **Enterprise** | $7,500/month | CISOs, infrastructure teams | Unlimited API, custom hardware profiles, branded roadmaps |
| **Institution** | $15,000/month | Banks, exchanges | Multi-seat, dedicated support, custom integration, SLA |

### Revenue Drivers

- **HNDL Assessment Reports** — Board-ready PDF reports: $2,500–$10,000 per report
- **PQC Migration Plans** — Phased technical roadmap: $5,000–$25,000 per institution
- **QKD Architecture Design** — Multi-site network topology: $15,000–$50,000 per engagement
- **Compliance Readiness** — DORA/CNSA 2.0 gap analysis: $10,000–$30,000 per assessment

---

## 14. Roadmap to Production

| Phase | What to Add |
|-------|------------|
| **Authentication** | JWT tokens, API keys per client, Stripe billing integration |
| **Database** | PostgreSQL + SQLAlchemy for persistent KMS, audit logs, user data |
| **Real PQC** | Replace simulation with `liboqs-python` (Open Quantum Safe) for actual NIST implementations |
| **Real QKD Hardware** | ID Quantique Clavis3 or Toshiba QKD integration via vendor SDK |
| **PDF Export** | WeasyPrint/ReportLab for board-ready HNDL and roadmap reports |
| **Multi-tenancy** | Per-client data isolation, RBAC, SSO via SAML/OIDC |
| **Monitoring** | Prometheus metrics, Grafana dashboards, alerting |
| **Deployment** | Docker + Kubernetes, or bare Gunicorn behind Nginx |

---

## 15. Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API Backend | FastAPI + Uvicorn | Async REST API, 35 endpoints |
| API Validation | Pydantic v2 | Request/response schema validation |
| Dashboard | Streamlit | 11-tab interactive UI |
| Visualisation | Plotly | Interactive charts, geo maps, gauges |
| Data | Pandas + NumPy | DataFrames, numerical computation |
| Scientific | SciPy | Statistical distributions, optimization |
| Cryptography | cryptography (PyCA) | SHA3, hashing primitives |
| Testing | pytest + httpx | 64 unit tests, async API testing |
| Environment | python-dotenv | Configuration management |

All dependencies are **open-source and free**. No paid APIs. No cloud services required. Total infrastructure cost to run: $0.

---

## Licence

MIT — free to use, modify, and deploy commercially.

---

*Built with Python 3.13 · FastAPI · Streamlit · NumPy · Plotly*
*Aligned to NIST FIPS 203/204/205/206 · ETSI GS QKD 014 · CNSA 2.0 · DORA*
